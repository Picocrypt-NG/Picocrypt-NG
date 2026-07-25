package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/keyfile"
	"Picocrypt-NG/internal/log"
	"Picocrypt-NG/internal/util"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	perrors "Picocrypt-NG/internal/errors"

	pwnorm "Picocrypt-NG/internal/password"
)

// Encrypt performs a complete volume encryption operation.
// This is the main entry point for encryption.
// If ctx is nil, a background context is used.
func Encrypt(ctx context.Context, req *EncryptRequest) (retErr error) {
	if err := req.Validate(); err != nil {
		return err
	}

	opCtx := NewEncryptContext(ctx, req)
	defer func() {
		retErr = errors.Join(retErr, opCtx.Close())
	}() // Secure zeroing of key material and fail-loud stage cleanup

	log.Info("starting encryption", log.String("output", req.OutputFile))

	// Phase 1: Preprocess (zip if multiple files or compression requested)
	if err := encryptPreprocess(opCtx, req); err != nil {
		return err
	}

	// Phase 2: Generate cryptographic values
	if err := encryptGenerateValues(opCtx, req); err != nil {
		return err
	}

	// Phase 3: Write header
	if err := encryptWriteHeader(opCtx, req); err != nil {
		return err
	}

	// Phase 4: Derive keys
	if err := encryptDeriveKeys(opCtx, req); err != nil {
		return err
	}

	// Phase 5: Process keyfiles
	if err := encryptProcessKeyfiles(opCtx, req); err != nil {
		return err
	}

	// Phase 6: Compute header auth
	if err := encryptComputeAuth(opCtx, req); err != nil {
		return err
	}

	// Phase 7: Encrypt payload
	if err := encryptPayload(opCtx, req); err != nil {
		return err
	}

	// Phase 8: Finalize (write auth values, add deniability, split)
	if err := encryptFinalize(opCtx, req); err != nil {
		return err
	}

	log.Info("encryption completed successfully")
	return nil
}

func preprocessInputFiles(req *EncryptRequest) []string {
	if len(req.InputFiles) > 0 {
		return req.InputFiles
	}
	if req.InputFile != "" {
		return []string{req.InputFile}
	}
	return nil
}

func encryptPreprocess(ctx *OperationContext, req *EncryptRequest) error {
	inputFiles := preprocessInputFiles(req)

	// Create a zip when the selection is anything other than a single bare file:
	// multiple files, a single file with compression requested, or any folder
	// selection (even one containing a single file). A dropped folder is labelled
	// "Zip and Encrypt" by the UI and named "<name>.zip.pcv", so it must decrypt to
	// a real zip that preserves the folder structure — see issue #130. OnlyFolders
	// is the signal that a folder (not a bare file) was selected.
	if len(inputFiles) > 1 || (len(inputFiles) == 1 && (req.Compress || len(req.OnlyFolders) > 0)) {
		ctx.SetStatus("Compressing files...")

		// Create temp zip ciphers for encrypting the temporary file
		var err error
		ctx.TempCiphers, err = fileops.NewTempZipCiphers()
		if err != nil {
			return err
		}

		zipReq := *req
		zipReq.InputFiles = inputFiles

		commonRoot, entryNames, err := buildZipEntryNames(&zipReq)
		if err != nil {
			return err
		}

		tempZip, err := fileops.CreateSiblingTemp(req.OutputFile)
		if err != nil {
			return err
		}
		ctx.adoptTempInput(tempZip)

		// Create the zip through the exclusively owned handle. The random path
		// is never reopened for writing.
		err = fileops.CreateZip(fileops.ZipOptions{
			Files:      inputFiles,
			RootDir:    commonRoot,
			EntryNames: entryNames,
			OutputFile: tempZip.File(),
			Compress:   req.Compress,
			Cipher:     ctx.TempCiphers,
			Progress: func(p float32, info string) {
				ctx.UpdateProgress(p, info)
			},
			Status: func(s string) {
				ctx.SetStatus(s)
			},
			Cancel: func() bool {
				return ctx.IsCancelled()
			},
		})
		if err != nil {
			return err
		}

		ctx.InputFile = tempZip.Path()
		ctx.TempZipInUse = true
	} else if len(inputFiles) == 1 {
		ctx.InputFile = inputFiles[0]
	} else {
		ctx.InputFile = req.InputFile
	}

	return nil
}

func encryptGenerateValues(ctx *OperationContext, req *EncryptRequest) error {
	ctx.SetStatus("Generating values...")

	// Generate random cryptographic values
	salt, err := crypto.RandomBytes(header.SaltSize)
	if err != nil {
		return err
	}

	hkdfSalt, err := crypto.RandomBytes(header.HKDFSaltSize)
	if err != nil {
		return err
	}

	serpentIV, err := crypto.RandomBytes(header.SerpentIVSize)
	if err != nil {
		return err
	}

	nonce, err := crypto.RandomBytes(header.NonceSize)
	if err != nil {
		return err
	}

	// Get input file size for padded flag
	stat, err := os.Stat(ctx.InputFile)
	if err != nil {
		return fmt.Errorf("stat input: %w", err)
	}
	ctx.Total = stat.Size()

	// Determine if padding is needed (RS internals)
	// Padding is required when the last partial block would leave fewer than RS128DataSize
	// bytes after RS128 encoding chunks are filled.
	ctx.Padded = ctx.Total%int64(util.MiB) >= int64(util.MiB)-encoding.RS128DataSize

	// Create header
	ctx.Header = header.NewVolumeHeader(salt, hkdfSalt, serpentIV, nonce)
	ctx.Header.Comments = req.Comments
	ctx.Header.Flags = header.Flags{
		Paranoid:       req.Paranoid,
		UseKeyfiles:    len(req.Keyfiles) > 0,
		KeyfileOrdered: req.KeyfileOrdered,
		ReedSolomon:    req.ReedSolomon,
		Padded:         ctx.Padded,
	}

	return nil
}

func encryptWriteHeader(ctx *OperationContext, req *EncryptRequest) error {
	if err := ctx.beginStagedOutput(); err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	fout, err := ctx.stagedOutputFile()
	if err != nil {
		return err
	}

	// Write header
	w := header.NewWriter(fout, req.RSCodecs)
	if _, err := w.WriteHeader(ctx.Header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	return nil
}

func encryptDeriveKeys(ctx *OperationContext, req *EncryptRequest) error {
	ctx.SetStatus("Deriving key...")

	// Feed the KDF the NFC-normalized password so new volumes derive a
	// canonical, cross-platform-stable key regardless of how it was typed (#19).
	kdfInput := pwnorm.EncodeForKDF(req.Password)
	defer crypto.SecureZero(kdfInput)
	key, err := deriveVolumeKey(kdfInput, ctx.Header.Salt, req.Paranoid)
	if err != nil {
		return err
	}
	ctx.setKey(key)

	return nil
}

func encryptProcessKeyfiles(ctx *OperationContext, req *EncryptRequest) error {
	if len(req.Keyfiles) == 0 {
		ctx.KeyfileHash = make([]byte, 32)
		return nil
	}

	ctx.SetStatus("Reading keyfiles...")
	ctx.UseKeyfiles = true

	result, err := keyfile.Process(req.Keyfiles, req.KeyfileOrdered, func(p float32) {
		ctx.UpdateProgress(p, "")
	})
	if err != nil {
		return err
	}

	ctx.setKeyfileKey(result.Key)
	ctx.KeyfileHash = result.Hash

	return nil
}

func encryptComputeAuth(ctx *OperationContext, req *EncryptRequest) error { //nolint:unparam // (ctx, req) signature shared by all encrypt phases; req unused here by design
	ctx.SetStatus("Calculating values...")

	// v2: Initialize HKDF BEFORE keyfile XOR
	hkdfStream := crypto.NewHKDFStream(ctx.Key.Bytes(), ctx.Header.HKDFSalt)
	ctx.SubkeyReader = crypto.NewSubkeyReader(hkdfStream)

	// Read header subkey for v2 MAC
	subkeyHeader, err := ctx.SubkeyReader.HeaderSubkey()
	if err != nil {
		return err
	}
	defer crypto.SecureZero(subkeyHeader)

	// Compute header MAC
	ctx.Header.KeyHash = header.ComputeV2HeaderMAC(subkeyHeader, ctx.Header, ctx.KeyfileHash)
	ctx.Header.KeyfileHash = ctx.KeyfileHash

	return nil
}

func encryptPayload(ctx *OperationContext, req *EncryptRequest) error {
	// Apply keyfile XOR to key (AFTER HKDF init for v2).
	if ctx.UseKeyfiles && ctx.KeyfileKey != nil {
		if keyfile.IsDuplicateKeyfileKey(ctx.KeyfileKey.Bytes()) {
			return perrors.ErrDuplicateKeyfiles
		}
		// SEC-05/WR-01: route the XOR reassignment through setKey for symmetry
		// with the decrypt path. keyfile.XORWithKey allocates a NEW slice, so the
		// old Argon2 backing array would otherwise linger until Close(); setKey
		// zeros it now. Safe here because HKDF has already extracted ctx.Key
		// (encryptComputeAuth read HeaderSubkey, so the stream's PRK is fixed) and
		// the cipher uses the XOR result, not the original key. The pointer-identity
		// guard means the no-keyfile path (this branch skipped) is never wiped.
		ctx.setKey(keyfile.XORWithKey(ctx.Key.Bytes(), ctx.KeyfileKey.Bytes()))
	}
	key := ctx.Key.Bytes()

	// Read remaining subkeys
	macSubkey, err := ctx.SubkeyReader.MACSubkey()
	if err != nil {
		return err
	}
	defer crypto.SecureZero(macSubkey)

	serpentKey, err := ctx.SubkeyReader.SerpentKey()
	if err != nil {
		return err
	}
	defer crypto.SecureZero(serpentKey)

	// Create MAC
	mac, err := crypto.NewMAC(macSubkey, req.Paranoid)
	if err != nil {
		return err
	}

	// Create cipher suite
	cipherSuite, err := crypto.NewCipherSuite(
		key,
		ctx.Header.Nonce,
		serpentKey,
		ctx.Header.SerpentIV,
		mac,
		ctx.SubkeyReader.Reader(),
		req.Paranoid,
	)
	if err != nil {
		return err
	}
	ctx.CipherSuite = cipherSuite

	// Open files
	fin, closeInput, err := ctx.openInput()
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	if closeInput {
		defer func() { _ = fin.Close() }()
	}

	fout, err := ctx.stagedOutputFile()
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	if _, err := fout.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek output: %w", err)
	}

	// Wrap with temp zip cipher if needed
	var reader io.Reader = fin
	if ctx.TempZipInUse && ctx.TempCiphers != nil {
		reader = fileops.WrapReaderWithCipher(fin, ctx.TempCiphers)
	}
	reader = newPayloadReader(reader)

	// Encrypt loop
	ctx.SetCanCancel(true)
	startTime := time.Now()
	var done int64
	var counter int64

	// Get buffers from pool to reduce GC pressure
	src := util.GetMiBBuffer()
	defer util.PutMiBBuffer(src)
	dst := util.GetMiBBuffer()
	defer util.PutMiBBuffer(dst)

	for {
		if ctx.IsCancelled() {
			return ctx.CancellationError()
		}

		n, readErr := io.ReadFull(reader, src)
		if n > 0 {
			srcData := src[:n]
			dstData := dst[:n]

			// Encrypt: Serpent -> XChaCha20 -> MAC
			ctx.CipherSuite.Encrypt(dstData, srcData)

			// Apply Reed-Solomon if enabled
			var writeData []byte
			if req.ReedSolomon {
				enc, err := encoding.EncodeRSPayloadBlock(dstData, req.RSCodecs)
				if err != nil {
					return fmt.Errorf("rs encode payload: %w", err)
				}
				writeData = enc
			} else {
				writeData = dstData
			}

			if _, err := fout.Write(writeData); err != nil {
				return fmt.Errorf("write ciphertext: %w", err)
			}

			done += int64(n)
			counter += int64(util.MiB)

			progress, speed, eta := util.Statify(done, ctx.Total, startTime)
			ctx.UpdateProgress(progress, fmt.Sprintf("%.2f%%", progress*100))
			ctx.SetStatus(fmt.Sprintf("Encrypting at %.2f MiB/s (ETA: %s)", speed, eta))

			// Rekey every 60 GiB
			if counter >= crypto.RekeyThreshold {
				if err := ctx.CipherSuite.Rekey(); err != nil {
					return err
				}
				counter = 0
			}
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read input: %w", readErr)
		}
	}

	// Sync to ensure all encrypted data is written before finalize
	if err := fout.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}

	return nil
}

func encryptFinalize(ctx *OperationContext, req *EncryptRequest) error {
	ctx.SetStatus("Writing values...")

	fout, err := ctx.stagedOutputFile()
	if err != nil {
		return fmt.Errorf("open output for auth: %w", err)
	}

	// Write auth values
	offset := header.AuthValuesOffset(len(ctx.Header.Comments))
	err = header.WriteAuthValues(
		fout,
		offset,
		ctx.Header.KeyHash,
		ctx.Header.KeyfileHash,
		ctx.CipherSuite.Sum(),
		req.RSCodecs,
	)
	if err != nil {
		return err
	}

	if err := req.ValidateOutputSafety(); err != nil {
		return err
	}
	if err := ctx.publishStagedOutput(); err != nil {
		return fmt.Errorf("publish output: %w", err)
	}
	outputInfo := ctx.publishedOutputInfo

	// Add deniability if requested
	if req.Deniability {
		if err := addDeniability(
			req.OutputFile,
			req.Password,
			ctx.Reporter,
			outputInfo,
			&outputInfo,
		); err != nil {
			return err
		}
	}

	// Split if requested
	if req.Split {
		ctx.SetStatus("Splitting...")
		if outputInfo == nil {
			return errors.New("published output identity is unavailable")
		}
		_, err = fileops.Split(fileops.SplitOptions{
			InputPath:     req.OutputFile,
			ExpectedInput: outputInfo,
			ChunkSize:     req.ChunkSize,
			Unit:          req.ChunkUnit,
			Progress: func(p float32, info string) {
				ctx.UpdateProgress(p, info)
			},
			Status: func(s string) {
				ctx.SetStatus(s)
			},
			Cancel: func() bool {
				return ctx.IsCancelled()
			},
		})
		if err != nil {
			return err
		}

		removed, err := fileops.RemoveIfSameFile(req.OutputFile, outputInfo)
		if err != nil {
			return fmt.Errorf("remove unsplit output: %w", err)
		}
		if !removed {
			if _, err := os.Lstat(req.OutputFile); err == nil {
				return fmt.Errorf("unsplit output path %q changed during splitting; refusing to remove it", req.OutputFile)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("inspect unsplit output after splitting: %w", err)
			}
		}
	}

	return nil
}
