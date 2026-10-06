package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/keyfile"
	"Picocrypt-NG/internal/log"
	"Picocrypt-NG/internal/pcv3operation"
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
func Encrypt(ctx context.Context, req *EncryptRequest) error {
	_, err := EncryptWithResult(ctx, req, pcv3operation.ExecutionOptions{})
	return err
}

// EncryptWithResult returns the core-owned PCV3 result only after source and
// preprocessing cleanup. Legacy v2 returns a nil result and its existing error.
func EncryptWithResult(ctx context.Context, req *EncryptRequest, options pcv3operation.ExecutionOptions) (result *pcv3operation.Result, retErr error) {
	if req == nil {
		return nil, errors.New("encryption request is required")
	}
	if !req.PCV3 {
		return nil, encryptLegacy(ctx, req)
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	opCtx := NewEncryptContext(ctx, req)
	defer func() {
		panicValue := recover()
		cleanupErr := opCtx.Close()
		if cleanupErr != nil {
			if result != nil {
				result.WithCleanupWarning()
			}
			retErr = errors.Join(retErr, cleanupErr)
		}
		if panicValue != nil {
			fileops.RepanicWithCleanup(panicValue, cleanupErr)
		}
	}()

	return encryptPCV3(opCtx, req, options)
}

func encryptLegacy(ctx context.Context, req *EncryptRequest) (retErr error) {
	if err := req.Validate(); err != nil {
		return err
	}

	opCtx := NewEncryptContext(ctx, req)
	defer func() {
		panicValue := recover()
		cleanupErr := opCtx.Close()
		retErr = errors.Join(retErr, cleanupErr)
		if panicValue != nil {
			fileops.RepanicWithCleanup(panicValue, cleanupErr)
		}
	}() // Secure zeroing of key material and fail-loud stage cleanup

	log.Info("starting encryption", log.String("output", req.OutputFile))

	// Preprocess (zip if multiple files or compression is requested).
	if err := encryptPreprocess(opCtx, req); err != nil {
		return err
	}

	// Generate cryptographic values.
	if err := encryptGenerateValues(opCtx, req); err != nil {
		return err
	}

	// Write the header.
	if err := encryptWriteHeader(opCtx, req); err != nil {
		return err
	}

	// Derive keys.
	if err := encryptDeriveKeys(opCtx, req); err != nil {
		return err
	}

	// Process keyfiles.
	if err := encryptProcessKeyfiles(opCtx, req); err != nil {
		return err
	}

	// Compute header authentication.
	if err := encryptComputeAuth(opCtx, req); err != nil {
		return err
	}

	// Encrypt the payload.
	if err := encryptPayload(opCtx, req); err != nil {
		return err
	}

	// Finalize (write authentication values, add deniability, split).
	if err := encryptFinalize(opCtx, req); err != nil {
		return err
	}

	log.Info("encryption completed successfully")
	return nil
}

func encryptPCV3(ctx *OperationContext, req *EncryptRequest, options pcv3operation.ExecutionOptions) (result *pcv3operation.Result, retErr error) {
	ctx.SetStatus("Generating values...")
	ctx.SetCanCancel(true)
	prepared, err := prepareEncryptInput(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		panicValue := recover()
		cleanupErr := prepared.Close()
		if cleanupErr != nil {
			if result != nil {
				result.WithCleanupWarning()
			}
			retErr = errors.Join(retErr, cleanupErr)
		}
		if panicValue != nil {
			fileops.RepanicWithCleanup(panicValue, cleanupErr)
		}
	}()
	factors, err := pcv3WriteFactors(req)
	if err != nil {
		return nil, err
	}
	protected := append([]string{ctx.InputFile}, req.InputFiles...)
	protected = append(protected, req.OnlyFiles...)
	protected = append(protected, req.OnlyFolders...)
	protected = append(protected, req.Keyfiles...)
	mode := pcv3operation.WriteModeNormal
	suite := pcv3operation.SuiteStandard
	if req.Paranoid {
		suite = pcv3operation.SuiteParanoid
	}
	if req.Deniability {
		mode = pcv3operation.WriteModeD1
	}
	request := &pcv3operation.WriteRequest{
		Mode: mode, Suite: suite, PayloadKind: prepared.PayloadKind(), PayloadBodyRS: req.ReedSolomon,
		PlaintextLength: prepared.Length(),
		Comment:         []byte(req.Comments), Factors: factors, Source: prepared.Reader(),
		SourceFile: prepared.File(), SourcePath: prepared.Path(), Target: req.OutputFile, Protected: protected,
		Reporter: func(status pcv3operation.Status) error {
			switch status.Code() {
			case pcv3operation.StatusEncrypting, pcv3operation.StatusSplitting:
				args := status.Args()
				if len(args) == 2 && args[1] > 0 && args[0] <= args[1] {
					ctx.UpdateProgress(float32(float64(args[0])/float64(args[1])), "")
				}
			case pcv3operation.StatusDerivingKey:
				ctx.SetStatus("Deriving key...")
			case pcv3operation.StatusPublishing:
				ctx.SetStatus("Writing values...")
			}
			return nil
		},
	}
	if req.Split {
		request.Split = &pcv3operation.WriteSplitOptions{ChunkSize: req.ChunkSize, Unit: req.ChunkUnit}
	}
	result = pcv3operation.RunWriteWithOptions(ctx.Ctx, request, options)
	if result.CompletionClass() != pcv3operation.CompletionClean {
		return result, result
	}
	ctx.UpdateProgress(1, "100.00%")
	return result, nil
}

func pcv3WriteFactors(req *EncryptRequest) (*pcv3operation.FactorRequest, error) {
	request := &pcv3operation.FactorRequest{
		Password: append([]byte(nil), req.Password...),
	}
	if len(req.Keyfiles) == 0 {
		request.Mode = pcv3operation.CredentialModePasswordOnly
		request.KeyfileMode = pcv3operation.KeyfileModeNone
		request.ExpectedPolicy = pcv3operation.FactorPolicyPasswordOnly
		return request, nil
	}

	request.KeyfileMode = pcv3operation.KeyfileModeUnordered
	if req.KeyfileOrdered {
		request.KeyfileMode = pcv3operation.KeyfileModeOrdered
	}
	if len(req.Password) == 0 {
		request.Mode = pcv3operation.CredentialModeKeyfilesOnly
		request.ExpectedPolicy = pcv3operation.FactorPolicyKeyfilesOnly
	} else {
		request.Mode = pcv3operation.CredentialModePasswordAndKeyfiles
		request.ExpectedPolicy = pcv3operation.FactorPolicyPasswordAndKeyfiles
	}
	for _, path := range req.Keyfiles {
		file, err := fileops.OpenExistingNoSymlink(path, os.O_RDONLY)
		if err != nil {
			_ = request.Close()
			return nil, fmt.Errorf("open PCV3 keyfile: %w", err)
		}
		info, err := file.Stat()
		if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
			_ = file.Close()
			_ = request.Close()
			return nil, errors.New("PCV3 keyfile must be a regular file")
		}
		request.Keyfiles = append(request.Keyfiles, pcv3operation.OwnKeyfileReader(file))
	}
	return request, nil
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
		budget := req.ZIPBudget
		if budget == nil {
			budget = fileops.NewZIPResourceBudget()
		}
		if err := pcv3operation.AdmitZIPWorkingMemory(ctx.Ctx, budget); err != nil {
			return err
		}
		selectionCharge, err := reserveZIPSelection(budget, req, inputFiles)
		if err != nil {
			return err
		}
		defer budget.Release(selectionCharge)
		ctx.SetStatus("Compressing files...")
		zipReq := *req
		zipReq.InputFiles = inputFiles

		commonRoot, entryNames, err := buildZipEntryNames(&zipReq)
		if err != nil {
			return err
		}

		maxPhysical, err := admitTemporaryZIP(req)
		if err != nil {
			return err
		}
		tempZip, err := fileops.CreateTempZip(ctx.Ctx, fileops.TempZipOptions{
			Files: inputFiles, RootDir: commonRoot, EntryNames: entryNames,
			NearPath: req.OutputFile, Compress: req.Compress, MaxPhysicalBytes: maxPhysical,
			Budget: budget, Progress: ctx.UpdateProgress, Status: ctx.SetStatus, Cancel: ctx.IsCancelled,
		})
		if err != nil {
			if errors.Is(err, fileops.ErrTempZipCleanupIncomplete) {
				return errors.Join(err, ErrEncryptInputCleanupIncomplete)
			}
			return err
		}

		ctx.InputFile = tempZip.Path()
		ctx.tempZip = tempZip
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

	// Authentication tags belong only to the private spool, never to the
	// public legacy payload length or RS padding decision.
	if ctx.tempZip != nil {
		ctx.Total = int64(ctx.tempZip.Length()) //nolint:gosec // The finalized spool enforces physical extent <= MaxInt64.
	} else {
		stat, err := os.Stat(ctx.InputFile)
		if err != nil {
			return fmt.Errorf("stat input: %w", err)
		}
		ctx.Total = stat.Size()
	}

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

func encryptComputeAuth(ctx *OperationContext, req *EncryptRequest) error { //nolint:unparam // (ctx, req) signature shared by encrypt steps; req unused here by design
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

	reader, err := ctx.TempZipReader(fin)
	if err != nil {
		return err
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

	if req.Split {
		ctx.SetStatus("Splitting...")
		if outputInfo == nil {
			return errors.New("published output identity is unavailable")
		}
		_, err := fileops.Split(fileops.SplitOptions{
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
