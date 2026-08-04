package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/pcv3"
	"errors"
	"fmt"
	"io"
	"os"
)

// PreparedDecryptInput owns the exact descriptor classified before a caller
// collects credentials. The caller must keep it open until DecryptPrepared
// returns and then close it.
type PreparedDecryptInput struct {
	inputPath  string
	recombine  bool
	file       *os.File
	info       os.FileInfo
	inputInfos []os.FileInfo
}

// PrepareDecryptInput opens and routes the descriptor that authorizes a legacy
// decrypt. Split inputs are represented by chunk zero, which owns the format
// discriminator for the complete recombined volume.
func PrepareDecryptInput(inputPath string, recombine bool) (*PreparedDecryptInput, error) {
	sourcePath := inputPath
	if recombine {
		sourcePath = recombineInputBase(inputPath) + ".0"
	}

	source, err := os.Open(sourcePath) // #nosec G304 -- caller-provided input path
	if err != nil {
		return nil, fmt.Errorf("open input for PCV3 preflight: %w", err)
	}
	info, err := source.Stat()
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("stat input for PCV3 routing: %w", err),
			source.Close(),
		)
	}
	if err := rejectClaimedPCV3Size(source, info.Size()); err != nil {
		return nil, errors.Join(err, source.Close())
	}
	inputInfos := []os.FileInfo{info}
	if recombine {
		inputBase := recombineInputBase(inputPath)
		numChunks, _, err := fileops.CountChunks(inputBase)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("inspect split inputs for PCV3 routing: %w", err),
				source.Close(),
			)
		}
		inputInfos = make([]os.FileInfo, numChunks)
		inputInfos[0] = info
		for i := 1; i < numChunks; i++ {
			chunkPath := fmt.Sprintf("%s.%d", inputBase, i)
			chunkInfo, err := os.Stat(chunkPath)
			if err != nil {
				return nil, errors.Join(
					fmt.Errorf("inspect split input %d for PCV3 routing: %w", i, err),
					source.Close(),
				)
			}
			inputInfos[i] = chunkInfo
		}
	}

	return &PreparedDecryptInput{
		inputPath:  inputPath,
		recombine:  recombine,
		file:       source,
		info:       info,
		inputInfos: inputInfos,
	}, nil
}

// Close releases the prepared descriptor. It is safe to call more than once.
func (input *PreparedDecryptInput) Close() error {
	if input == nil || input.file == nil {
		return nil
	}
	err := input.file.Close()
	input.file = nil
	input.info = nil
	input.inputInfos = nil
	return err
}

// ReadLegacyHeader parses metadata from the routed descriptor without exposing
// or transferring ownership of the underlying file.
func (input *PreparedDecryptInput) ReadLegacyHeader(rs *encoding.RSCodecs) (*header.VolumeHeader, error) {
	file, err := input.rewindRouted()
	if err != nil {
		return nil, err
	}
	result, err := header.NewReader(file, rs).ReadHeader()
	if err != nil {
		return nil, err
	}
	return result.Header, nil
}

func (input *PreparedDecryptInput) rewindRouted() (*os.File, error) {
	if input == nil || input.file == nil || input.info == nil {
		return nil, errors.New("prepared decrypt input is closed or unavailable")
	}
	if _, err := input.file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind prepared decrypt input: %w", err)
	}
	current, err := input.file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat prepared decrypt input: %w", err)
	}
	if !os.SameFile(input.info, current) {
		return nil, errors.New("prepared decrypt input identity changed")
	}
	if err := rejectClaimedPCV3Size(input.file, current.Size()); err != nil {
		return nil, err
	}
	return input.file, nil
}

func (input *PreparedDecryptInput) matches(inputPath string, recombine bool) bool {
	return input != nil && input.inputPath == inputPath && input.recombine == recombine
}

func (input *PreparedDecryptInput) detach() *os.File {
	file := input.file
	input.file = nil
	return file
}

// PreflightPCV3 routes a native input before legacy operation state or side
// effects exist. A recombine request is inspected through chunk zero only.
func PreflightPCV3(inputPath string, recombine bool) error {
	input, err := PrepareDecryptInput(inputPath, recombine)
	if err != nil {
		return err
	}
	return input.Close()
}

// OpenLegacyPCVInput opens and routes the exact descriptor a caller will use
// for legacy metadata inspection. The caller owns the returned file.
func OpenLegacyPCVInput(inputPath string, recombine bool) (*os.File, error) {
	input, err := PrepareDecryptInput(inputPath, recombine)
	if err != nil {
		return nil, err
	}
	return input.detach(), nil
}

func rejectClaimedPCV3(source *os.File) error {
	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("stat input for PCV3 routing: %w", err)
	}
	return rejectClaimedPCV3Size(source, info.Size())
}

func rejectClaimedPCV3Size(source *os.File, sourceSize int64) error {
	route, _, err := pcv3.Probe(source, sourceSize)
	if err != nil {
		return err
	}
	if route == pcv3.RouteNormalPCV {
		return pcv3.ErrReaderUnavailable
	}
	return nil
}

func (ctx *OperationContext) pinLegacyDecryptInput(source *os.File, owned bool) error {
	if source == nil {
		return errors.New("decrypt input descriptor is unavailable")
	}
	if ctx.pinnedLegacyInput != nil {
		return errors.New("decrypt input descriptor is already pinned")
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind decrypt input before pinning: %w", err)
	}
	if err := rejectClaimedPCV3(source); err != nil {
		return err
	}
	ctx.pinnedLegacyInput = source
	ctx.ownsPinnedLegacyInput = owned
	return nil
}

func (ctx *OperationContext) openLegacyDecryptInput() (*os.File, error) {
	if ctx.pinnedLegacyInput == nil {
		return nil, errors.New("decrypt input descriptor is not pinned")
	}
	if _, err := ctx.pinnedLegacyInput.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind pinned decrypt input: %w", err)
	}
	if err := rejectClaimedPCV3(ctx.pinnedLegacyInput); err != nil {
		return nil, err
	}
	return ctx.pinnedLegacyInput, nil
}

func (ctx *OperationContext) releasePinnedLegacyInput() error {
	if ctx == nil || ctx.pinnedLegacyInput == nil {
		return nil
	}
	file := ctx.pinnedLegacyInput
	owned := ctx.ownsPinnedLegacyInput
	ctx.pinnedLegacyInput = nil
	ctx.ownsPinnedLegacyInput = false
	if !owned {
		return nil
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close pinned decrypt input: %w", err)
	}
	return nil
}
