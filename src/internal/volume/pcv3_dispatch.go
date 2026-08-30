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
	route      pcv3.Route
}

// PrepareDecryptInput opens and routes the descriptor that authorizes a legacy
// decrypt. Split inputs are represented by chunk zero, which owns the format
// discriminator for the complete recombined volume.
func PrepareDecryptInput(inputPath string, recombine bool) (*PreparedDecryptInput, error) {
	sourcePath := inputPath
	if recombine {
		sourcePath = recombineInputBase(inputPath) + ".0"
	}

	source, err := os.Open(sourcePath) // #nosec G304 -- legacy compatibility permits a leaf symlink
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
	if info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return nil, errors.Join(
			errors.New("prepared decrypt input must be a regular file"),
			source.Close(),
		)
	}
	route := pcv3.RouteLegacyEligible
	if recombine {
		var prefix [4]byte
		count, readErr := io.ReadFull(source, prefix[:])
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return nil, errors.Join(readErr, source.Close())
		}
		route = pcv3.DetectPrefix(prefix[:count])
		if _, err := source.Seek(0, io.SeekStart); err != nil {
			return nil, errors.Join(err, source.Close())
		}
	} else if err := rejectClaimedPCV3Size(source, info.Size()); err != nil {
		return nil, errors.Join(err, source.Close())
	}
	inputInfos := []os.FileInfo{info}
	if recombine && route != pcv3.RouteNormalPCV {
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
			chunkInfo, statErr := os.Stat(chunkPath)
			if statErr != nil || chunkInfo == nil || !chunkInfo.Mode().IsRegular() {
				return nil, errors.Join(
					fmt.Errorf("inspect split input %d for PCV3 routing", i),
					statErr,
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
		route:      route,
	}, nil
}

func (input *PreparedDecryptInput) ClaimsNormalPCV3() bool {
	return input != nil && input.route == pcv3.RouteNormalPCV
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
	input.route = pcv3.RouteLegacyEligible
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
	if current.Size() != input.info.Size() {
		return nil, errors.New("prepared decrypt input size changed")
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

// DetachSource transfers the pinned descriptor while leaving no cleanup
// authority on PreparedDecryptInput.
func (input *PreparedDecryptInput) DetachSource() *os.File {
	if input == nil {
		return nil
	}
	return input.detach()
}

// PreflightPCV3 routes a native input before legacy operation state or side
// effects exist. A recombine request is inspected through chunk zero only.
func PreflightPCV3(inputPath string, recombine bool) error {
	input, err := PrepareDecryptInput(inputPath, recombine)
	if err != nil {
		return err
	}
	if input.ClaimsNormalPCV3() {
		return errors.Join(pcv3.ErrReaderUnavailable, input.Close())
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
	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("stat decrypt input before pinning: %w", err)
	}
	if err := rejectClaimedPCV3(source); err != nil {
		return err
	}
	ctx.pinnedLegacyInput = source
	ctx.ownsPinnedLegacyInput = owned
	ctx.pinnedLegacyInputInfo = info
	ctx.pinnedLegacyInputSize = info.Size()
	return nil
}

func (ctx *OperationContext) openLegacyDecryptInput() (io.ReadSeeker, error) {
	if ctx.pinnedLegacyInput == nil {
		return nil, errors.New("decrypt input descriptor is not pinned")
	}
	if _, err := ctx.pinnedLegacyInput.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind pinned decrypt input: %w", err)
	}
	current, err := ctx.pinnedLegacyInput.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat pinned decrypt input: %w", err)
	}
	if ctx.pinnedLegacyInputInfo == nil || !os.SameFile(ctx.pinnedLegacyInputInfo, current) {
		return nil, errors.New("pinned decrypt input identity changed")
	}
	if current.Size() != ctx.pinnedLegacyInputSize {
		return nil, errors.New("pinned decrypt input size changed")
	}
	if err := rejectClaimedPCV3(ctx.pinnedLegacyInput); err != nil {
		return nil, err
	}
	return ctx.pinnedLegacyInput, nil
}

func (ctx *OperationContext) releasePinnedLegacyInput() error {
	if ctx == nil {
		return nil
	}
	if ctx.pinnedLegacyInput == nil {
		return nil
	}
	file := ctx.pinnedLegacyInput
	owned := ctx.ownsPinnedLegacyInput
	ctx.pinnedLegacyInput = nil
	ctx.ownsPinnedLegacyInput = false
	ctx.pinnedLegacyInputInfo = nil
	ctx.pinnedLegacyInputSize = 0
	if !owned {
		return nil
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close pinned decrypt input: %w", err)
	}
	return nil
}
