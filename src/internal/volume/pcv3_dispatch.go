package volume

import (
	"Picocrypt-NG/internal/pcv3"
	"errors"
	"fmt"
	"os"
)

// PreflightPCV3 routes a native input before legacy operation state or side
// effects exist. A recombine request is inspected through chunk zero only.
func PreflightPCV3(inputPath string, recombine bool) (retErr error) {
	sourcePath := inputPath
	if recombine {
		sourcePath = recombineInputBase(inputPath) + ".0"
	}

	source, err := os.Open(sourcePath) // #nosec G304 -- caller-provided input path
	if err != nil {
		return fmt.Errorf("open input for PCV3 preflight: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, source.Close())
	}()

	return rejectClaimedPCV3(source)
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

func (ctx *OperationContext) openLegacyDecryptInput() (*os.File, bool, error) {
	source, closeInput, err := ctx.openInput()
	if err != nil {
		return nil, false, err
	}
	if err := rejectClaimedPCV3(source); err != nil {
		if closeInput {
			err = errors.Join(err, source.Close())
		}
		return nil, false, err
	}
	return source, closeInput, nil
}
