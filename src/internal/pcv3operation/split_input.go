package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

func (owner *operationOwner) prepareSplitInput(ctx context.Context) error {
	if owner == nil || ctx == nil || owner.source == nil || owner.splitBase == "" || owner.splitStage != nil {
		return errors.New("pcv3 operation: invalid split input")
	}
	firstInfo, err := owner.source.Stat()
	if err != nil || firstInfo == nil || !firstInfo.Mode().IsRegular() || firstInfo.Size() < 0 {
		return errors.New("pcv3 operation: invalid split chunk zero")
	}
	currentFirst, err := os.Lstat(owner.splitBase + ".0")
	if err != nil || currentFirst == nil || !currentFirst.Mode().IsRegular() ||
		currentFirst.Mode()&os.ModeSymlink != 0 || !os.SameFile(firstInfo, currentFirst) {
		return errors.New("pcv3 operation: split chunk zero changed")
	}
	var prefix [4]byte
	count, readErr := io.ReadFull(owner.source, prefix[:])
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return readErr
	}
	claimsNormal := pcv3.DetectPrefix(prefix[:count]) == pcv3.RouteNormalPCV
	expectsNormal := owner.mode == ModeReadNormal || owner.mode == ModeRecoverNormal ||
		owner.mode == ModeForceNormal || owner.mode == ModeForceUnverifiedNormal
	if expectsNormal && !claimsNormal {
		return errors.New("pcv3 operation: split format intent mismatch")
	}
	if _, err := owner.source.Seek(0, io.SeekStart); err != nil {
		return err
	}

	numChunks, _, err := fileops.CountChunksWithCancel(owner.splitBase, func() bool { return ctx.Err() != nil })
	if err != nil {
		return err
	}
	expected := make([]os.FileInfo, numChunks)
	expected[0] = firstInfo
	protected := make([]string, numChunks)
	protected[0] = owner.splitBase + ".0"
	for index := 1; index < numChunks; index++ {
		path := fmt.Sprintf("%s.%d", owner.splitBase, index)
		chunk, err := fileops.OpenExistingNoSymlink(path, os.O_RDONLY)
		if err != nil {
			return err
		}
		info, statErr := chunk.Stat()
		closeErr := chunk.Close()
		if statErr != nil || closeErr != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
			return errors.Join(
				errors.New("pcv3 operation: invalid split chunk"),
				statErr,
				closeErr,
			)
		}
		expected[index] = info
		protected[index] = path
	}

	stage, err := fileops.CreateSiblingTemp(owner.splitBase)
	if err != nil {
		return err
	}
	owner.splitStage = stage
	err = fileops.Recombine(fileops.RecombineOptions{
		InputBase:      owner.splitBase,
		Output:         stage.File(),
		ExpectedInputs: expected,
		FirstChunk:     owner.source,
		Cancel:         func() bool { return ctx.Err() != nil },
	})
	if err != nil {
		return err
	}
	source, err := stage.Detach()
	if err != nil {
		return err
	}
	if err := owner.source.Close(); err != nil {
		return errors.Join(err, source.Close())
	}
	owner.source = source
	owner.protected = append(owner.protected, protected...)
	return nil
}
