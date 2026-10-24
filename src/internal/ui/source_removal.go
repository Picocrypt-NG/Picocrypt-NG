package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type operationSourceRemover func(context.Context, deletionSource, bool) error

var (
	errSourceDeletionChanged = errors.New("source changed before deletion")
	errSourceParentClose     = errors.New("source parent close failed")
	sourceRemovalOpenRoot    = os.OpenRoot
	sourceRemovalLstat       = (*os.Root).Lstat
	sourceRemovalRemove      = (*os.Root).Remove
	sourceRemovalClose       = (*os.Root).Close
)

func removeOperationSource(ctx context.Context, source deletionSource, directory bool) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := filepath.Base(source.path)
	if name == "." || name == ".." || !filepath.IsLocal(name) || source.info == nil {
		return errSourceDeletionChanged
	}
	parent, err := sourceRemovalOpenRoot(filepath.Dir(source.path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		if err := sourceRemovalClose(parent); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("%w: %w", errSourceParentClose, err))
		}
	}()
	state, err := inspectDeletionSource(parent, name, source, directory)
	if err != nil {
		return err
	}
	if state == deletionSourceMissing {
		return nil
	}
	if state != deletionSourceUnchanged {
		return errSourceDeletionChanged
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err = sourceRemovalRemove(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func inspectDeletionSource(root *os.Root, name string, source deletionSource, directory bool) (deletionSourceState, error) {
	current, err := sourceRemovalLstat(root, name)
	if errors.Is(err, os.ErrNotExist) {
		return deletionSourceMissing, nil
	}
	if err != nil {
		return deletionSourceChanged, err
	}
	if !os.SameFile(source.info, current) || current.Mode().Type() != source.info.Mode().Type() {
		return deletionSourceChanged, nil
	}
	if directory {
		if !current.IsDir() || current.Mode().Perm() != source.info.Mode().Perm() {
			return deletionSourceChanged, nil
		}
		return deletionSourceUnchanged, nil
	}
	if !current.Mode().IsRegular() ||
		current.Mode() != source.info.Mode() ||
		current.Size() != source.info.Size() ||
		!current.ModTime().Equal(source.info.ModTime()) {
		return deletionSourceChanged, nil
	}
	return deletionSourceUnchanged, nil
}
