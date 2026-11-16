//go:build wasm

package fileops

import (
	"errors"
	"os"
)

func openZIPInputInRoot(_ *os.Root, name string) (*os.File, error) {
	return nil, &os.PathError{Op: "open", Path: name, Err: errors.ErrUnsupported}
}
