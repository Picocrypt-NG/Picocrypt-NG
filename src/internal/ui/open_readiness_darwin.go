//go:build darwin

package ui

/*
#cgo LDFLAGS: -framework Foundation
#include <stdlib.h>

int pcngCheckOpenedPathReadiness(char *path, int *ubiquitousOut, int *dirOut, char **errorOut);
void pcngFreeCString(char *s);
*/
import "C"

import (
	"context"
	"errors"
)

const (
	pcngOpenedPathReady = iota
	pcngOpenedPathDownloading
	pcngOpenedPathNotDownloaded
	pcngOpenedPathStale
	pcngOpenedPathMissing
	pcngOpenedPathError
)

func openedPathStateFromDarwinCode(code int) openedPathReadinessState {
	switch code {
	case pcngOpenedPathReady:
		return openedPathReady
	case pcngOpenedPathDownloading, pcngOpenedPathNotDownloaded, pcngOpenedPathStale:
		return openedPathPending
	case pcngOpenedPathMissing:
		return openedPathMissing
	default:
		return openedPathError
	}
}

func defaultOpenedPathReadiness(ctx context.Context, paths []string) openedPathReadinessResult {
	result := make(openedPathReadinessResult, 0, len(paths))
	for _, path := range paths {
		if ctx.Err() != nil {
			return result
		}
		cpath := C.CString(path)
		var cubiquitous C.int
		var cdir C.int
		var cerr *C.char
		code := int(C.pcngCheckOpenedPathReadiness(cpath, &cubiquitous, &cdir, &cerr))
		C.pcngFreeCString(cpath)
		item := openedPathReadiness{
			Path:         path,
			State:        openedPathStateFromDarwinCode(code),
			IsUbiquitous: cubiquitous != 0,
			IsDir:        cdir != 0,
		}
		if cerr != nil {
			item.Err = errors.New(C.GoString(cerr))
			C.pcngFreeCString(cerr)
		}
		result = append(result, item)
	}
	return result
}
