//go:build !linux && !darwin && !windows

package main

import (
	"errors"
	"os"
	"os/exec"
)

var errUnsupportedProcessTree = errors.New(
	"process-tree containment is unsupported on this platform",
)

func processTreeSupported() error {
	return errUnsupportedProcessTree
}

func fileLinkCount(os.FileInfo) (uint64, bool) {
	return 0, false
}

func openEvidenceRootHandle(string) (*os.File, error) {
	return nil, errUnsupportedProcessTree
}

func createEvidenceFileAt(*os.File, string) (*os.File, error) {
	return nil, errUnsupportedProcessTree
}

func openReadFileAt(*os.File, string) (*os.File, error) {
	return nil, errUnsupportedProcessTree
}

func makeDirectoryAt(*os.File, string, uint32) error {
	return errUnsupportedProcessTree
}

func removeDirectoryAt(*os.File, string) error {
	return errUnsupportedProcessTree
}

func linkPublicationProofAt(*os.File, string, string) error {
	return errUnsupportedProcessTree
}

func newProcessTree(_ *exec.Cmd) (processTree, error) {
	return nil, errUnsupportedProcessTree
}
