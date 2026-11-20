//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package fileops

func unpackLinkUnsupportedFilesystem(int) bool { return false }
