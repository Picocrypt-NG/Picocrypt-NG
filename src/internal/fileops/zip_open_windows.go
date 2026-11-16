package fileops

import (
	"golang.org/x/sys/windows"
	"os"
)

func openZIPInputInRoot(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}
