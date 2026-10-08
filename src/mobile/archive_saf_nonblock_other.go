//go:build !android && !linux

package mobile

func preparePCV3ArchiveSAFNonblocking(int64) bool {
	return false
}
