package mobile

import "errors"

// SetInputNonblocking prepares a borrowed Android input descriptor for cancellable
// pipe reads. The caller must keep the descriptor open throughout this call; it
// remains responsible for reads and closing it. No bytes are consumed.
func SetInputNonblocking(fd int64) error {
	if fd < 0 || fd > maxPCV3OutputFD {
		return errors.New("invalid input descriptor")
	}
	return setDescriptorNonblocking(int(fd))
}

func preparePCV3ArchiveSAFNonblocking(fd int64) bool {
	return SetInputNonblocking(fd) == nil
}
