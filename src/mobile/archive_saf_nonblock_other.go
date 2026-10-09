//go:build !android && !linux

package mobile

import "errors"

func setDescriptorNonblocking(int) error {
	return errors.New("nonblocking input descriptors unsupported on this platform")
}
