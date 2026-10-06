package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"fmt"
	"io"
	"strconv"
)

// WriteSizeError is a closed geometry rejection with no request data or cause.
type WriteSizeError struct{}

func (*WriteSizeError) Error() string        { return "pcv3operation: invalid write size" }
func (err *WriteSizeError) String() string   { return err.Error() }
func (err *WriteSizeError) GoString() string { return err.Error() }
func (err *WriteSizeError) Format(state fmt.State, verb rune) {
	value := err.Error()
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = io.WriteString(state, value)
}

// WriteCiphertextLength returns the canonical native ciphertext length for disk
// accounting. It performs no KDF, I/O, allocation by plaintext size, or admission.
// The writer must still validate credentials, comment contents, and the source.
func WriteCiphertextLength(mode WriteMode, plaintextLength uint64, commentBytes uint32, payloadBodyRS bool) (uint64, error) {
	var nativeMode pcv3.WriteSizeMode
	switch mode {
	case WriteModeNormal:
		nativeMode = pcv3.WriteSizeNormal
	case WriteModeD1:
		nativeMode = pcv3.WriteSizeD1
	default:
		return 0, &WriteSizeError{}
	}
	length, err := pcv3.WriteCiphertextLength(nativeMode, plaintextLength, commentBytes, payloadBodyRS)
	if err != nil {
		return 0, &WriteSizeError{}
	}
	return length, nil
}
