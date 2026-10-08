package pcv3operation

import (
	"errors"
	"fmt"
	"math"
	"testing"
)

func TestWriteCiphertextLengthFacadeClosedModesAndSafeFailure(t *testing.T) {
	for _, test := range []struct {
		mode WriteMode
		want uint64
	}{{WriteModeNormal, 2232}, {WriteModeD1, 2760}} {
		got, err := WriteCiphertextLength(test.mode, 0, 0, false)
		if err != nil || got != test.want {
			t.Fatalf("mode %d: length=%d err=%v; want %d", test.mode, got, err, test.want)
		}
	}
	for _, test := range []struct {
		mode    WriteMode
		plain   uint64
		comment uint32
	}{{0, 0, 0}, {255, 0, 0}, {WriteModeNormal, math.MaxUint64, 0}, {WriteModeD1, math.MaxInt64, 0}, {WriteModeNormal, 0, 100000}} {
		got, err := WriteCiphertextLength(test.mode, test.plain, test.comment, true)
		var sizeErr *WriteSizeError
		if got != 0 || !errors.As(err, &sizeErr) {
			t.Fatalf("rejected request returned length=%d err=%v", got, err)
		}
		// Public error formatting must never include request metadata or a codec cause.
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, err); got != "pcv3operation: invalid write size" {
				t.Fatalf("unsafe error format %s: %q", format, got)
			}
		}
	}
}
