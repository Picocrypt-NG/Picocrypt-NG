package fileops

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPanicCleanupCarrierRetainsOriginalWithoutRenderingOrUnwrapping(t *testing.T) {
	original := errors.New("private original panic")
	cleanup := errors.New("private cleanup path /secret/stage")
	var recovered any
	func() { defer func() { recovered = recover() }(); RepanicWithCleanup(original, cleanup) }()
	carrier, ok := recovered.(*cleanupPanic)
	if !ok || carrier.original != original || carrier.cleanup != cleanup { //nolint:errorlint // Private identity is preserved, not merely an equivalent wrapped cause.
		t.Fatal("carrier lost original panic or cleanup cause")
	}
	if !PanicCleanupIncomplete(recovered) || !PanicCleanupIncomplete(*carrier) {
		t.Fatal("carrier lost warning predicate")
	}
	for _, rendered := range []string{carrier.Error(), carrier.String(), carrier.GoString(), fmt.Sprintf("%v", carrier), fmt.Sprintf("%+v", carrier), fmt.Sprintf("%#v", carrier), fmt.Sprintf("%s", carrier), fmt.Sprintf("%q", carrier), fmt.Sprintf("%x", carrier), fmt.Sprintf("%#v", *carrier)} {
		if rendered != cleanupPanicMessage || strings.Contains(rendered, "private") {
			t.Fatal("carrier formatter exposed a private diagnostic")
		}
	}
	if errors.Is(carrier, original) || errors.Is(carrier, cleanup) {
		t.Fatal("carrier exposed a private cause via unwrapping")
	}
	if PanicCleanupIncomplete(original) || PanicCleanupIncomplete(nil) || PanicCleanupIncomplete((*cleanupPanic)(nil)) {
		t.Fatal("ordinary panic acquired cleanup warning")
	}
}

func TestRepanicWithSuccessfulCleanupPreservesExactOriginalValue(t *testing.T) {
	original := &struct{ private string }{"private panic payload"}
	var recovered any
	func() { defer func() { recovered = recover() }(); RepanicWithCleanup(original, nil) }()
	if recovered != original || PanicCleanupIncomplete(recovered) {
		t.Fatal("successful cleanup changed panic identity")
	}
}
