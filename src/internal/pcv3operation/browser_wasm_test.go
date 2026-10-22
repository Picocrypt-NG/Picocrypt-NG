//go:build js && wasm

package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestBrowserRequestFormattingRedactsOwnedFactorsAndData(t *testing.T) {
	for _, request := range []any{
		BrowserWriteRequest{Data: []byte("private data"), Password: []byte("private factor")},
		BrowserReadRequest{Data: []byte("private data"), Password: []byte("private factor")},
	} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, request); strings.Contains(got, "private") || !strings.Contains(got, "REDACTED") {
				t.Fatal("browser request formatting exposed owned input")
			}
		}
	}
}

func TestBrowserAddressSpacePolicyPreservesFixedKDF(t *testing.T) {
	standard := pcv3credential.KDFProfile{ID: 1, Argon2Version: 19, Time: 4, MemoryKiB: 1048576, Parallelism: 4, SaltBytes: 16, OutputBytes: 32}
	if !browserKDFWithinBudget(standard, 32<<20, BrowserMaxPlaintextBytes) {
		t.Fatal("fixed standard profile refused with bounded address-space headroom")
	}
	if browserKDFWithinBudget(standard, browserGoBudget, 0) {
		t.Fatal("address-space budget overcommit accepted")
	}
	for _, mutate := range []func(*pcv3credential.KDFProfile){
		func(p *pcv3credential.KDFProfile) { p.MemoryKiB /= 2 },
		func(p *pcv3credential.KDFProfile) { p.Time-- },
		func(p *pcv3credential.KDFProfile) { p.Parallelism-- },
	} {
		profile := standard
		mutate(&profile)
		if browserKDFWithinBudget(profile, 0, 0) {
			t.Fatal("browser policy accepted a weakened KDF profile")
		}
	}
}

func TestBrowserWriteMalformedRequestConsumesEveryOwnedBuffer(t *testing.T) {
	data, password, key, comment := []byte("input"), []byte("password"), []byte("keyfile"), []byte("comment")
	request := &BrowserWriteRequest{Data: data, Password: password, Keyfiles: [][]byte{key}, Comment: comment, Suite: 255}
	result := BrowserWrite(context.Background(), request)
	defer result.Close()
	if result.Code() != 6 || len(result.Bytes()) != 0 || request.Data != nil {
		t.Fatal("malformed write did not fail closed")
	}
	for _, owned := range [][]byte{data, password, key, comment} {
		if !bytes.Equal(owned, make([]byte, len(owned))) {
			t.Fatal("browser facade retained consumed data")
		}
	}
}

func TestBrowserReadUnknownMajorConsumesFactorsWithoutOutput(t *testing.T) {
	password := []byte("unused password")
	result := BrowserRead(context.Background(), &BrowserReadRequest{Data: []byte("PCV\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), Password: password, Mode: ModeReadNormal})
	defer result.Close()
	if result.Code() != 1 || len(result.Bytes()) != 0 || !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatalf("unknown-major read: code=%d", result.Code())
	}
}
