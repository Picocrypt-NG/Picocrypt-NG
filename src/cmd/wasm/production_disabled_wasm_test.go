//go:build js && wasm && !pcv3_production_kdf

package main

import "testing"

func requireWASMProductionKDF(t *testing.T) {
	t.Helper()
	t.Skip("requires serial real 1-GiB KDF lane: -tags pcv3_production_kdf")
}
