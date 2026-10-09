//go:build windows || wasm

package fileops

import "os"

const regularReadFlags = os.O_RDONLY
