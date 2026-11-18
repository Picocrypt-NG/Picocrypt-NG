package volume

import (
	"Picocrypt-NG/internal/crypto"
	"bytes"
	"context"
	"os"
	"testing"

	"golang.org/x/crypto/argon2"
)

const (
	fastTestArgon2NormalPasses    uint32 = 1
	fastTestArgon2NormalMemory    uint32 = 32 * 1024
	fastTestArgon2NormalThreads   uint8  = 1
	fastTestArgon2ParanoidPasses  uint32 = 2
	fastTestArgon2ParanoidMemory  uint32 = 64 * 1024
	fastTestArgon2ParanoidThreads uint8  = 1
)

func fastTestVolumeKey(password, salt []byte, paranoid bool) ([]byte, error) {
	passes := fastTestArgon2NormalPasses
	memory := fastTestArgon2NormalMemory
	threads := fastTestArgon2NormalThreads
	if paranoid {
		passes = fastTestArgon2ParanoidPasses
		memory = fastTestArgon2ParanoidMemory
		threads = fastTestArgon2ParanoidThreads
	}
	return argon2.IDKey(password, salt, passes, memory, threads, crypto.Argon2KeySize), nil
}

func fastTestDeniabilityKey(password, salt []byte) []byte {
	return argon2.IDKey(
		password,
		salt,
		fastTestArgon2NormalPasses,
		fastTestArgon2NormalMemory,
		fastTestArgon2NormalThreads,
		crypto.Argon2KeySize,
	)
}

func useTestKDF(
	volumeKey func(password, salt []byte, paranoid bool) ([]byte, error),
	deniabilityKey func(password, salt []byte) []byte,
) func() {
	prevVolumeKey := deriveVolumeKey
	prevDeniabilityKey := deriveDeniabilityKey
	deriveVolumeKey = volumeKey
	deriveDeniabilityKey = deniabilityKey
	return func() {
		deriveVolumeKey = prevVolumeKey
		deriveDeniabilityKey = prevDeniabilityKey
	}
}

func useFastTestKDF() func() {
	return useTestKDF(fastTestVolumeKey, fastTestDeniabilityKey)
}

var (
	productionTestVolumeKey      func(password, salt []byte, paranoid bool) ([]byte, error)
	productionTestDeniabilityKey func(password, salt []byte) []byte
	productionTestAdmission      func(context.Context) error
)

func useProductionTestKDF() func() {
	restore := useTestKDF(productionTestVolumeKey, productionTestDeniabilityKey)
	previous := admitLegacyKDF
	admitLegacyKDF = productionTestAdmission
	return func() {
		admitLegacyKDF = previous
		restore()
	}
}

func TestMain(m *testing.M) {
	productionTestVolumeKey = deriveVolumeKey
	productionTestDeniabilityKey = deriveDeniabilityKey
	productionTestAdmission = admitLegacyKDF
	admitLegacyKDF = func(ctx context.Context) error { return ctx.Err() }
	restore := useFastTestKDF()
	code := m.Run()
	restore()
	os.Exit(code)
}

func TestKDFHooksCanBeEnabledAndRestored(t *testing.T) {
	outerRestore := useTestKDF(
		func([]byte, []byte, bool) ([]byte, error) { return []byte{0x11}, nil },
		func([]byte, []byte) []byte { return []byte{0x12} },
	)
	defer outerRestore()

	innerRestore := useTestKDF(
		func([]byte, []byte, bool) ([]byte, error) { return []byte{0x21}, nil },
		func([]byte, []byte) []byte { return []byte{0x22} },
	)

	volumeKey, err := deriveVolumeKey(nil, nil, false)
	if err != nil || !bytes.Equal(volumeKey, []byte{0x21}) {
		t.Fatalf("inner volume KDF = %x, %v; want 21, nil", volumeKey, err)
	}
	if got := deriveDeniabilityKey(nil, nil); !bytes.Equal(got, []byte{0x22}) {
		t.Fatalf("inner deniability KDF = %x; want 22", got)
	}

	innerRestore()
	volumeKey, err = deriveVolumeKey(nil, nil, false)
	if err != nil || !bytes.Equal(volumeKey, []byte{0x11}) {
		t.Fatalf("restored volume KDF = %x, %v; want 11, nil", volumeKey, err)
	}
	if got := deriveDeniabilityKey(nil, nil); !bytes.Equal(got, []byte{0x12}) {
		t.Fatalf("restored deniability KDF = %x; want 12", got)
	}
}
