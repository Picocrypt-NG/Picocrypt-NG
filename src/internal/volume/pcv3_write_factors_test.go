package volume

import (
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPCV3WriteFactorsPreserveSelectedShapeAndFileOrder(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first.key"), filepath.Join(dir, "second.key")
	for path, contents := range map[string]string{first: "first factor", second: "second factor"} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name     string
		password string
		files    []string
		ordered  bool
		mode     pcv3operation.CredentialMode
		policy   pcv3operation.FactorPolicy
		order    pcv3operation.KeyfileMode
	}{
		{"password only", "raw pass", nil, true, pcv3operation.CredentialModePasswordOnly, pcv3operation.FactorPolicyPasswordOnly, pcv3operation.KeyfileModeNone},
		{"empty selection", "", nil, true, pcv3operation.CredentialModePasswordOnly, pcv3operation.FactorPolicyPasswordOnly, pcv3operation.KeyfileModeNone},
		{"one ordered file", "", []string{first}, true, pcv3operation.CredentialModeKeyfilesOnly, pcv3operation.FactorPolicyKeyfilesOnly, pcv3operation.KeyfileModeOrdered},
		{"combined unordered", "e\u0301", []string{second, first}, false, pcv3operation.CredentialModePasswordAndKeyfiles, pcv3operation.FactorPolicyPasswordAndKeyfiles, pcv3operation.KeyfileModeUnordered},
	} {
		t.Run(test.name, func(t *testing.T) {
			password := []byte(test.password)
			factors, err := pcv3WriteFactors(&EncryptRequest{Password: password, Keyfiles: test.files, KeyfileOrdered: test.ordered})
			if err != nil {
				t.Fatal(err)
			}
			defer factors.Close()
			if factors.Mode != test.mode || factors.ExpectedPolicy != test.policy || factors.KeyfileMode != test.order ||
				len(factors.Keyfiles) != len(test.files) || string(factors.Password) != test.password {
				t.Fatalf("selected factors changed before write: mode=%v, policy=%v, order=%v, files=%d",
					factors.Mode, factors.ExpectedPolicy, factors.KeyfileMode, len(factors.Keyfiles))
			}
			files := make([]*os.File, len(test.files))
			for index, path := range test.files {
				file := factors.Keyfiles[index].BorrowFile()
				if file == nil || file.Name() != path {
					t.Fatalf("keyfile %d lost its direct descriptor or selected position", index)
				}
				if offset, err := file.Seek(0, io.SeekCurrent); offset != 0 || err != nil {
					t.Fatalf("keyfile %d was read during acquisition: offset=%d, err=%v", index, offset, err)
				}
				files[index] = file
			}
			ownedPassword := factors.Password
			if err := factors.Close(); err != nil {
				t.Fatal(err)
			}
			var probe [1]byte
			for index, file := range files {
				if n, err := file.Read(probe[:]); n != 0 || !errors.Is(err, os.ErrClosed) {
					t.Fatalf("keyfile %d read after cleanup = %d, %v; want closed", index, n, err)
				}
			}
			if !bytes.Equal(ownedPassword, make([]byte, len(password))) || string(password) != test.password {
				t.Fatal("closing factors did not wipe its password copy independently of the caller")
			}
		})
	}
}
