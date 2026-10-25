package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPCV3RecoveryTrustMessagesFromRealOperation(t *testing.T) {
	if !nativeCLIDirectorySyncSupported(t, t.TempDir()) {
		t.Skip("durable recovery-artifact terminal contract requires native directory sync")
	}
	volume, err := os.ReadFile(filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "normal", "volumes", "normal-standard-combined-ordered-two-mib.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(volume)
	if hex.EncodeToString(digest[:]) != "5845cf7585fb85f5e48d20b9c0e2a075355190e2bb9445217f455bca31fcc9da" {
		t.Fatal("independent two-record volume changed")
	}
	// The frozen first record remains authenticated. Damage only the second
	// record's MAC and the final MAC, so both ranges still have bytes.
	volume[2098424] ^= 1
	volume[2098536] ^= 1
	dir := t.TempDir()
	input := writePCV3CLIFixture(t, dir, "damaged.pcv", volume)
	red := writePCV3CLIFixture(t, dir, "red.key", []byte("red"))
	blue := writePCV3CLIFixture(t, dir, "blue.key", []byte("blue"))
	output := filepath.Join(dir, "recovery.pcv3-recovery")
	result, observation := runPCV3CLIHelper(t, dir, pcv3CLIHelperConfig{
		Args:        []string{"decrypt", input, "-o", output, "--pcv3-action=force", "--pcv3-role=backup", "--pcv3-factors=combined", "--pcv3-keyfile-order=ordered", "-p", "mix", "-k", red, "-k", blue, "--quiet"},
		Observation: filepath.Join(dir, "observation.json"), RealOperation: true,
		Interactive: true, ConsentLine: "RECOVER UNVERIFIED",
	}, nil)
	if !observation.Called || !observation.ConsentPresent || pcv3operation.Mode(observation.Mode) != pcv3operation.ModeForceUnverifiedNormal {
		t.Fatal("real operation did not receive live force consent")
	}
	if result.exitCode != ExitPCV3Warning || len(result.stdout) != 0 {
		t.Fatalf("untrusted output terminal = %d stdout=%q", result.exitCode, result.stdout)
	}
	artifact, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	// Independent public recovery-format oracle: one partial artifact, backup
	// role, unverified final; two exact ranges, verified then unverified.
	if len(artifact) != 2097312 || string(artifact[:16]) != "PICO-RECOVERY-3\x00" || !bytes.Equal(artifact[16:21], []byte{1, 1, 1, 2, 2}) || binary.BigEndian.Uint64(artifact[32:40]) != 2097152 || binary.BigEndian.Uint64(artifact[40:48]) != 2 {
		t.Fatalf("CLI published ordinary plaintext or wrong recovery header: bytes=%d", len(artifact))
	}
	for index, status := range []byte{1, 2} {
		entry := artifact[80+40*index : 120+40*index]
		if binary.BigEndian.Uint64(entry[0:8]) != uint64(index) || binary.BigEndian.Uint64(entry[8:16]) != uint64(index)*1048576 || binary.BigEndian.Uint64(entry[16:24]) != uint64(index+1)*1048576 || entry[36] != status {
			t.Fatalf("CLI artifact range %d = %x", index, entry)
		}
	}
	retained, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(retained, volume) {
		t.Fatal("CLI recovery changed source")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
			t.Fatalf("CLI retained private staging %q", entry.Name())
		}
	}
	want := "Outcome: force-partial\nPublication: published-durable\nWarning: Not a fully verified file. Data may be missing or unverified.\n"
	if !strings.HasSuffix(result.stderr, want) {
		t.Errorf("real CLI warning = %q; want terminal suffix %q", result.stderr, want)
	}
	if strings.Contains(result.stderr, "complete plaintext file") {
		t.Errorf("real CLI retained misleading warning: %q", result.stderr)
	}
}
