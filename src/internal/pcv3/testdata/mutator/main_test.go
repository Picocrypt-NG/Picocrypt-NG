package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunnerMechanics(t *testing.T) {
	source := []byte("before\nanchor\nafter\n")
	mutation := mutationSpec{
		ID:           "P3-ROUTE-ORDER-001",
		SourceSHA256: sha256Hex(source),
		Anchor:       "anchor\n",
		AnchorSHA256: sha256Hex([]byte("anchor\n")),
		Replacement:  "replacement\n",
	}
	mutated, err := applyMutation(source, mutation)
	if err != nil {
		t.Fatalf("applyMutation() error = %v", err)
	}
	if string(mutated) != "before\nreplacement\nafter\n" {
		t.Fatalf("applyMutation() = %q", mutated)
	}
	mutation.Anchor = "missing\n"
	mutation.AnchorSHA256 = sha256Hex([]byte(mutation.Anchor))
	if _, err := applyMutation(source, mutation); err == nil || !strings.Contains(err.Error(), "exactly once") {
		t.Fatalf("missing anchor error = %v; want exactly-once rejection", err)
	}

	passing := []byte("{\"Action\":\"run\",\"Test\":\"TestBinding\"}\n" +
		"{\"Action\":\"pass\",\"Test\":\"TestBinding\"}\n")
	if err := requireBaselinePass(passing, nil, "TestBinding"); err != nil {
		t.Fatalf("requireBaselinePass() error = %v", err)
	}
	failing := []byte("{\"Action\":\"run\",\"Test\":\"TestBinding\"}\n" +
		"{\"Action\":\"output\",\"Test\":\"TestBinding\",\"Output\":\"binding removed\\n\"}\n" +
		"{\"Action\":\"fail\",\"Test\":\"TestBinding\"}\n")
	if err := requireNamedAssertionFailure(failing, errors.New("exit status 1"), "TestBinding", "binding removed"); err != nil {
		t.Fatalf("requireNamedAssertionFailure() error = %v", err)
	}
	setupFailure := []byte("{\"Action\":\"fail\",\"Package\":\"example\"}\n")
	if err := requireNamedAssertionFailure(setupFailure, errors.New("exit status 1"), "TestBinding", "binding removed"); err == nil {
		t.Fatal("setup failure counted as a named assertion failure")
	}

	report := campaignReport{
		SchemaVersion:  1,
		BaselineCommit: strings.Repeat("a", 40),
		BaselineTree:   strings.Repeat("b", 40),
		SpecRevision:   "0.3",
		SpecSHA256:     strings.Repeat("c", 64),
		ManifestSHA256: strings.Repeat("d", 64),
		Command:        canonicalCampaignCommand,
		Mutations: []mutationResult{{
			ID:                   "P3-ROUTE-ORDER-001",
			BaselineGreen:        true,
			Applied:              true,
			Compiled:             true,
			NamedAssertionFailed: true,
			Restored:             true,
			Killed:               true,
		}},
	}
	first, err := marshalReport(report)
	if err != nil {
		t.Fatalf("marshalReport() error = %v", err)
	}
	second, err := marshalReport(report)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("marshalReport() is nondeterministic: err=%v", err)
	}
	for _, forbidden := range []string{"/home/", "/tmp/", "timestamp", "hostname"} {
		if bytes.Contains(first, []byte(forbidden)) {
			t.Fatalf("report contains volatile/private field %q", forbidden)
		}
	}

	resultPath := filepath.Join(t.TempDir(), "report.json")
	if err := writeAtomicReport(resultPath, first); err != nil {
		t.Fatalf("writeAtomicReport() error = %v", err)
	}
	written, err := os.ReadFile(resultPath)
	if err != nil || !bytes.Equal(written, first) {
		t.Fatalf("written report mismatch: err=%v", err)
	}
	if err := writeAtomicReport(resultPath, first); err == nil {
		t.Fatal("writeAtomicReport() overwrote retained evidence")
	}

	repoRoot, err := gitValue(".", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatalf("resolve test repository: %v", err)
	}
	commit, err := gitValue(repoRoot, "rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("resolve test commit: %v", err)
	}
	committedTree := t.TempDir()
	if err := materializeCommittedTree(repoRoot, commit, committedTree); err != nil {
		t.Fatalf("materializeCommittedTree() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(committedTree, "src", "go.mod")); err != nil {
		t.Fatalf("materialized committed tree lacks src/go.mod: %v", err)
	}
}
