// Package pcv3validation implements the Picocrypt NG Phase 9 mutation-campaign
// tooling: the closed twelve-family manifest parser, the exact go test event
// acceptance for pristine and mutant oracles, and the isolated source-copy
// campaign that refuses compile-only, no-op, missing-selector, unrelated, and
// error-only kills.
//
// Everything in this package is tooling/policy evidence. It never counts as
// product coverage: the manifest only points at the owning product tests, and
// only those product oracles establish product behavior. The terminal product
// campaign is executed exactly once by Plan 09-03; this package provides the
// machinery and its synthetic self-tests.
package pcv3validation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ManifestSchemaVersion is the only accepted closed manifest schema version.
const ManifestSchemaVersion = 1

// CanonicalFamilies is the closed twelve-family set in canonical order, as
// frozen by the Phase 9 validation strategy. Every family must be nonempty in
// an accepted manifest and no other family may appear.
var CanonicalFamilies = []string{
	"routing",
	"credential",
	"key-label",
	"capsule",
	"record",
	"reed-solomon",
	"metadata",
	"tail-completion",
	"force",
	"d1",
	"publication-extraction",
	"lifecycle-diagnostics",
}

// allowedPackages is the closed allowlist of repository test packages a
// manifest entry may select.
var allowedPackages = map[string]bool{
	"./internal/pcv3":            true,
	"./internal/pcv3credential":  true,
	"./internal/pcv3publication": true,
	"./internal/pcv3operation":   true,
	"./internal/volume":          true,
}

// allowedSourceDirs is the closed allowlist of repository directories a
// mutated source file may live in.
var allowedSourceDirs = map[string]bool{
	"internal/pcv3":            true,
	"internal/pcv3credential":  true,
	"internal/pcv3publication": true,
	"internal/pcv3operation":   true,
	"internal/volume":          true,
	"internal/fileops":         true,
}

// Observations freezes the exact oracle expectations applicable to a
// mutation's invariant. Every field is mandatory; an aspect the invariant
// genuinely does not exercise is recorded as the closed token "n/a".
type Observations struct {
	Stage       string `json:"stage"`
	KDF         string `json:"kdf"`
	Output      string `json:"output"`
	Publication string `json:"publication"`
	Completion  string `json:"completion"`
	Owner       string `json:"owner"`
	Cleanup     string `json:"cleanup"`
}

// Mutation is one closed manifest entry: one exact one-anchor, non-no-op
// transform of one allowlisted source file plus the exact product oracle
// (package, top-level test, required subtest when applicable) and the frozen
// behavioral marker that must appear in the mutant's named failure.
//
// Replacement is a pointer so an absent JSON field is rejected while an
// explicitly empty replacement remains representable: two frozen RED
// transforms (force-ignore-live-role, d1-decrypt-early) are demonstrated
// deletions whose replacement is the empty string.
type Mutation struct {
	ID           string       `json:"id"`
	Family       string       `json:"family"`
	SourcePath   string       `json:"source_path"`
	SourceSHA256 string       `json:"source_sha256"`
	Anchor       string       `json:"anchor"`
	Replacement  *string      `json:"replacement"`
	Package      string       `json:"package"`
	Test         string       `json:"test"`
	Subtest      *string      `json:"subtest"`
	Marker       string       `json:"marker"`
	Observations Observations `json:"observations"`
}

// ReplacementText returns the frozen replacement, or "" when absent (which
// validation rejects before any campaign use).
func (mutation Mutation) ReplacementText() string {
	if mutation.Replacement == nil {
		return ""
	}
	return *mutation.Replacement
}

// RequiredSubtest returns the frozen required subtest, or "" when the oracle
// is the whole top-level test.
func (mutation Mutation) RequiredSubtest() string {
	if mutation.Subtest == nil {
		return ""
	}
	return *mutation.Subtest
}

// Manifest is the closed mutation-campaign manifest.
type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	Mutations     []Mutation `json:"mutations"`
}

// ParseManifest decodes and validates the closed manifest schema. Unknown
// fields, trailing JSON, and any invariant violation are rejected.
func ParseManifest(data []byte) (*Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode mutation manifest: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("mutation manifest has trailing JSON")
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// LoadManifest reads a manifest through rooted filesystem operations and
// returns the validated manifest plus its raw bytes (for report hashing).
func LoadManifest(path string) (*Manifest, []byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve mutation manifest: %w", err)
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, nil, fmt.Errorf("open mutation manifest parent: %w", err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(filepath.Base(absolute))
	if err != nil {
		return nil, nil, fmt.Errorf("read mutation manifest: %w", err)
	}
	manifest, err := ParseManifest(data)
	if err != nil {
		return nil, nil, err
	}
	return manifest, data, nil
}

// Validate enforces every closed manifest invariant.
func (manifest *Manifest) Validate() error {
	if manifest == nil || manifest.SchemaVersion != ManifestSchemaVersion {
		return errors.New("invalid mutation manifest schema version")
	}
	if len(manifest.Mutations) == 0 {
		return errors.New("mutation manifest has no mutations")
	}
	ids := make(map[string]bool, len(manifest.Mutations))
	families := make(map[string]int, len(CanonicalFamilies))
	for i := range manifest.Mutations {
		mutation := &manifest.Mutations[i]
		if err := mutation.validate(); err != nil {
			return fmt.Errorf("mutation %q: %w", mutation.ID, err)
		}
		if ids[mutation.ID] {
			return fmt.Errorf("duplicate mutation ID %q", mutation.ID)
		}
		ids[mutation.ID] = true
		families[mutation.Family]++
	}
	for _, family := range CanonicalFamilies {
		if families[family] == 0 {
			return fmt.Errorf("mutation manifest family %q is empty or missing", family)
		}
		delete(families, family)
	}
	for family := range families {
		return fmt.Errorf("mutation manifest has unexpected family %q", family)
	}
	return nil
}

func (mutation *Mutation) validate() error {
	if !validMutationID(mutation.ID) {
		return errors.New("missing or invalid mutation ID")
	}
	if !canonicalFamily(mutation.Family) {
		return fmt.Errorf("unexpected family %q", mutation.Family)
	}
	if !validSourcePath(mutation.SourcePath) {
		return fmt.Errorf("source path %q is not an allowlisted repository source file", mutation.SourcePath)
	}
	if !validSHA256Hex(mutation.SourceSHA256) {
		return errors.New("invalid source preimage SHA-256")
	}
	if mutation.Anchor == "" {
		return errors.New("empty anchor")
	}
	if mutation.Replacement == nil {
		return errors.New("replacement field is absent")
	}
	if *mutation.Replacement == mutation.Anchor {
		return errors.New("replacement equals anchor (no-op transform)")
	}
	if !allowedPackages[mutation.Package] {
		return fmt.Errorf("package %q is not allowlisted", mutation.Package)
	}
	if !validTestName(mutation.Test) {
		return fmt.Errorf("test name %q is not a valid top-level test identifier", mutation.Test)
	}
	if mutation.Subtest == nil {
		return errors.New("subtest field is absent")
	}
	if *mutation.Subtest != "" && !validSingleLine(*mutation.Subtest) {
		return errors.New("subtest is not a single printable line")
	}
	if mutation.Marker == "" || !validSingleLine(mutation.Marker) {
		return errors.New("marker is empty or not a single line")
	}
	return mutation.Observations.validate()
}

func (observations Observations) validate() error {
	for field, value := range map[string]string{
		"stage":       observations.Stage,
		"kdf":         observations.KDF,
		"output":      observations.Output,
		"publication": observations.Publication,
		"completion":  observations.Completion,
		"owner":       observations.Owner,
		"cleanup":     observations.Cleanup,
	} {
		if value == "" || !validSingleLine(value) {
			return fmt.Errorf("observation %q is empty or not a single line", field)
		}
	}
	return nil
}

func canonicalFamily(family string) bool {
	for _, candidate := range CanonicalFamilies {
		if family == candidate {
			return true
		}
	}
	return false
}

func validMutationID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func validSourcePath(path string) bool {
	if !validRelativePath(path) || !strings.HasSuffix(path, ".go") ||
		strings.HasSuffix(path, "_test.go") {
		return false
	}
	elements := strings.Split(path, "/")
	if len(elements) != 3 {
		return false
	}
	if elements[0] != "internal" || elements[2] == "testdata" {
		return false
	}
	return allowedSourceDirs[elements[0]+"/"+elements[1]]
}

func validTestName(name string) bool {
	if !strings.HasPrefix(name, "Test") || len(name) > 256 {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func validSingleLine(value string) bool {
	if len(value) > 1024 || strings.ContainsAny(value, "\r\n") {
		return false
	}
	for _, r := range value {
		if r < 0x20 && r != '\t' {
			return false
		}
	}
	return true
}

func validRelativePath(path string) bool {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") {
		return false
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	return cleaned == path && cleaned != "." && cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
