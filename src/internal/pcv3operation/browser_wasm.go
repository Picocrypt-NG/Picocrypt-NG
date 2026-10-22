//go:build js && wasm

package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/secret"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

const (
	BrowserMaxPlaintextBytes    = 128 << 20
	BrowserMaxPCV3VolumeBytes   = 256 << 20
	BrowserMaxLegacyVolumeBytes = 1 << 30
	BrowserMaxKeyfileBytes      = 64 << 20 // Aggregate across all selected files.
	BrowserMaxPasswordBytes     = 1 << 20
	BrowserMaxCommentBytes      = 99999
	browserGoBudget             = (2 << 30) - (128 << 20)
	browserWorkingReserve       = 96 << 20
	browserJSBudget             = 768 << 20
)

// BrowserWriteRequest transfers every byte buffer on call. It carries no key,
// entropy, KDF, admission, or filesystem capability. Available only in js/wasm.
type BrowserWriteRequest struct {
	Data, Password, Comment []byte
	Keyfiles                [][]byte
	KeyfileOrdered          bool
	Suite                   Suite
	ReedSolomon             bool
	Deniability             bool
}

type BrowserReadRequest struct {
	Data, Password         []byte
	Keyfiles               [][]byte
	KeyfileOrdered         bool
	Mode                   Mode
	Role                   PhysicalRole
	D1SuiteHint            Suite
	ForceUnverifiedConsent bool
}

func (BrowserWriteRequest) String() string     { return "pcv3operation: browser write request [REDACTED]" }
func (r BrowserWriteRequest) GoString() string { return r.String() }
func (r BrowserWriteRequest) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, r.String())
}

func (BrowserReadRequest) String() string     { return "pcv3operation: browser read request [REDACTED]" }
func (r BrowserReadRequest) GoString() string { return r.String() }
func (r BrowserReadRequest) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, r.String())
}

// BrowserResult owns its output until Close. Its numeric code is the website
// convention; only codes 0 and 10 can carry data, and 10 is always untrusted.
type BrowserResult struct {
	code int
	read *pcv3.MemoryReadResult
	data []byte
}

func (r *BrowserResult) Code() int {
	if r == nil {
		return 6
	}
	return r.code
}

func (r *BrowserResult) Bytes() []byte {
	if r == nil {
		return nil
	}
	if r.read != nil {
		return r.read.Bytes()
	}
	return r.data
}

func (r *BrowserResult) Comment() string {
	if r == nil || r.read == nil {
		return ""
	}
	return r.read.AuthenticatedComment()
}

func (r *BrowserResult) Recovered() bool {
	return r != nil && r.read != nil && r.read.Outcome() == OutcomeAuthenticatedDegraded
}

func (*BrowserResult) String() string                      { return "pcv3operation: browser result" }
func (r *BrowserResult) GoString() string                  { return r.String() }
func (r *BrowserResult) Format(state fmt.State, verb rune) { _, _ = io.WriteString(state, r.String()) }

func (r *BrowserResult) Close() {
	if r == nil {
		return
	}
	if r.read != nil {
		r.read.Close()
	}
	secret.SecureZero(r.data)
	*r = BrowserResult{code: 6}
}

func clearBrowserInput(data, password []byte, files [][]byte) {
	secret.SecureZero(data)
	secret.SecureZero(password)
	for _, file := range files {
		secret.SecureZero(file)
	}
}

func browserFactorBytes(password []byte, files [][]byte) (uint64, bool) {
	if len(password) > BrowserMaxPasswordBytes || len(files) > MaxKeyfiles {
		return 0, false
	}
	var total uint64
	for _, file := range files {
		if len(file) == 0 || uint64(len(file)) > BrowserMaxKeyfileBytes-total {
			return 0, false
		}
		total += uint64(len(file))
	}
	return total, true
}

func browserFactors(password []byte, files [][]byte, ordered bool) *pcv3credential.FactorRequest {
	request := &pcv3credential.FactorRequest{Password: password, Mode: CredentialModePasswordOnly, ExpectedPolicy: FactorPolicyPasswordOnly, KeyfileMode: KeyfileModeNone}
	if len(files) != 0 {
		request.Mode, request.ExpectedPolicy, request.KeyfileMode = CredentialModeKeyfilesOnly, FactorPolicyKeyfilesOnly, KeyfileModeUnordered
		if len(password) != 0 {
			request.Mode, request.ExpectedPolicy = CredentialModePasswordAndKeyfiles, FactorPolicyPasswordAndKeyfiles
		}
		if ordered {
			request.KeyfileMode = KeyfileModeOrdered
		}
		for _, file := range files {
			request.Keyfiles = append(request.Keyfiles, OwnKeyfileReader(io.NopCloser(bytes.NewReader(file))))
		}
	}
	return request
}

func browserJSWithinBudget(input, output, factors uint64) bool {
	return input <= BrowserMaxPCV3VolumeBytes && output <= BrowserMaxPCV3VolumeBytes &&
		factors <= BrowserMaxKeyfileBytes && input+output+factors+(64<<20) <= browserJSBudget
}

// browserKDFWithinBudget enforces only the bounded Go address-space policy. It
// is not an observation or guarantee of physical browser/host RAM availability.
func browserKDFWithinBudget(p pcv3credential.KDFProfile, heap, pending uint64) bool {
	valid := p.Argon2Version == 19 && p.MemoryKiB == 1048576 && p.SaltBytes == 16 && p.OutputBytes == 32 &&
		((p.ID == 1 && p.Time == 4 && p.Parallelism == 4) || ((p.ID == 2 || p.ID == 3) && p.Time == 8 && p.Parallelism == 8))
	if !valid || heap > browserGoBudget || pending > BrowserMaxPCV3VolumeBytes {
		return false
	}
	return (1<<30)+browserWorkingReserve+pending <= browserGoBudget-heap
}

type browserAddressAdmitter struct {
	pending uint64
	denied  bool
}

func (a *browserAddressAdmitter) AdmitKDF(ctx context.Context, p pcv3credential.KDFProfile) (pcv3credential.KDFAdmission, error) {
	if ctx == nil {
		a.denied = true
		return pcv3credential.KDFAdmissionDeniedUnknown, nil
	}
	if err := ctx.Err(); err != nil {
		a.denied = true
		return pcv3credential.KDFAdmissionDeniedUnknown, err
	}
	// Each fixed-profile call gets a fresh collection. In D1 this reclaims the
	// prior unreachable KDF workspace rather than counting two live workspaces.
	debug.FreeOSMemory()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	if !browserKDFWithinBudget(p, stats.HeapAlloc, a.pending) {
		a.denied = true
		return pcv3credential.KDFAdmissionDeniedInsufficient, nil
	}
	return pcv3credential.KDFAdmissionGranted, nil
}

func browserPreflightAllocation(pending uint64) bool {
	debug.FreeOSMemory()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc <= browserGoBudget && pending <= browserGoBudget-stats.HeapAlloc &&
		(1<<30)+browserWorkingReserve <= browserGoBudget-stats.HeapAlloc-pending
}

// BrowserInspectNormal checks ordinary Normal input and its declared output
// bound using only bounded structural reads. It grants no credential authority.
func BrowserInspectNormal(source io.ReaderAt, size int64) int {
	if size < 0 || size > BrowserMaxPCV3VolumeBytes {
		return 14
	}
	route, structure, err := pcv3.Probe(source, size)
	if err != nil {
		var failure pcv3.Failure
		if errors.As(err, &failure) && failure.Outcome() == OutcomeUnsupportedRoutingPreKDF {
			return 1
		}
		return 2
	}
	if route != pcv3.RouteNormalPCV {
		return 1
	}
	for i := range structure.CandidateCount() {
		candidate, _ := structure.CandidateAt(i)
		if candidate.PlaintextLength() > BrowserMaxPlaintextBytes {
			return 14
		}
	}
	return 0
}

func BrowserWrite(ctx context.Context, request *BrowserWriteRequest) *BrowserResult {
	if request == nil {
		return &BrowserResult{code: 6}
	}
	owned := *request
	*request = BrowserWriteRequest{}
	defer clearBrowserInput(owned.Data, owned.Password, owned.Keyfiles)
	defer secret.SecureZero(owned.Comment)
	if ctx == nil || (owned.Suite != SuiteStandard && owned.Suite != SuiteParanoid) || len(owned.Comment) > BrowserMaxCommentBytes {
		return &BrowserResult{code: 6}
	}
	factorBytes, valid := browserFactorBytes(owned.Password, owned.Keyfiles)
	if !valid || len(owned.Data) > BrowserMaxPlaintextBytes {
		return &BrowserResult{code: 14}
	}
	if len(owned.Password) == 0 && len(owned.Keyfiles) == 0 {
		return &BrowserResult{code: 13}
	}
	mode := WriteModeNormal
	if owned.Deniability {
		mode = WriteModeD1
	}
	length, err := WriteCiphertextLength(mode, uint64(len(owned.Data)), uint32(len(owned.Comment)), owned.ReedSolomon) //nolint:gosec // Comment bound above.
	if err != nil || length > BrowserMaxPCV3VolumeBytes || !browserJSWithinBudget(uint64(len(owned.Data)), length, factorBytes) || !browserPreflightAllocation(length) {
		return &BrowserResult{code: 14}
	}
	admitter := &browserAddressAdmitter{}
	output, err := pcv3.RunMemoryWrite(ctx, &pcv3.MemoryWriteRequest{
		Suite: owned.Suite, PayloadKind: pcv3.PayloadKindRaw,
		PayloadBodyRS: owned.ReedSolomon, Comment: owned.Comment, Factors: browserFactors(owned.Password, owned.Keyfiles, owned.KeyfileOrdered),
		Admitter: admitter, Data: owned.Data, Deniability: owned.Deniability, MaxOutputBytes: BrowserMaxPCV3VolumeBytes,
	})
	if err != nil {
		secret.SecureZero(output)
		if admitter.denied {
			return &BrowserResult{code: 14}
		}
		var stage interface{ Stage() Stage }
		if errors.As(err, &stage) && stage.Stage() == StageResourceBudget {
			return &BrowserResult{code: 14}
		}
		return &BrowserResult{code: 6}
	}
	return &BrowserResult{data: output}
}

func BrowserRead(ctx context.Context, request *BrowserReadRequest) *BrowserResult {
	if request == nil {
		return &BrowserResult{code: 6}
	}
	owned := *request
	*request = BrowserReadRequest{}
	defer clearBrowserInput(owned.Data, owned.Password, owned.Keyfiles)
	factorBytes, valid := browserFactorBytes(owned.Password, owned.Keyfiles)
	if !valid || len(owned.Data) > BrowserMaxPCV3VolumeBytes {
		return &BrowserResult{code: 14}
	}
	if ctx == nil || owned.Mode < ModeReadNormal || owned.Mode > ModeForceUnverifiedD1 {
		return &BrowserResult{code: 6}
	}
	core := &pcv3.MemoryReadRequest{Source: owned.Data, Mode: pcv3.MemoryReadMode(owned.Mode), MaxOutputBytes: BrowserMaxPlaintextBytes}
	switch owned.Mode {
	case ModeForceUnverifiedNormal:
		if !owned.ForceUnverifiedConsent || owned.D1SuiteHint != 0 || (owned.Role != RolePrimary && owned.Role != RoleBackup) {
			return &BrowserResult{code: 6}
		}
		if owned.Role == RolePrimary {
			core.Role = pcv3.CapsuleRolePrimary
		} else {
			core.Role = pcv3.CapsuleRoleBackup
		}
	case ModeForceUnverifiedD1:
		if !owned.ForceUnverifiedConsent || (owned.Role != RoleD1Front && owned.Role != RoleD1Tail) ||
			(owned.D1SuiteHint != 0 && owned.D1SuiteHint != SuiteStandard && owned.D1SuiteHint != SuiteParanoid) {
			return &BrowserResult{code: 6}
		}
		if owned.Role == RoleD1Front {
			core.D1Role = pcv3.D1BootstrapFront
		} else {
			core.D1Role = pcv3.D1BootstrapTail
		}
		core.SuiteHint = owned.D1SuiteHint
	default:
		if owned.Role != RoleNone || owned.D1SuiteHint != 0 || owned.ForceUnverifiedConsent {
			return &BrowserResult{code: 6}
		}
	}
	if !browserJSWithinBudget(uint64(len(owned.Data)), BrowserMaxPlaintextBytes, factorBytes) {
		return &BrowserResult{code: 14}
	}
	admitter := &browserAddressAdmitter{pending: BrowserMaxPlaintextBytes}
	core.Admitter, core.Factors = admitter, browserFactors(owned.Password, owned.Keyfiles, owned.KeyfileOrdered)
	result, err := pcv3.RunMemoryRead(ctx, core)
	if result == nil {
		return &BrowserResult{code: 6}
	}
	code := 6
	switch result.Outcome() {
	case OutcomeSuccess, OutcomeAuthenticatedDegraded:
		code = 0
	case OutcomeForcePartial, OutcomeForceUnverified:
		code = 10
	case OutcomeUnsupportedRoutingPreKDF:
		code = 1
	case OutcomeInvalidStructurePreKDF:
		code = 2
	case OutcomeCredentialsOrDamage:
		code = 3
	case OutcomeAuthenticationFailed:
		code = 4
	case OutcomeAmbiguousVolume:
		code = 15
	}
	if admitter.denied || result.Stage() == StageResourceBudget {
		code = 14
	}
	if err != nil && code == 0 {
		code = 6
	}
	if code != 0 && code != 10 {
		result.Close()
		return &BrowserResult{code: code}
	}
	return &BrowserResult{code: code, read: result}
}
