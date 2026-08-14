// Package pcv3operation owns the single native PCV3 operation boundary.
package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/pcv3recovery"
	"Picocrypt-NG/internal/pcv3resource"
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
)

// Mode is a closed explicit operation route. Its zero value never infers a
// format, recovery policy, or writer operation.
type Mode uint8

const (
	ModeReadNormal Mode = iota + 1
	ModeReadD1
	ModeRecoverNormal
	ModeRecoverD1
	ModeForceNormal
	ModeForceD1
	ModeForceUnverifiedNormal
	ModeForceUnverifiedD1
	ModeMigrate
)

// PhysicalRole is the exact physical input authorized for unverified Force.
// Capsule and D1 roles are deliberately distinct values.
type PhysicalRole uint8

const (
	RoleNone PhysicalRole = iota
	RolePrimary
	RoleBackup
	RoleD1Front
	RoleD1Tail
)

// StatusCode is a stable, non-sensitive progress concept.
type StatusCode uint8

const (
	StatusCheckingRequest StatusCode = iota + 1
	StatusCheckingFactors
	StatusCheckingResources
	StatusDerivingKey
	StatusAuthenticating
	StatusRecovering
	StatusPreparingArtifact
	StatusPublishing
	StatusConfirmingDurability
	StatusVerifyingLegacy
	StatusMigrating
)

// Status carries only a closed code and bounded numeric arguments.
type Status struct {
	code     StatusCode
	args     [maxResultArgs]uint64
	argCount uint8
}

func (status Status) Code() StatusCode { return status.code }

func (status Status) Args() []uint64 {
	if status.argCount == 0 {
		return nil
	}
	args := make([]uint64, status.argCount)
	copy(args, status.args[:status.argCount])
	return args
}

// Reporter is operation-owned after Run begins. Task 3 establishes ownership;
// later platform integration supplies the typed progress producers.
type Reporter func(Status) error

// ConsentRequest identifies one exact unverified operation and the complete
// closed set of physical roles that may be selected while its callback is
// live. No role is preselected or serializable in Request.
type ConsentRequest struct {
	mode      Mode
	roles     [2]PhysicalRole
	roleCount uint8
}

func (request ConsentRequest) Mode() Mode { return request.mode }

func (request ConsentRequest) AllowedRoles() []PhysicalRole {
	if request.roleCount == 0 || int(request.roleCount) > len(request.roles) {
		return nil
	}
	roles := make([]PhysicalRole, request.roleCount)
	copy(roles, request.roles[:request.roleCount])
	return roles
}

// ConsentAction selects one role from ConsentRequest. It is live only during
// its Consent callback and is one-shot, including an invalid selection.
type ConsentAction func(PhysicalRole) error

// Consent must invoke the supplied action synchronously or while the callback
// remains live. Returning without invocation is a refusal.
type Consent func(ConsentRequest, ConsentAction) error

var (
	ErrConsentExpired          = errors.New("pcv3 operation: consent expired")
	ErrConsentRole             = errors.New("pcv3 operation: consent role refused")
	errReporterCallback        = errors.New("pcv3 operation: reporter callback failed")
	errNativeOutputUnavailable = errors.New("pcv3 operation: native output unavailable")
)

// Request transfers its mutable factors, already-opened source, reporter, and
// consent callback to Run. Native callers must establish the source
// descriptor's no-follow provenance before transfer; a bare *os.File cannot
// re-prove it here. Request intentionally carries no resource authority,
// admission policy, factor identity, digest, snapshot callback, or writer
// capability.
type Request struct {
	Mode      Mode
	Source    *os.File
	Factors   *pcv3credential.FactorRequest
	Migration *MigrationRequest
	Target    string
	Protected []string
	Reporter  Reporter
	Consent   Consent
}

// ExecutionOptions selects internal output custody without expanding Request
// or its serializable frontend contract. The zero value preserves Run.
type ExecutionOptions struct {
	RetainDurableOutput bool
}

func (Request) String() string { return "pcv3operation.Request([REDACTED])" }

func (Request) GoString() string { return "pcv3operation.Request([REDACTED])" }

// operationSeams is the sole admission substitution point. It is unreachable
// outside this package; production binds the native platform implementation.
type operationSeams struct {
	admitter pcv3credential.Admitter
}

type reportingAdmitter struct {
	owner *operationOwner
	next  pcv3credential.Admitter
}

func (admitter reportingAdmitter) AdmitKDF(
	ctx context.Context,
	profile pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	if admitter.owner == nil || admitter.next == nil ||
		!admitter.owner.report(StatusCheckingResources) {
		return pcv3credential.KDFAdmissionDenied, errReporterCallback
	}
	decision, err := admitter.next.AdmitKDF(ctx, profile)
	if err != nil {
		admitter.owner.resourceDiagnostic = DiagnosticResourceUnknown
	} else {
		admitter.owner.resourceDiagnostic = resourceDiagnosticForAdmission(decision)
	}
	if err != nil || decision != pcv3credential.KDFAdmissionGranted {
		return decision, err
	}
	if !admitter.owner.report(StatusDerivingKey) {
		return pcv3credential.KDFAdmissionDenied, errReporterCallback
	}
	return decision, nil
}

func resourceDiagnosticForAdmission(admission pcv3credential.KDFAdmission) Diagnostic {
	switch admission {
	case pcv3credential.KDFAdmissionGranted:
		return DiagnosticNone
	case pcv3credential.KDFAdmissionDeniedInsufficient:
		return DiagnosticResourceInsufficient
	default:
		return DiagnosticResourceUnknown
	}
}

// Run takes ownership immediately and executes one explicit operation route.
func Run(ctx context.Context, request *Request) *Result {
	return RunWithOptions(ctx, request, ExecutionOptions{})
}

// RunWithOptions executes the same operation runner with an optional retained
// owner for a durably published non-archive output.
func RunWithOptions(
	ctx context.Context,
	request *Request,
	options ExecutionOptions,
) *Result {
	return runWithSeamsAndOptions(ctx, request, operationSeams{
		admitter: pcv3resource.NewPlatformAdmitter(),
	}, options)
}

func runWithSeams(
	ctx context.Context,
	request *Request,
	seams operationSeams,
) (result *Result) {
	return runWithSeamsAndOptions(ctx, request, seams, ExecutionOptions{})
}

func runWithSeamsAndOptions(
	ctx context.Context,
	request *Request,
	seams operationSeams,
	options ExecutionOptions,
) (result *Result) {
	owner := takeOperationRequest(request)
	defer func() {
		if recovered := recover(); recovered != nil {
			cleanupIncomplete := panicCleanupIncomplete(recovered)
			if cleanupOutputExact(result) {
				cleanupIncomplete = true
			}
			result = closedFailure(
				pcv3.OutcomeOperationFailed,
				pcv3.StageCredentialPolicy,
				pcv3.CodeOperationFailed,
				DiagnosticCallbackPanic,
			)
			if cleanupIncomplete {
				result.appendWarning(WarningCleanupIncomplete)
			}
		}
		if owner.close() {
			if result == nil {
				result = closedFailure(
					pcv3.OutcomeOperationFailed,
					pcv3.StageCredentialPolicy,
					pcv3.CodeOperationFailed,
					DiagnosticCoreFailure,
				)
			}
			result.appendWarning(WarningCleanupIncomplete)
		}
	}()

	if !validMode(owner.mode) {
		return closedFailure(
			pcv3.OutcomeUnsupportedRoutingPreKDF,
			pcv3.StageRouting,
			pcv3.CodeUnsupported,
			DiagnosticRoutingRefusal,
		)
	}
	if owner.mode == ModeMigrate {
		return runMigration(ctx, owner, seams, nil)
	}
	if ctx == nil || owner.source == nil || owner.factors == nil ||
		owner.target == "" || !owner.validProtected() || !owner.validRoleAndConsent() {
		return closedFailure(
			pcv3.OutcomeOperationFailed,
			pcv3.StageCredentialPolicy,
			pcv3.CodeOperationFailed,
			DiagnosticInvalidRequest,
		)
	}
	if ctx.Err() != nil {
		return closedFailure(
			pcv3.OutcomeOperationFailed,
			pcv3.StageCancellation,
			pcv3.CodeOperationFailed,
			DiagnosticCancellation,
		)
	}
	info, err := owner.source.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return closedFailure(
			pcv3.OutcomeOperationFailed,
			pcv3.StageInputIO,
			pcv3.CodeOperationFailed,
			DiagnosticCoreFailure,
		)
	}
	if !owner.report(StatusCheckingRequest) {
		return owner.reportFailure()
	}
	if !owner.report(StatusCheckingFactors) {
		return owner.reportFailure()
	}
	seams.admitter = reportingAdmitter{owner: owner, next: seams.admitter}

	switch owner.mode {
	case ModeReadNormal:
		return runNormalRead(ctx, owner, info.Size(), seams, options)
	case ModeReadD1, ModeRecoverD1:
		return runRecovery(ctx, owner, info.Size(), seams, options, true, pcv3.RecoveryModeNormalV3, nil)
	case ModeRecoverNormal:
		return runRecovery(ctx, owner, info.Size(), seams, options, false, pcv3.RecoveryModeNormalV3, nil)
	case ModeForceNormal:
		return runRecovery(ctx, owner, info.Size(), seams, options, false, pcv3.RecoveryModeForce, nil)
	case ModeForceD1:
		return runRecovery(ctx, owner, info.Size(), seams, options, true, pcv3.RecoveryModeForce, nil)
	case ModeForceUnverifiedNormal:
		return runUnverified(ctx, owner, info.Size(), seams, options, false)
	case ModeForceUnverifiedD1:
		return runUnverified(ctx, owner, info.Size(), seams, options, true)
	default:
		return closedFailure(
			pcv3.OutcomeUnsupportedRoutingPreKDF,
			pcv3.StageRouting,
			pcv3.CodeUnsupported,
			DiagnosticRoutingRefusal,
		)
	}
}

func validMode(mode Mode) bool {
	switch mode {
	case ModeReadNormal, ModeReadD1, ModeRecoverNormal, ModeRecoverD1,
		ModeForceNormal, ModeForceD1, ModeForceUnverifiedNormal,
		ModeForceUnverifiedD1, ModeMigrate:
		return true
	default:
		return false
	}
}

func runNormalRead(
	ctx context.Context,
	owner *operationOwner,
	sourceSize int64,
	seams operationSeams,
	options ExecutionOptions,
) (result *Result) {
	if !owner.report(StatusAuthenticating) {
		return owner.reportFailure()
	}
	request := &pcv3.NativeReadRequest{
		Source:     owner.source,
		SourceSize: sourceSize,
		Factors:    owner.takeFactors(),
		Admitter:   seams.admitter,
		Target:     owner.target,
		Protected:  owner.outputProtected(),
	}
	var archive *pcv3.NativeArchiveHandoff
	var retainedOutput *pcv3publication.RetainedFile
	defer func() {
		if recovered := recover(); recovered != nil {
			cleanupIncomplete := cleanupRetainedExact(&retainedOutput)
			if cleanupOutputExact(result) {
				cleanupIncomplete = true
			}
			if archive != nil && archive.Close() {
				cleanupIncomplete = true
			}
			if cleanupIncomplete {
				panic(pcv3publication.ErrCleanupIncomplete)
			}
			panic(recovered)
		}
	}()
	nativeResult := pcv3.RunNativeRead(
		ctx,
		request,
		func(output *pcv3.NativeReadOutput) error {
			switch output.Disposition() {
			case pcv3.NativePayloadPublish:
				if options.RetainDurableOutput {
					retainedOutput = output.PublishRetained(ctx)
					if retainedOutput == nil {
						return errNativeOutputUnavailable
					}
				} else if output.Publish(ctx) == nil {
					return errNativeOutputUnavailable
				}
			case pcv3.NativePayloadArchive:
				archive = output.Archive()
				if archive == nil {
					return errNativeOutputUnavailable
				}
			default:
				return errNativeOutputUnavailable
			}
			return nil
		},
	)
	result = owner.finishReportedResult(resultFromNativeRead(nativeResult))
	if owner.reporterFailed || owner.reporterPanicked {
		if cleanupRetainedExact(&retainedOutput) {
			result.appendWarning(WarningCleanupIncomplete)
		}
		if archive != nil && archive.Close() {
			result.appendWarning(WarningCleanupIncomplete)
		}
		return result
	}
	if retainedOutput != nil {
		followUp := newOutputFollowUp(retainedOutput)
		if followUp != nil && result.publicationAttempted &&
			result.publicationState == pcv3publication.StatePublishedDurable &&
			(result.outcome == pcv3.OutcomeSuccess ||
				result.outcome == pcv3.OutcomeAuthenticatedDegraded) && archive == nil {
			result.outputFollowUp = followUp
			retainedOutput = nil
			return result
		}
		if cleanupRetainedExact(&retainedOutput) {
			result.appendWarning(WarningCleanupIncomplete)
		}
		return result
	}
	if archive == nil {
		return result
	}
	followUp := newArchiveFollowUp(archive)
	if followUp != nil && result.outcome == pcv3.OutcomeSuccess &&
		result.stage == pcv3.StageNone && result.code == pcv3.CodeSuccess &&
		!result.publicationAttempted && result.warningCount == 0 {
		result.archiveFollowUp = followUp
		return result
	}
	if archive.Close() {
		result.appendWarning(WarningCleanupIncomplete)
	}
	return result
}

func runRecovery(
	ctx context.Context,
	owner *operationOwner,
	sourceSize int64,
	seams operationSeams,
	options ExecutionOptions,
	d1 bool,
	mode pcv3.RecoveryMode,
	d1Role *pcv3.D1BootstrapRole,
) *Result {
	if !owner.report(StatusRecovering) {
		return owner.reportFailure()
	}
	request := &pcv3recovery.Request{
		Source:     owner.source,
		SourceSize: sourceSize,
		Factors:    owner.takeFactors(),
		Admitter:   seams.admitter,
		Mode:       mode,
		Target:     owner.target,
		Protected:  owner.outputProtected(),
	}
	defer func() {
		if request.Factors != nil {
			_ = request.Factors.Close()
			request.Factors = nil
		}
	}()
	var recoveryResult *pcv3recovery.Result
	recoveryOptions := pcv3recovery.ExecutionOptions{
		RetainDurableOutput: options.RetainDurableOutput,
	}
	if d1Role != nil {
		recoveryResult = pcv3recovery.RunD1UnverifiedWithOptions(
			ctx, request, *d1Role, recoveryOptions,
		)
	} else if d1 {
		recoveryResult = pcv3recovery.RunD1WithOptions(ctx, request, recoveryOptions)
	} else {
		recoveryResult = pcv3recovery.RunWithOptions(ctx, request, recoveryOptions)
	}
	return owner.finishReportedResult(resultFromRecovery(recoveryResult))
}

type consentWindow struct {
	mu      sync.Mutex
	cond    *sync.Cond
	expired atomic.Bool
	used    bool
	running bool
	run     func(PhysicalRole) *Result
	result  *Result
}

func runUnverified(
	ctx context.Context,
	owner *operationOwner,
	sourceSize int64,
	seams operationSeams,
	options ExecutionOptions,
	d1 bool,
) *Result {
	window := &consentWindow{}
	window.cond = sync.NewCond(&window.mu)
	window.run = func(role PhysicalRole) *Result {
		if d1 {
			d1Role := d1Role(role)
			return runRecovery(
				ctx,
				owner,
				sourceSize,
				seams,
				options,
				true,
				pcv3.RecoveryModeForceUnverified,
				&d1Role,
			)
		}
		if !owner.report(StatusRecovering) {
			return owner.reportFailure()
		}
		request := &pcv3recovery.Request{
			Source:       owner.source,
			SourceSize:   sourceSize,
			Factors:      owner.takeFactors(),
			Admitter:     seams.admitter,
			Mode:         pcv3.RecoveryModeForceUnverified,
			SelectedRole: capsuleRole(role),
			Target:       owner.target,
			Protected:    owner.outputProtected(),
		}
		defer func() {
			if request.Factors != nil {
				_ = request.Factors.Close()
				request.Factors = nil
			}
		}()
		return owner.finishReportedResult(resultFromRecovery(pcv3recovery.RunWithOptions(
			ctx,
			request,
			pcv3recovery.ExecutionOptions{RetainDurableOutput: options.RetainDurableOutput},
		)))
	}
	consentRequest := consentRequestForMode(owner.mode)
	action := ConsentAction(func(role PhysicalRole) error {
		if window.expired.Load() {
			return ErrConsentExpired
		}
		window.mu.Lock()
		if window.expired.Load() || window.used || window.run == nil {
			window.mu.Unlock()
			return ErrConsentExpired
		}
		window.used = true
		run := window.run
		window.run = nil
		if !consentRequest.allows(role) {
			window.mu.Unlock()
			return ErrConsentRole
		}
		window.running = true
		window.mu.Unlock()

		result := runConsentOperation(func() *Result { return run(role) })
		window.mu.Lock()
		window.result = result
		window.running = false
		window.cond.Broadcast()
		window.mu.Unlock()
		return nil
	})

	var callbackErr error
	callbackPanicked := false
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				callbackPanicked = true
			}
		}()
		callbackErr = owner.consent(consentRequest, action)
	}()
	owner.consent = nil
	window.expired.Store(true)

	window.mu.Lock()
	window.run = nil
	for window.running {
		window.cond.Wait()
	}
	result := window.result
	window.result = nil
	window.mu.Unlock()
	if result != nil {
		if callbackErr != nil || callbackPanicked {
			result.appendWarning(WarningCallbackFailure)
			if callbackPanicked {
				result.diagnostic = DiagnosticCallbackPanic
			} else {
				result.diagnostic = DiagnosticCallbackFailure
			}
		}
		return result
	}
	if callbackPanicked {
		return closedFailure(
			pcv3.OutcomeOperationFailed,
			pcv3.StageCredentialPolicy,
			pcv3.CodeOperationFailed,
			DiagnosticCallbackPanic,
		)
	}
	if callbackErr != nil {
		return closedFailure(
			pcv3.OutcomeOperationFailed,
			pcv3.StageCredentialPolicy,
			pcv3.CodeOperationFailed,
			DiagnosticCallbackFailure,
		)
	}
	if ctx.Err() != nil {
		return closedFailure(
			pcv3.OutcomeOperationFailed,
			pcv3.StageCancellation,
			pcv3.CodeOperationFailed,
			DiagnosticCancellation,
		)
	}
	return closedFailure(
		pcv3.OutcomeOperationFailed,
		pcv3.StageCredentialPolicy,
		pcv3.CodeOperationFailed,
		DiagnosticCredentialPolicy,
	)
}

func consentRequestForMode(mode Mode) ConsentRequest {
	request := ConsentRequest{mode: mode, roleCount: 2}
	switch mode {
	case ModeForceUnverifiedNormal:
		request.roles = [2]PhysicalRole{RolePrimary, RoleBackup}
	case ModeForceUnverifiedD1:
		request.roles = [2]PhysicalRole{RoleD1Front, RoleD1Tail}
	default:
		return ConsentRequest{}
	}
	return request
}

func (request ConsentRequest) allows(role PhysicalRole) bool {
	if request.roleCount == 0 || int(request.roleCount) > len(request.roles) {
		return false
	}
	for _, allowed := range request.roles[:request.roleCount] {
		if role == allowed {
			return true
		}
	}
	return false
}

func runConsentOperation(run func() *Result) (result *Result) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = closedFailure(
				pcv3.OutcomeOperationFailed,
				pcv3.StageCredentialPolicy,
				pcv3.CodeOperationFailed,
				DiagnosticCallbackPanic,
			)
			if panicCleanupIncomplete(recovered) {
				result.appendWarning(WarningCleanupIncomplete)
			}
		}
	}()
	return run()
}

func panicCleanupIncomplete(recovered any) bool {
	err, ok := recovered.(error)
	return ok && errors.Is(err, pcv3publication.ErrCleanupIncomplete)
}

func capsuleRole(role PhysicalRole) pcv3.CapsuleRole {
	if role == RoleBackup {
		return pcv3.CapsuleRoleBackup
	}
	return pcv3.CapsuleRolePrimary
}

func d1Role(role PhysicalRole) pcv3.D1BootstrapRole {
	if role == RoleD1Tail {
		return pcv3.D1BootstrapTail
	}
	return pcv3.D1BootstrapFront
}

func resultFromNativeRead(native *pcv3.NativeReadResult) *Result {
	if native == nil {
		return closedFailure(
			pcv3.OutcomeOperationFailed,
			pcv3.StageCredentialPolicy,
			pcv3.CodeOperationFailed,
			DiagnosticCoreFailure,
		)
	}
	diagnostic := DiagnosticNone
	if native.CallbackFailed() {
		diagnostic = DiagnosticCallbackFailure
	}
	result := newResult(resultData{
		outcome:              native.Outcome(),
		stage:                native.Stage(),
		code:                 native.Code(),
		publicationAttempted: native.PublicationAttempted(),
		publicationState:     native.PublicationState(),
		publicationStage:     native.PublicationStage(),
		publicationCode:      native.PublicationCode(),
		diagnostic:           diagnostic,
	})
	if native.CleanupIncomplete() {
		result.appendWarning(WarningCleanupIncomplete)
	}
	if native.CallbackFailed() {
		result.appendWarning(WarningCallbackFailure)
	}
	return result
}

func resultFromRecovery(recovery *pcv3recovery.Result) (result *Result) {
	var retained *pcv3publication.RetainedFile
	defer func() {
		if recovered := recover(); recovered != nil {
			cleanupIncomplete := cleanupRetainedExact(&retained)
			if cleanupOutputExact(result) {
				cleanupIncomplete = true
			}
			if cleanupIncomplete {
				panic(pcv3publication.ErrCleanupIncomplete)
			}
			panic(recovered)
		}
	}()
	if recovery == nil {
		return closedFailure(
			pcv3.OutcomeOperationFailed,
			pcv3.StageCredentialPolicy,
			pcv3.CodeOperationFailed,
			DiagnosticCoreFailure,
		)
	}
	result = newResult(resultData{
		outcome:               recovery.Outcome(),
		stage:                 recovery.Stage(),
		code:                  recovery.Code(),
		forceProvenance:       recovery.ForceProvenance(),
		d1BootstrapProvenance: recovery.D1BootstrapProvenance(),
		detailStage:           recovery.DetailStage(),
		publicationAttempted:  recovery.PublicationAttempted(),
		publicationState:      recovery.PublicationState(),
		publicationStage:      recovery.PublicationStage(),
		publicationCode:       recovery.PublicationCode(),
	})
	if errors.Is(recovery, pcv3publication.ErrCleanupIncomplete) {
		result.appendWarning(WarningCleanupIncomplete)
	}
	result.artifactInspection = recovery.ArtifactInspection()
	retained = recovery.TakeRetainedOutput()
	if retained != nil {
		followUp := newOutputFollowUp(retained)
		if followUp == nil {
			cleanupIncomplete := cleanupRetainedExact(&retained)
			if cleanupIncomplete {
				result.appendWarning(WarningCleanupIncomplete)
			}
			return result
		}
		result.outputFollowUp = followUp
		retained = nil
		if result.OutputFollowUp() == nil {
			cleanupIncomplete := cleanupOutputExact(result)
			result.outputFollowUp = nil
			if cleanupIncomplete {
				result.appendWarning(WarningCleanupIncomplete)
			}
		}
	}
	return result
}

func closedFailure(
	outcome pcv3.Outcome,
	stage pcv3.Stage,
	code pcv3.Code,
	diagnostic Diagnostic,
) *Result {
	return newResult(resultData{
		outcome:    outcome,
		stage:      stage,
		code:       code,
		diagnostic: diagnostic,
	})
}

type operationOwner struct {
	mode               Mode
	source             *os.File
	factors            *pcv3credential.FactorRequest
	migration          *MigrationRequest
	target             string
	protected          []string
	reporter           Reporter
	consent            Consent
	reporterFailed     bool
	reporterPanicked   bool
	resourceDiagnostic Diagnostic
	closed             bool
}

func takeOperationRequest(request *Request) *operationOwner {
	owner := &operationOwner{}
	if request == nil {
		return owner
	}
	owner.mode = request.Mode
	owner.source = request.Source
	owner.factors = request.Factors
	owner.migration = request.Migration
	owner.target = request.Target
	owner.protected = append([]string(nil), request.Protected...)
	owner.reporter = request.Reporter
	owner.consent = request.Consent

	request.Mode = 0
	request.Source = nil
	request.Factors = nil
	request.Migration = nil
	request.Target = ""
	for index := range request.Protected {
		request.Protected[index] = ""
	}
	request.Protected = nil
	request.Reporter = nil
	request.Consent = nil
	return owner
}

func (owner *operationOwner) takeFactors() *pcv3credential.FactorRequest {
	if owner == nil {
		return nil
	}
	factors := owner.factors
	owner.factors = nil
	return factors
}

func (owner *operationOwner) validProtected() bool {
	if owner == nil {
		return false
	}
	for _, path := range owner.protected {
		if path == "" {
			return false
		}
	}
	return true
}

func (owner *operationOwner) validRoleAndConsent() bool {
	if owner == nil {
		return false
	}
	switch owner.mode {
	case ModeForceUnverifiedNormal:
		return owner.consent != nil
	case ModeForceUnverifiedD1:
		return owner.consent != nil
	default:
		return owner.consent == nil
	}
}

func (owner *operationOwner) outputProtected() []string {
	if owner == nil {
		return nil
	}
	protected := append([]string(nil), owner.protected...)
	if owner.source != nil && owner.source.Name() != "" {
		protected = append(protected, owner.source.Name())
	}
	return protected
}

func (owner *operationOwner) report(code StatusCode) (ok bool) {
	if owner == nil || owner.reporterFailed || owner.reporterPanicked {
		return false
	}
	if owner.reporter == nil {
		return true
	}
	reporter := owner.reporter
	var callbackErr error
	defer func() {
		if recovered := recover(); recovered != nil {
			owner.reporterPanicked = true
			owner.reporter = nil
			ok = false
		}
	}()
	callbackErr = reporter(Status{code: code})
	if callbackErr != nil {
		owner.reporterFailed = true
		owner.reporter = nil
		return false
	}
	return true
}

func (owner *operationOwner) reportFailure() *Result {
	diagnostic := DiagnosticCallbackFailure
	if owner != nil && owner.reporterPanicked {
		diagnostic = DiagnosticCallbackPanic
	}
	result := closedFailure(
		pcv3.OutcomeOperationFailed,
		pcv3.StageCredentialPolicy,
		pcv3.CodeOperationFailed,
		diagnostic,
	)
	result.appendWarning(WarningCallbackFailure)
	return result
}

func (owner *operationOwner) finishReportedResult(result *Result) *Result {
	if owner == nil {
		return result
	}
	if owner.reporterFailed || owner.reporterPanicked {
		failure := owner.reportFailure()
		if cleanupOutputExact(result) {
			failure.appendWarning(WarningCleanupIncomplete)
		}
		return failure
	}
	if result != nil && owner.resourceDiagnostic != DiagnosticNone &&
		result.outcome == pcv3.OutcomeOperationFailed &&
		result.stage == pcv3.StageCredentialPolicy && !result.publicationAttempted {
		result.diagnostic = owner.resourceDiagnostic
	}
	return result
}

func (owner *operationOwner) close() bool {
	if owner == nil || owner.closed {
		return false
	}
	owner.closed = true
	failed := safeCloseFactors(owner.factors)
	owner.factors = nil
	if owner.migration != nil && owner.migration.close() != nil {
		failed = true
	}
	owner.migration = nil
	if safeCloseSource(owner.source) {
		failed = true
	}
	owner.source = nil
	owner.reporter = nil
	owner.consent = nil
	owner.resourceDiagnostic = DiagnosticNone
	owner.mode = 0
	owner.target = ""
	for index := range owner.protected {
		owner.protected[index] = ""
	}
	owner.protected = nil
	return failed
}

func safeCloseFactors(factors *pcv3credential.FactorRequest) (failed bool) {
	if factors == nil {
		return false
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			failed = true
		}
	}()
	return factors.Close() != nil
}

func safeCloseSource(source *os.File) (failed bool) {
	if source == nil {
		return false
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			failed = true
		}
	}()
	return source.Close() != nil
}
