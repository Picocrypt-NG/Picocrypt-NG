package pcv3_test

import (
	"Picocrypt-NG/internal/pcv3"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestPhase3Registry(t *testing.T) {
	stages := []struct {
		stage pcv3.Stage
		want  string
	}{
		{pcv3.StageRouting, "routing"},
		{pcv3.StagePreamble, "preamble"},
		{pcv3.StageCapsuleRS, "capsule-rs"},
		{pcv3.StageCapsuleStructure, "capsule-structure"},
		{pcv3.StageTailGeometry, "tail-geometry"},
		{pcv3.StageInputIO, "input-io"},
	}
	for _, test := range stages {
		if got := test.stage.String(); got != test.want {
			t.Errorf("stage string = %q; want %q", got, test.want)
		}
	}

	assertFailure := func(
		t *testing.T,
		err error,
		wantOutcome pcv3.Outcome,
		wantStage pcv3.Stage,
		wantCode pcv3.Code,
	) {
		t.Helper()
		var failure pcv3.Failure
		if !errors.As(err, &failure) {
			t.Fatalf("error type = %T; want pcv3.Failure", err)
		}
		if got := failure.Outcome(); got != wantOutcome {
			t.Errorf("outcome = %v; want %v", got, wantOutcome)
		}
		if got := failure.Stage(); got != wantStage {
			t.Errorf("stage = %v; want %v", got, wantStage)
		}
		if got := failure.Code(); got != wantCode {
			t.Errorf("code = %v; want %v", got, wantCode)
		}
	}

	assertFailure(
		t,
		pcv3.NewUnsupportedRoutingError(),
		pcv3.OutcomeUnsupportedRoutingPreKDF,
		pcv3.StageRouting,
		pcv3.CodeUnsupported,
	)

	for _, stage := range []pcv3.Stage{
		pcv3.StagePreamble,
		pcv3.StageCapsuleRS,
		pcv3.StageCapsuleStructure,
		pcv3.StageTailGeometry,
	} {
		assertFailure(
			t,
			pcv3.NewInvalidStructureError(stage),
			pcv3.OutcomeInvalidStructurePreKDF,
			stage,
			pcv3.CodeInvalidStructure,
		)
	}

	sourceCause := errors.New("source sentinel")
	inputErr := pcv3.NewInputError(sourceCause)
	assertFailure(
		t,
		inputErr,
		pcv3.OutcomeOperationFailed,
		pcv3.StageInputIO,
		pcv3.CodeOperationFailed,
	)
	if !errors.Is(inputErr, sourceCause) {
		t.Fatal("input failure did not preserve its source cause for errors.Is")
	}

	for _, stage := range []pcv3.Stage{
		0,
		pcv3.StageRouting,
		pcv3.StageInputIO,
		255,
	} {
		err := pcv3.NewInvalidStructureError(stage)
		if !errors.Is(err, pcv3.ErrInvalidFailureMapping) {
			t.Errorf("invalid structural stage %v returned %T; want mapping rejection", stage, err)
		}
		var failure pcv3.Failure
		if errors.As(err, &failure) {
			t.Errorf("invalid structural stage %v constructed a PCV3 failure", stage)
		}
	}

	for _, cause := range []error{
		io.EOF,
		io.ErrUnexpectedEOF,
		fmt.Errorf("wrapped EOF: %w", io.EOF),
	} {
		err := pcv3.NewInputError(cause)
		if !errors.Is(err, pcv3.ErrInvalidFailureMapping) {
			t.Errorf("EOF-like input cause %v was not rejected as a structural/operational mapping error", cause)
		}
	}

	if got := pcv3.OutcomeUnsupportedRoutingPreKDF.String(); got != "unsupported-routing-pre-kdf" {
		t.Errorf("unsupported outcome string = %q", got)
	}
	if got := pcv3.OutcomeInvalidStructurePreKDF.String(); got != "invalid-structure-pre-kdf" {
		t.Errorf("invalid-structure outcome string = %q", got)
	}
	if got := pcv3.OutcomeOperationFailed.String(); got != "operation-failed" {
		t.Errorf("operation-failed outcome string = %q", got)
	}
	if got := pcv3.CodeUnsupported.String(); got != "PCV3_UNSUPPORTED" {
		t.Errorf("unsupported code string = %q", got)
	}
	if got := pcv3.CodeInvalidStructure.String(); got != "PCV3_INVALID_STRUCTURE" {
		t.Errorf("invalid-structure code string = %q", got)
	}
	if got := pcv3.CodeOperationFailed.String(); got != "PCV3_OPERATION_FAILED" {
		t.Errorf("operation-failed code string = %q", got)
	}
}

func TestPCV3ErrorRedaction(t *testing.T) {
	canaries := []string{
		"/private/path/pcv3-canary",
		"bytes=50435600deadbeef",
		"offset=918273645",
		"length=564738291",
		"password=credential-canary",
		"keyfile=keyfile-canary",
		"plaintext=plaintext-canary",
	}
	cause := errors.New(strings.Join(canaries, " "))
	err := pcv3.NewInputError(cause)
	if !errors.Is(err, cause) {
		t.Fatal("redacted input error no longer preserves typed source inspection")
	}

	var failure pcv3.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T; want pcv3.Failure", err)
	}
	formatted := []string{
		err.Error(),
		failure.String(),
		failure.GoString(),
		fmt.Sprintf("%s", err),
		fmt.Sprintf("%q", err),
		fmt.Sprintf("%v", err),
		fmt.Sprintf("%+v", err),
		fmt.Sprintf("%#v", err),
		fmt.Sprintf("%x", err),
		fmt.Sprintf("%X", err),
		fmt.Sprintf("%d", err),
	}
	for _, output := range formatted {
		for _, canary := range canaries {
			if strings.Contains(output, canary) {
				t.Fatalf("formatted PCV3 error disclosed %q in %q", canary, output)
			}
		}
	}

	unknowns := []any{pcv3.Outcome(255), pcv3.Stage(255), pcv3.Code(255)}
	for _, unknown := range unknowns {
		for _, format := range []string{"%v", "%+v", "%#v", "%d", "%x"} {
			if got := fmt.Sprintf(format, unknown); strings.Contains(got, "255") || strings.Contains(got, "ff") {
				t.Errorf("unknown %T with %q exposed its numeric value: %q", unknown, format, got)
			}
		}
	}
}

func TestReaderUnavailableSentinel(t *testing.T) {
	wrapped := fmt.Errorf("native operation: %w", pcv3.ErrReaderUnavailable)
	if !errors.Is(wrapped, pcv3.ErrReaderUnavailable) {
		t.Fatal("reader-unavailable sentinel is not preserved through wrapping")
	}
	var typed pcv3.ReaderUnavailableError
	if !errors.As(wrapped, &typed) {
		t.Fatalf("wrapped sentinel type = %T; want pcv3.ReaderUnavailableError", wrapped)
	}
	if errors.Is(pcv3.NewUnsupportedRoutingError(), pcv3.ErrReaderUnavailable) {
		t.Fatal("unsupported routing was confused with a structurally admitted unavailable reader")
	}
	if got := fmt.Sprintf("%#v", pcv3.ErrReaderUnavailable); got != "pcv3: reader unavailable after structural admission" {
		t.Fatalf("reader-unavailable debug rendering = %q", got)
	}
}
