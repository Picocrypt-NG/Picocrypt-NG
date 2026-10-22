//go:build pcv3_production_kdf

package pcv3

import (
	"bytes"
	"context"
	"testing"
)

// Independent reference fixtures exercise the real credential/KDF boundary.
// Run serially with other 1-GiB KDF tests.
func TestMemoryIndependentProductionRead(t *testing.T) {
	for _, test := range []struct {
		fixture string
		mode    MemoryReadMode
	}{
		{"normal.pcv", MemoryReadNormal},
		{"d1-standard.pcv", MemoryReadD1},
		{"d1.pcv", MemoryReadD1},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			source := independentD1File(t, test.fixture)
			want := independentD1File(t, "plaintext.bin")
			admitter := &independentD1Admitter{}
			result, err := RunMemoryRead(context.Background(), &MemoryReadRequest{
				Source:  source,
				Factors: independentD1Factors(t, ""), Admitter: admitter, Mode: test.mode, MaxOutputBytes: uint64(len(want)),
			})
			if result == nil {
				t.Fatalf("no memory result: %v", err)
			}
			defer result.Close()
			if err != nil || result.Outcome() != OutcomeSuccess || !bytes.Equal(result.Bytes(), want) || admitter.calls != 1 {
				t.Fatalf("independent memory read: outcome=%v stage=%v KDF=%d error=%v", result.Outcome(), result.Stage(), admitter.calls, err)
			}
		})
	}
}

func TestMemoryIndependentD1ProductionWrite(t *testing.T) {
	for _, test := range []struct {
		fixture string
		suite   Suite
	}{{"d1-standard.pcv", SuiteStandard}, {"d1.pcv", SuiteParanoid}} {
		t.Run(test.fixture, func(t *testing.T) {
			want := independentD1File(t, test.fixture)
			data := independentD1File(t, "plaintext.bin")
			admitter := &independentD1Admitter{}
			entropy := independentD1Entropy(t, test.suite)
			output, err := runMemoryWrite(context.Background(), &MemoryWriteRequest{
				Suite:       test.suite,
				PayloadKind: PayloadKindRaw, Factors: independentD1Factors(t, ""), Admitter: admitter,
				Data: data, Deniability: true, MaxOutputBytes: uint64(len(want)),
			}, memoryD1WriteSeams{entropy: entropy})
			if err != nil || !bytes.Equal(output, want) || admitter.calls != 2 || entropy.Len() != 0 {
				t.Fatalf("independent D1 memory writer: bytes=%d KDF=%d remaining entropy=%d error=%v", len(output), admitter.calls, entropy.Len(), err)
			}
		})
	}
}

func TestMemoryIndependentProductionFinalDamageExposesNoPlaintext(t *testing.T) {
	source := independentD1File(t, "normal.pcv")
	// The final tag immediately precedes the frozen 1008-byte suffix. Literal
	// layout avoids deriving the test mutation with the production algorithm.
	source[len(source)-1008-1] ^= 0x80
	admitter := &independentD1Admitter{}
	result, err := RunMemoryRead(context.Background(), &MemoryReadRequest{
		Source:  source,
		Factors: independentD1Factors(t, ""), Admitter: admitter, Mode: MemoryReadNormal, MaxOutputBytes: uint64(len(source)),
	})
	if result == nil {
		t.Fatalf("missing failure result: %v", err)
	}
	defer result.Close()
	if err != nil || result.Outcome() != OutcomeAuthenticationFailed || result.Stage() != StageFinalRecord || len(result.Bytes()) != 0 || result.AuthenticatedComment() != "" || admitter.calls != 1 {
		t.Fatalf("damaged final record: outcome=%v stage=%v bytes=%d KDF=%d error=%v", result.Outcome(), result.Stage(), len(result.Bytes()), admitter.calls, err)
	}
}

func TestMemoryNormalRecoverPreservesAuthenticatedComment(t *testing.T) {
	const password = "browser Normal recovery password"
	const comment = "authenticated public recovery comment"
	plaintext := []byte("browser Normal recovery payload")
	admitter := &independentD1Admitter{}
	volume, err := RunMemoryWrite(context.Background(), &MemoryWriteRequest{
		Suite: SuiteParanoid, PayloadKind: PayloadKindRaw, Data: plaintext,
		Comment: []byte(comment), Factors: memoryPasswordFactors([]byte(password)),
		Admitter: admitter, MaxOutputBytes: 4096,
	})
	if err != nil || admitter.calls != 1 {
		t.Fatalf("commented Normal creation: KDF=%d error=%v", admitter.calls, err)
	}
	defer clear(volume)
	for _, test := range []struct {
		name    string
		mode    MemoryReadMode
		outcome Outcome
		comment string
	}{
		{"authenticated recovery", MemoryRecoverNormal, OutcomeSuccess, comment},
		{"Force withholds metadata", MemoryForceNormal, OutcomeAuthenticatedDegraded, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := admitter.calls
			result, err := RunMemoryRead(context.Background(), &MemoryReadRequest{
				Source: volume, Factors: memoryPasswordFactors([]byte(password)), Admitter: admitter,
				Mode: test.mode, MaxOutputBytes: uint64(len(plaintext)),
			})
			if result == nil {
				t.Fatalf("Normal recovery returned no result: %v", err)
			}
			defer result.Close()
			if err != nil || result.Outcome() != test.outcome || !bytes.Equal(result.Bytes(), plaintext) || admitter.calls != before+1 {
				t.Fatalf("Normal recovery: outcome=%v KDF=%d error=%v", result.Outcome(), admitter.calls-before, err)
			}
			if result.AuthenticatedComment() != test.comment {
				t.Fatalf("authenticated comment = %q, want %q", result.AuthenticatedComment(), test.comment)
			}
			ownedComment := result.comment
			result.Close()
			if !allZero(ownedComment) || result.AuthenticatedComment() != "" {
				t.Fatal("Close retained the owned authenticated comment")
			}
		})
	}
}
