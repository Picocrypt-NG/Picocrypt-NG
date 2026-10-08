package pcv3credential

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3unicode"
	pcsecret "Picocrypt-NG/internal/secret"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func decodeTranscriptLiteral(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid literal hex fixture: %v", err)
	}
	return decoded
}

func requireTranscriptCode(
	t *testing.T,
	err error,
	want TranscriptErrorCode,
) *TranscriptError {
	t.Helper()
	var transcriptErr *TranscriptError
	if !errors.As(err, &transcriptErr) {
		t.Fatalf("error = %T %v; want *TranscriptError code %d", err, err, want)
	}
	if transcriptErr.Code != want {
		t.Fatalf(
			"transcript error code = %d; want %d (error %v)",
			transcriptErr.Code,
			want,
			err,
		)
	}
	return transcriptErr
}

func newRealTranscriptRequest(
	mode CredentialMode,
	keyfileMode KeyfileMode,
	policy FactorPolicy,
	password []byte,
	keyfiles ...[]byte,
) (*FactorRequest, []byte, []*trackedReadCloser) {
	passwordAlias := password
	readers := make([]*trackedReadCloser, len(keyfiles))
	ownedReaders := make([]*KeyfileReader, len(keyfiles))
	for i := range keyfiles {
		readers[i] = newChunkedReadCloser(keyfiles[i], 3)
		ownedReaders[i] = OwnKeyfileReader(readers[i])
	}
	return &FactorRequest{
		Mode:           mode,
		KeyfileMode:    keyfileMode,
		ExpectedPolicy: policy,
		Password:       password,
		Keyfiles:       ownedReaders,
	}, passwordAlias, readers
}

func requireRealInputsReleased(
	t *testing.T,
	request *FactorRequest,
	passwordAlias []byte,
	readers []*trackedReadCloser,
) {
	t.Helper()
	if !allZero(passwordAlias) {
		t.Fatal("transferred password backing was not cleared")
	}
	if request.Password != nil || request.Keyfiles != nil {
		t.Fatal("transferred request fields were not detached")
	}
	for i, reader := range readers {
		if reader.closeCalls != 1 {
			t.Fatalf("reader %d close calls = %d; want 1", i, reader.closeCalls)
		}
	}
}

func canonicalTranscriptFromRequest(
	request *FactorRequest,
) (*CanonicalTranscript, error) {
	var transcript *CanonicalTranscript
	err := WithValidatedFactors(
		context.Background(),
		request,
		func(factors *ValidatedFactors) error {
			var transcriptErr error
			transcript, transcriptErr = NewCanonicalTranscript(factors)
			return transcriptErr
		},
	)
	return transcript, err
}

func directTranscriptFactors(
	mode CredentialMode,
	keyfileMode KeyfileMode,
	policy FactorPolicy,
	password []byte,
	digests ...[]byte,
) *ValidatedFactors {
	factors := &ValidatedFactors{
		mode:           mode,
		keyfileMode:    keyfileMode,
		expectedPolicy: policy,
		password:       pcsecret.SecretFrom(password),
		descriptors:    make([]FactorDescriptor, len(digests)),
	}
	for i := range digests {
		if digests[i] != nil {
			factors.descriptors[i].digest = pcsecret.SecretFrom(digests[i])
		}
	}
	return factors
}

func closeDirectTranscriptFactors(factors *ValidatedFactors) {
	if factors == nil {
		return
	}
	if factors.password != nil {
		factors.password.Close()
		factors.password = nil
	}
	for i := range factors.descriptors {
		if factors.descriptors[i].digest != nil {
			factors.descriptors[i].digest.Close()
			factors.descriptors[i].digest = nil
		}
	}
	factors.descriptors = nil
}

func requireTranscriptLiteral(
	t *testing.T,
	transcript *CanonicalTranscript,
	wantHex string,
) {
	t.Helper()
	if transcript == nil || transcript.secret == nil {
		t.Fatal("canonical transcript was not published")
	}
	want := decodeTranscriptLiteral(t, wantHex)
	if !bytes.Equal(transcript.secret.Bytes(), want) {
		t.Fatalf(
			"canonical transcript = %x; want literal %x",
			transcript.secret.Bytes(),
			want,
		)
	}
}

func newPasswordNormalInput(t *testing.T) *CredentialInputNormal {
	t.Helper()
	request, passwordAlias, readers := newRealTranscriptRequest(
		CredentialModePasswordOnly,
		KeyfileModeNone,
		FactorPolicyPasswordOnly,
		[]byte("Cafe\u0301"),
	)
	var input *CredentialInputNormal
	err := WithValidatedFactors(
		context.Background(),
		request,
		func(factors *ValidatedFactors) error {
			transcript, transcriptErr := NewCanonicalTranscript(factors)
			if transcriptErr != nil {
				return transcriptErr
			}
			var inputErr error
			input, inputErr = NewCredentialInputNormal(transcript)
			return inputErr
		},
	)
	if err != nil {
		t.Fatalf("normal credential input setup failed: %v", err)
	}
	requireRealInputsReleased(t, request, passwordAlias, readers)
	if input == nil || input.secret == nil {
		t.Fatal("normal credential input setup published no owner")
	}
	return input
}

func TestCanonicalTranscriptLiteralKAT(t *testing.T) {
	tests := []struct {
		name        string
		mode        CredentialMode
		keyfileMode KeyfileMode
		policy      FactorPolicy
		password    []byte
		keyfiles    [][]byte
		wantHex     string
	}{
		{
			name:        "password only Unicode NFC",
			mode:        CredentialModePasswordOnly,
			keyfileMode: KeyfileModeNone,
			policy:      FactorPolicyPasswordOnly,
			password:    []byte("Cafe\u0301"),
			wantHex:     "0101000000000005436166c3a90000",
		},
		{
			name:        "keyfiles only ordered alpha beta",
			mode:        CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeOrdered,
			policy:      FactorPolicyKeyfilesOnly,
			keyfiles:    [][]byte{[]byte("alpha"), []byte("beta")},
			wantHex:     "0102010000000000000208fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e78655037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d5",
		},
		{
			name:        "keyfiles only unordered beta alpha",
			mode:        CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeUnordered,
			policy:      FactorPolicyKeyfilesOnly,
			keyfiles:    [][]byte{[]byte("beta"), []byte("alpha")},
			wantHex:     "0102020000000000000208fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e78655037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d5",
		},
		{
			name:        "combined ordered mix red blue",
			mode:        CredentialModePasswordAndKeyfiles,
			keyfileMode: KeyfileModeOrdered,
			policy:      FactorPolicyPasswordAndKeyfiles,
			password:    []byte("mix"),
			keyfiles:    [][]byte{[]byte("red"), []byte("blue")},
			wantHex:     "01030100000000036d697800026d6788bf3bb7ebee87c9c2503a97aacdd7912e8b4093d4c99f17843af69f2f549eb695bdf185f656ac1ee1f68647bbd6c2288ef9f8a5c5b9ef3fec6336b7e3e0",
		},
		{
			name:        "combined unordered mix blue red",
			mode:        CredentialModePasswordAndKeyfiles,
			keyfileMode: KeyfileModeUnordered,
			policy:      FactorPolicyPasswordAndKeyfiles,
			password:    []byte("mix"),
			keyfiles:    [][]byte{[]byte("blue"), []byte("red")},
			wantHex:     "01030200000000036d697800026d6788bf3bb7ebee87c9c2503a97aacdd7912e8b4093d4c99f17843af69f2f549eb695bdf185f656ac1ee1f68647bbd6c2288ef9f8a5c5b9ef3fec6336b7e3e0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, passwordAlias, readers := newRealTranscriptRequest(
				test.mode,
				test.keyfileMode,
				test.policy,
				test.password,
				test.keyfiles...,
			)
			transcript, err := canonicalTranscriptFromRequest(request)
			if err != nil {
				t.Fatalf("canonical transcript failed: %v", err)
			}
			requireRealInputsReleased(t, request, passwordAlias, readers)
			requireTranscriptLiteral(t, transcript, test.wantHex)
			transcript.Close()
		})
	}
}

func TestCanonicalTranscriptModeMatrix(t *testing.T) {
	valid := []struct {
		name        string
		mode        CredentialMode
		keyfileMode KeyfileMode
		policy      FactorPolicy
		password    []byte
		keyfiles    [][]byte
		wantHex     string
	}{
		{
			name: "password only", mode: CredentialModePasswordOnly,
			keyfileMode: KeyfileModeNone, policy: FactorPolicyPasswordOnly,
			password: []byte("p"),
			wantHex:  "0101000000000001700000",
		},
		{
			name: "keyfiles only ordered", mode: CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeOrdered, policy: FactorPolicyKeyfilesOnly,
			keyfiles: [][]byte{[]byte("alpha")},
			wantHex:  "0102010000000000000108fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e786",
		},
		{
			name: "keyfiles only unordered", mode: CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeUnordered, policy: FactorPolicyKeyfilesOnly,
			keyfiles: [][]byte{[]byte("alpha")},
			wantHex:  "0102020000000000000108fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e786",
		},
		{
			name: "combined ordered", mode: CredentialModePasswordAndKeyfiles,
			keyfileMode: KeyfileModeOrdered, policy: FactorPolicyPasswordAndKeyfiles,
			password: []byte("p"), keyfiles: [][]byte{[]byte("alpha")},
			wantHex: "010301000000000170000108fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e786",
		},
		{
			name: "combined unordered", mode: CredentialModePasswordAndKeyfiles,
			keyfileMode: KeyfileModeUnordered, policy: FactorPolicyPasswordAndKeyfiles,
			password: []byte("p"), keyfiles: [][]byte{[]byte("alpha")},
			wantHex: "010302000000000170000108fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e786",
		},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			request, passwordAlias, readers := newRealTranscriptRequest(
				test.mode,
				test.keyfileMode,
				test.policy,
				test.password,
				test.keyfiles...,
			)
			transcript, err := canonicalTranscriptFromRequest(request)
			if err != nil {
				t.Fatalf("valid mode failed: %v", err)
			}
			requireRealInputsReleased(t, request, passwordAlias, readers)
			requireTranscriptLiteral(t, transcript, test.wantHex)
			transcript.Close()
		})
	}

	validDigest := func() []byte {
		return bytes.Repeat([]byte{0x5a}, 32)
	}
	invalid := []struct {
		name    string
		factors func() *ValidatedFactors
	}{
		{name: "nil factors", factors: func() *ValidatedFactors { return nil }},
		{
			name: "unknown credential mode",
			factors: func() *ValidatedFactors {
				return directTranscriptFactors(
					0xff,
					KeyfileModeNone,
					FactorPolicyPasswordOnly,
					[]byte("p"),
				)
			},
		},
		{
			name: "unknown keyfile mode",
			factors: func() *ValidatedFactors {
				return directTranscriptFactors(
					CredentialModeKeyfilesOnly,
					0xff,
					FactorPolicyKeyfilesOnly,
					nil,
					validDigest(),
				)
			},
		},
		{
			name: "policy mismatch",
			factors: func() *ValidatedFactors {
				return directTranscriptFactors(
					CredentialModePasswordOnly,
					KeyfileModeNone,
					FactorPolicyKeyfilesOnly,
					[]byte("p"),
				)
			},
		},
		{
			name: "password only without password",
			factors: func() *ValidatedFactors {
				return directTranscriptFactors(
					CredentialModePasswordOnly,
					KeyfileModeNone,
					FactorPolicyPasswordOnly,
					nil,
				)
			},
		},
		{
			name: "keyfiles only with password",
			factors: func() *ValidatedFactors {
				return directTranscriptFactors(
					CredentialModeKeyfilesOnly,
					KeyfileModeOrdered,
					FactorPolicyKeyfilesOnly,
					[]byte("p"),
					validDigest(),
				)
			},
		},
		{
			name: "combined without descriptor",
			factors: func() *ValidatedFactors {
				return directTranscriptFactors(
					CredentialModePasswordAndKeyfiles,
					KeyfileModeOrdered,
					FactorPolicyPasswordAndKeyfiles,
					[]byte("p"),
				)
			},
		},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			factors := test.factors()
			defer closeDirectTranscriptFactors(factors)
			transcript, err := NewCanonicalTranscript(factors)
			requireTranscriptCode(t, err, TranscriptErrorInvalidFactors)
			if transcript != nil {
				transcript.Close()
				t.Fatal("invalid mode/policy/combination published a transcript")
			}
		})
	}
}

func TestCanonicalTranscriptOrdered(t *testing.T) {
	tests := []struct {
		name     string
		keyfiles [][]byte
		wantHex  string
	}{
		{
			name:     "alpha beta",
			keyfiles: [][]byte{[]byte("alpha"), []byte("beta")},
			wantHex:  "0102010000000000000208fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e78655037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d5",
		},
		{
			name:     "beta alpha",
			keyfiles: [][]byte{[]byte("beta"), []byte("alpha")},
			wantHex:  "0102010000000000000255037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d508fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e786",
		},
	}

	var transcripts [][]byte
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, passwordAlias, readers := newRealTranscriptRequest(
				CredentialModeKeyfilesOnly,
				KeyfileModeOrdered,
				FactorPolicyKeyfilesOnly,
				nil,
				test.keyfiles...,
			)
			transcript, err := canonicalTranscriptFromRequest(request)
			if err != nil {
				t.Fatalf("ordered transcript failed: %v", err)
			}
			requireRealInputsReleased(t, request, passwordAlias, readers)
			requireTranscriptLiteral(t, transcript, test.wantHex)
			transcripts = append(
				transcripts,
				append([]byte(nil), transcript.secret.Bytes()...),
			)
			transcript.Close()
		})
	}
	if len(transcripts) != 2 || bytes.Equal(transcripts[0], transcripts[1]) {
		t.Fatal("ordered descriptors did not retain caller order")
	}
}

func TestCanonicalTranscriptUnordered(t *testing.T) {
	const wantHex = "0102020000000000000208fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e78655037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d5"
	inputs := []struct {
		name     string
		keyfiles [][]byte
	}{
		{name: "alpha beta", keyfiles: [][]byte{[]byte("alpha"), []byte("beta")}},
		{name: "beta alpha", keyfiles: [][]byte{[]byte("beta"), []byte("alpha")}},
	}

	var transcripts [][]byte
	for _, input := range inputs {
		t.Run(input.name, func(t *testing.T) {
			request, passwordAlias, readers := newRealTranscriptRequest(
				CredentialModeKeyfilesOnly,
				KeyfileModeUnordered,
				FactorPolicyKeyfilesOnly,
				nil,
				input.keyfiles...,
			)
			transcript, err := canonicalTranscriptFromRequest(request)
			if err != nil {
				t.Fatalf("unordered transcript failed: %v", err)
			}
			requireRealInputsReleased(t, request, passwordAlias, readers)
			requireTranscriptLiteral(t, transcript, wantHex)
			transcripts = append(
				transcripts,
				append([]byte(nil), transcript.secret.Bytes()...),
			)
			transcript.Close()
		})
	}
	if len(transcripts) != 2 || !bytes.Equal(transcripts[0], transcripts[1]) {
		t.Fatal("unordered descriptors were not canonical across supplied order")
	}
}

func TestCanonicalTranscriptSelectedFactorRemoval(t *testing.T) {
	const (
		fullHex    = "01030100000000036d6978000308fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e78655037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d5b59960dbbd8dd7f2792bba84d97bc1ed8f810e326a3dcfa6026a3b913ced9af2"
		removedHex = "01030100000000036d6978000208fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e786b59960dbbd8dd7f2792bba84d97bc1ed8f810e326a3dcfa6026a3b913ced9af2"
	)
	request, passwordAlias, readers := newRealTranscriptRequest(
		CredentialModePasswordAndKeyfiles,
		KeyfileModeOrdered,
		FactorPolicyPasswordAndKeyfiles,
		[]byte("mix"),
		[]byte("alpha"),
		[]byte("beta"),
		[]byte("gamma"),
	)
	transcript, err := canonicalTranscriptFromRequest(request)
	if err != nil {
		t.Fatalf("selected_factor_missing: full factor transcript failed: %v", err)
	}
	requireRealInputsReleased(t, request, passwordAlias, readers)
	if transcript == nil || transcript.secret == nil {
		t.Fatal("selected_factor_missing: full factor transcript was not published")
	}
	defer transcript.Close()
	full := decodeTranscriptLiteral(t, fullHex)
	removed := decodeTranscriptLiteral(t, removedHex)
	if bytes.Equal(transcript.secret.Bytes(), removed) {
		t.Fatal("selected_factor_missing: middle selected descriptor was omitted")
	}
	if !bytes.Equal(transcript.secret.Bytes(), full) {
		t.Fatalf(
			"selected_factor_missing: full transcript = %x; want %x",
			transcript.secret.Bytes(),
			full,
		)
	}
	transcript.Close()

	removedRequest, removedPasswordAlias, removedReaders := newRealTranscriptRequest(
		CredentialModePasswordAndKeyfiles,
		KeyfileModeOrdered,
		FactorPolicyPasswordAndKeyfiles,
		[]byte("mix"),
		[]byte("alpha"),
		[]byte("gamma"),
	)
	removedTranscript, err := canonicalTranscriptFromRequest(removedRequest)
	if err != nil {
		t.Fatalf("selected_factor_missing: removed-factor control failed: %v", err)
	}
	requireRealInputsReleased(
		t,
		removedRequest,
		removedPasswordAlias,
		removedReaders,
	)
	if removedTranscript == nil || removedTranscript.secret == nil {
		t.Fatal("selected_factor_missing: removed-factor control was not published")
	}
	defer removedTranscript.Close()
	if !bytes.Equal(removedTranscript.secret.Bytes(), removed) {
		t.Fatalf(
			"selected_factor_missing: removed-factor control = %x; want %x",
			removedTranscript.secret.Bytes(),
			removed,
		)
	}
	removedTranscript.Close()
}

func TestCanonicalTranscriptKeyfileModeOffset2Mutation(t *testing.T) {
	const (
		wantHex  = "01030200000000036d697800026d6788bf3bb7ebee87c9c2503a97aacdd7912e8b4093d4c99f17843af69f2f549eb695bdf185f656ac1ee1f68647bbd6c2288ef9f8a5c5b9ef3fec6336b7e3e0"
		wrongHex = "01030100000000036d697800026d6788bf3bb7ebee87c9c2503a97aacdd7912e8b4093d4c99f17843af69f2f549eb695bdf185f656ac1ee1f68647bbd6c2288ef9f8a5c5b9ef3fec6336b7e3e0"
	)
	request, passwordAlias, readers := newRealTranscriptRequest(
		CredentialModePasswordAndKeyfiles,
		KeyfileModeUnordered,
		FactorPolicyPasswordAndKeyfiles,
		[]byte("mix"),
		[]byte("blue"),
		[]byte("red"),
	)
	transcript, err := canonicalTranscriptFromRequest(request)
	if err != nil {
		t.Fatalf("keyfile_mode_offset_2_mismatch: transcript failed: %v", err)
	}
	requireRealInputsReleased(t, request, passwordAlias, readers)
	if transcript == nil || transcript.secret == nil {
		t.Fatal("keyfile_mode_offset_2_mismatch: transcript was not published")
	}
	defer transcript.Close()
	got := transcript.secret.Bytes()
	want := decodeTranscriptLiteral(t, wantHex)
	wrong := decodeTranscriptLiteral(t, wrongHex)
	if len(got) <= 2 || got[2] != 0x02 || bytes.Equal(got, wrong) ||
		!bytes.Equal(got, want) {
		t.Fatalf(
			"keyfile_mode_offset_2_mismatch: transcript = %x; want %x",
			got,
			want,
		)
	}
	transcript.Close()
}

func TestCanonicalTranscriptUnorderedSortMutation(t *testing.T) {
	const (
		wantHex  = "0102020000000000000208fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e78655037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d5"
		wrongHex = "0102020000000000000255037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d508fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e786"
	)
	request, passwordAlias, readers := newRealTranscriptRequest(
		CredentialModeKeyfilesOnly,
		KeyfileModeUnordered,
		FactorPolicyKeyfilesOnly,
		nil,
		[]byte("beta"),
		[]byte("alpha"),
	)
	transcript, err := canonicalTranscriptFromRequest(request)
	if err != nil {
		t.Fatalf("unordered_digest_order_noncanonical: transcript failed: %v", err)
	}
	requireRealInputsReleased(t, request, passwordAlias, readers)
	if transcript == nil || transcript.secret == nil {
		t.Fatal("unordered_digest_order_noncanonical: transcript was not published")
	}
	defer transcript.Close()
	got := transcript.secret.Bytes()
	want := decodeTranscriptLiteral(t, wantHex)
	wrong := decodeTranscriptLiteral(t, wrongHex)
	if bytes.Equal(got, wrong) || !bytes.Equal(got, want) {
		t.Fatalf(
			"unordered_digest_order_noncanonical: transcript = %x; want %x",
			got,
			want,
		)
	}
	transcript.Close()
}

func TestCanonicalTranscriptUnicodeOnce(t *testing.T) {
	t.Run("password is canonicalized once and temporary is cleared", func(t *testing.T) {
		request, passwordAlias, readers := newRealTranscriptRequest(
			CredentialModePasswordOnly,
			KeyfileModeNone,
			FactorPolicyPasswordOnly,
			[]byte("Cafe\u0301"),
		)
		calls := 0
		var canonicalInputAlias []byte
		var canonicalTemporary []byte
		var transcript *CanonicalTranscript
		err := WithValidatedFactors(
			context.Background(),
			request,
			func(factors *ValidatedFactors) error {
				factorBorrow := factors.password.Bytes()
				var transcriptErr error
				transcript, transcriptErr = newCanonicalTranscript(
					factors,
					func(input []byte) ([]byte, error) {
						calls++
						canonicalInputAlias = input
						if !bytes.Equal(input, []byte("Cafe\u0301")) {
							t.Fatalf("canonicalizer input = %x; want decomposed password", input)
						}
						if len(input) > 0 && len(factorBorrow) > 0 &&
							&input[0] == &factorBorrow[0] {
							t.Fatal("canonicalizer received the borrowed factor backing")
						}
						// A deliberately decomposed seam result makes a second,
						// hidden normalization call observable.
						canonicalTemporary = []byte("A\u030A")
						return canonicalTemporary, nil
					},
				)
				if transcriptErr != nil {
					return transcriptErr
				}
				if calls != 1 {
					t.Fatalf("canonicalizer calls = %d; want exactly 1", calls)
				}
				if len(canonicalInputAlias) == 0 ||
					!allZero(canonicalInputAlias) ||
					len(canonicalTemporary) == 0 ||
					!allZero(canonicalTemporary) {
					t.Fatal("canonicalizer input/output temporaries were not cleared")
				}
				if !bytes.Equal(factorBorrow, []byte("Cafe\u0301")) {
					t.Fatal("canonicalization modified the borrowed factor password")
				}
				requireTranscriptLiteral(
					t,
					transcript,
					"010100000000000341cc8a0000",
				)
				return nil
			},
		)
		if err != nil {
			t.Fatalf("canonical transcript failed: %v", err)
		}
		requireRealInputsReleased(t, request, passwordAlias, readers)
		if calls != 1 ||
			!allZero(canonicalInputAlias) ||
			!allZero(canonicalTemporary) {
			t.Fatal("password canonicalization count/cleanup changed after callback")
		}
		transcript.Close()
	})

	t.Run("canonicalizer error clears temporary and remains redacted", func(t *testing.T) {
		factors := directTranscriptFactors(
			CredentialModePasswordOnly,
			KeyfileModeNone,
			FactorPolicyPasswordOnly,
			[]byte("password"),
		)
		defer closeDirectTranscriptFactors(factors)

		const errorSentinel = "canonicalizer-sensitive-detail"
		canonicalizerErr := errors.New(errorSentinel)
		calls := 0
		var canonicalInputAlias []byte
		var canonicalTemporary []byte
		transcript, err := newCanonicalTranscript(
			factors,
			func(input []byte) ([]byte, error) {
				calls++
				canonicalInputAlias = input
				canonicalTemporary = []byte("canonical-sensitive-temporary")
				return canonicalTemporary, canonicalizerErr
			},
		)
		transcriptErr := requireTranscriptCode(
			t,
			err,
			TranscriptErrorPasswordCanonicalization,
		)
		if transcript != nil {
			transcript.Close()
			t.Fatal("canonicalizer failure published a transcript")
		}
		if calls != 1 ||
			len(canonicalInputAlias) == 0 ||
			!allZero(canonicalInputAlias) ||
			len(canonicalTemporary) == 0 ||
			!allZero(canonicalTemporary) {
			t.Fatal("canonicalizer failure did not clear its input/output temporaries")
		}
		if transcriptErr.Reason != 0 ||
			errors.Is(err, canonicalizerErr) ||
			strings.Contains(err.Error(), errorSentinel) {
			t.Fatal("canonicalizer failure exposed its private error detail")
		}
	})

	t.Run("already-NFC factor borrow survives repeated serialization", func(t *testing.T) {
		request, passwordAlias, readers := newRealTranscriptRequest(
			CredentialModePasswordOnly,
			KeyfileModeNone,
			FactorPolicyPasswordOnly,
			[]byte("Café"),
		)
		err := WithValidatedFactors(
			context.Background(),
			request,
			func(factors *ValidatedFactors) error {
				factorBorrow := factors.password.Bytes()
				first, firstErr := NewCanonicalTranscript(factors)
				if firstErr != nil {
					return firstErr
				}
				defer first.Close()
				second, secondErr := NewCanonicalTranscript(factors)
				if secondErr != nil {
					return secondErr
				}
				defer second.Close()

				const wantHex = "0101000000000005436166c3a90000"
				requireTranscriptLiteral(t, first, wantHex)
				requireTranscriptLiteral(t, second, wantHex)
				if !bytes.Equal(first.secret.Bytes(), second.secret.Bytes()) ||
					!bytes.Equal(factorBorrow, []byte("Café")) {
					t.Fatal("serialization mutated the already-NFC factor borrow")
				}
				return nil
			},
		)
		if err != nil {
			t.Fatalf("repeated serialization failed: %v", err)
		}
		requireRealInputsReleased(t, request, passwordAlias, readers)
	})

	t.Run("keyfiles only does not call password canonicalizer", func(t *testing.T) {
		request, passwordAlias, readers := newRealTranscriptRequest(
			CredentialModeKeyfilesOnly,
			KeyfileModeOrdered,
			FactorPolicyKeyfilesOnly,
			nil,
			[]byte("alpha"),
		)
		calls := 0
		var transcript *CanonicalTranscript
		err := WithValidatedFactors(
			context.Background(),
			request,
			func(factors *ValidatedFactors) error {
				var transcriptErr error
				transcript, transcriptErr = newCanonicalTranscript(
					factors,
					func(input []byte) ([]byte, error) {
						calls++
						return pcv3unicode.Canonicalize(input)
					},
				)
				return transcriptErr
			},
		)
		if err != nil {
			t.Fatalf("keyfiles-only transcript failed: %v", err)
		}
		requireRealInputsReleased(t, request, passwordAlias, readers)
		if calls != 0 {
			t.Fatalf("keyfiles-only canonicalizer calls = %d; want 0", calls)
		}
		if transcript == nil || transcript.secret == nil {
			t.Fatal("keyfiles-only path published no transcript")
		}
		transcript.Close()
	})
}

func requireCanonicalTranscriptRawNFDFallbackRejected(t *testing.T) {
	t.Helper()
	const (
		wantHex      = "0101000000000005436166c3a90000"
		forbiddenHex = "010100000000000643616665cc810000"
	)
	request, passwordAlias, readers := newRealTranscriptRequest(
		CredentialModePasswordOnly,
		KeyfileModeNone,
		FactorPolicyPasswordOnly,
		[]byte("Cafe\u0301"),
	)
	transcript, err := canonicalTranscriptFromRequest(request)
	if err != nil {
		t.Fatalf("canonical password transcript failed: %v", err)
	}
	requireRealInputsReleased(t, request, passwordAlias, readers)
	got := transcript.secret.Bytes()
	want := decodeTranscriptLiteral(t, wantHex)
	forbidden := decodeTranscriptLiteral(t, forbiddenHex)
	if bytes.Equal(got, forbidden) || !bytes.Equal(got, want) {
		transcript.Close()
		t.Fatalf("raw/decomposed legacy transcript became reachable: %x", got)
	}
	transcript.Close()
}

func requireCanonicalTranscriptXORFallbackRejected(t *testing.T) {
	t.Helper()
	const (
		wantHex      = "0102010000000000000208fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e78655037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d5"
		forbiddenHex = "010201000000000000015dfe8b4d0ea1b01692b0c24d547a4e059a1b402d0bc7d349b9f9d680bf420753"
	)
	request, passwordAlias, readers := newRealTranscriptRequest(
		CredentialModeKeyfilesOnly,
		KeyfileModeOrdered,
		FactorPolicyKeyfilesOnly,
		nil,
		[]byte("alpha"),
		[]byte("beta"),
	)
	transcript, err := canonicalTranscriptFromRequest(request)
	if err != nil {
		t.Fatalf("canonical keyfile transcript failed: %v", err)
	}
	requireRealInputsReleased(t, request, passwordAlias, readers)
	got := transcript.secret.Bytes()
	want := decodeTranscriptLiteral(t, wantHex)
	forbidden := decodeTranscriptLiteral(t, forbiddenHex)
	if bytes.Equal(got, forbidden) || !bytes.Equal(got, want) {
		transcript.Close()
		t.Fatalf("legacy XOR transcript became reachable: %x", got)
	}
	transcript.Close()
}

func TestCanonicalTranscriptRejectsLegacyAlternatives(t *testing.T) {
	t.Run("decomposed raw password transcript is unreachable", func(t *testing.T) {
		requireCanonicalTranscriptRawNFDFallbackRejected(t)
	})

	t.Run("legacy XOR keyfile transcript is unreachable", func(t *testing.T) {
		requireCanonicalTranscriptXORFallbackRejected(t)
	})

	t.Run("invalid UTF-8 has no raw fallback", func(t *testing.T) {
		request, passwordAlias, readers := newRealTranscriptRequest(
			CredentialModePasswordOnly,
			KeyfileModeNone,
			FactorPolicyPasswordOnly,
			[]byte{0xff},
		)
		transcript, err := canonicalTranscriptFromRequest(request)
		transcriptErr := requireTranscriptCode(
			t,
			err,
			TranscriptErrorPasswordCanonicalization,
		)
		if transcriptErr.Reason != pcv3unicode.RejectionInvalidUTF8 {
			t.Fatalf(
				"canonicalization rejection = %d; want invalid UTF-8",
				transcriptErr.Reason,
			)
		}
		if transcript != nil {
			transcript.Close()
			t.Fatal("invalid UTF-8 published a fallback transcript")
		}
		requireRealInputsReleased(t, request, passwordAlias, readers)
	})
}

func TestCanonicalTranscriptRawNFDFallbackMutation(t *testing.T) {
	requireCanonicalTranscriptRawNFDFallbackRejected(t)
}

func TestCanonicalTranscriptXORFallbackMutation(t *testing.T) {
	requireCanonicalTranscriptXORFallbackRejected(t)
}

func TestCanonicalTranscriptBounds(t *testing.T) {
	t.Run("exact 1 MiB password succeeds", func(t *testing.T) {
		password := bytes.Repeat([]byte{'a'}, 1<<20)
		request, passwordAlias, readers := newRealTranscriptRequest(
			CredentialModePasswordOnly,
			KeyfileModeNone,
			FactorPolicyPasswordOnly,
			password,
		)
		transcript, err := canonicalTranscriptFromRequest(request)
		if err != nil {
			t.Fatalf("exact password bound failed: %v", err)
		}
		requireRealInputsReleased(t, request, passwordAlias, readers)
		got := transcript.secret.Bytes()
		if len(got) != (1<<20)+10 {
			transcript.Close()
			t.Fatalf("transcript length = %d; want %d", len(got), (1<<20)+10)
		}
		if !bytes.Equal(got[:8], decodeTranscriptLiteral(t, "0101000000100000")) ||
			!bytes.Equal(got[len(got)-2:], []byte{0x00, 0x00}) {
			transcript.Close()
			t.Fatal("exact-bound transcript framing is not canonical")
		}
		for i, b := range got[8 : len(got)-2] {
			if b != 'a' {
				transcript.Close()
				t.Fatalf("exact-bound password byte %d = %02x; want 61", i, b)
			}
		}
		transcript.Close()
	})

	t.Run("1 MiB plus 1 raw password is rejected", func(t *testing.T) {
		factors := directTranscriptFactors(
			CredentialModePasswordOnly,
			KeyfileModeNone,
			FactorPolicyPasswordOnly,
			bytes.Repeat([]byte{'a'}, (1<<20)+1),
		)
		defer closeDirectTranscriptFactors(factors)
		transcript, err := NewCanonicalTranscript(factors)
		requireTranscriptCode(t, err, TranscriptErrorLength)
		if transcript != nil {
			transcript.Close()
			t.Fatal("oversized raw password published a transcript")
		}
	})

	t.Run("1 MiB plus 1 canonical output is rejected and cleared", func(t *testing.T) {
		factors := directTranscriptFactors(
			CredentialModePasswordOnly,
			KeyfileModeNone,
			FactorPolicyPasswordOnly,
			[]byte("p"),
		)
		defer closeDirectTranscriptFactors(factors)
		var oversized []byte
		transcript, err := newCanonicalTranscript(
			factors,
			func([]byte) ([]byte, error) {
				oversized = bytes.Repeat([]byte{'a'}, (1<<20)+1)
				return oversized, nil
			},
		)
		requireTranscriptCode(t, err, TranscriptErrorLength)
		if transcript != nil {
			transcript.Close()
			t.Fatal("oversized canonical password published a transcript")
		}
		if len(oversized) == 0 || !allZero(oversized) {
			t.Fatal("oversized canonicalizer temporary was not cleared")
		}
	})

	t.Run("exactly 64 descriptors succeed", func(t *testing.T) {
		digests := make([][]byte, 64)
		for i := range digests {
			digests[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
		}
		factors := directTranscriptFactors(
			CredentialModeKeyfilesOnly,
			KeyfileModeOrdered,
			FactorPolicyKeyfilesOnly,
			nil,
			digests...,
		)
		defer closeDirectTranscriptFactors(factors)
		transcript, err := NewCanonicalTranscript(factors)
		if err != nil {
			t.Fatalf("64 descriptors failed: %v", err)
		}
		got := transcript.secret.Bytes()
		if len(got) != 10+(64*32) ||
			!bytes.Equal(got[:10], decodeTranscriptLiteral(t, "01020100000000000040")) {
			transcript.Close()
			t.Fatal("64-descriptor boundary framing/content is wrong")
		}
		for i := range 64 {
			for j, b := range got[10+(i*32) : 10+((i+1)*32)] {
				if b != byte(i+1) {
					transcript.Close()
					t.Fatalf(
						"descriptor %d byte %d = %02x; want %02x",
						i,
						j,
						b,
						byte(i+1),
					)
				}
			}
		}
		transcript.Close()
	})

	t.Run("65 descriptors are rejected", func(t *testing.T) {
		digests := make([][]byte, 65)
		for i := range digests {
			digests[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
		}
		factors := directTranscriptFactors(
			CredentialModeKeyfilesOnly,
			KeyfileModeOrdered,
			FactorPolicyKeyfilesOnly,
			nil,
			digests...,
		)
		defer closeDirectTranscriptFactors(factors)
		transcript, err := NewCanonicalTranscript(factors)
		requireTranscriptCode(t, err, TranscriptErrorInvalidFactors)
		if transcript != nil {
			transcript.Close()
			t.Fatal("65 descriptors published a transcript")
		}
	})

	invalidDigests := []struct {
		name    string
		digests func() [][]byte
	}{
		{
			name: "nil digest",
			digests: func() [][]byte {
				return [][]byte{nil}
			},
		},
		{
			name: "31-byte digest",
			digests: func() [][]byte {
				return [][]byte{bytes.Repeat([]byte{0x31}, 31)}
			},
		},
		{
			name: "33-byte digest",
			digests: func() [][]byte {
				return [][]byte{bytes.Repeat([]byte{0x33}, 33)}
			},
		},
		{
			name: "non-adjacent duplicate digest",
			digests: func() [][]byte {
				return [][]byte{
					bytes.Repeat([]byte{0x44}, 32),
					bytes.Repeat([]byte{0x45}, 32),
					bytes.Repeat([]byte{0x44}, 32),
				}
			},
		},
	}
	for _, test := range invalidDigests {
		t.Run(test.name, func(t *testing.T) {
			factors := directTranscriptFactors(
				CredentialModeKeyfilesOnly,
				KeyfileModeOrdered,
				FactorPolicyKeyfilesOnly,
				nil,
				test.digests()...,
			)
			defer closeDirectTranscriptFactors(factors)
			transcript, err := NewCanonicalTranscript(factors)
			requireTranscriptCode(t, err, TranscriptErrorInvalidFactors)
			if transcript != nil {
				transcript.Close()
				t.Fatal("nil/wrong-width digest published a transcript")
			}
		})
	}
}

func TestCanonicalTranscriptZeroKDFOnReject(t *testing.T) {
	tests := []struct {
		name        string
		mode        CredentialMode
		keyfileMode KeyfileMode
		policy      FactorPolicy
		password    []byte
		keyfiles    [][]byte
		wantCode    FactorErrorCode
		wantKDF     int
	}{
		{
			name: "positive control", mode: CredentialModePasswordOnly,
			keyfileMode: KeyfileModeNone, policy: FactorPolicyPasswordOnly,
			password: []byte("valid"), wantKDF: 1,
		},
		{
			name: "invalid mode", mode: 0xff,
			keyfileMode: KeyfileModeNone, policy: FactorPolicyPasswordOnly,
			password: []byte("invalid"), wantCode: FactorErrorInvalidMode,
		},
		{
			name: "invalid count", mode: CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeOrdered, policy: FactorPolicyKeyfilesOnly,
			wantCode: FactorErrorInvalidCombination,
		},
		{
			name: "invalid ordering mode", mode: CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeNone, policy: FactorPolicyKeyfilesOnly,
			keyfiles: [][]byte{[]byte("alpha")},
			wantCode: FactorErrorInvalidCombination,
		},
		{
			name: "duplicate digest", mode: CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeOrdered, policy: FactorPolicyKeyfilesOnly,
			keyfiles: [][]byte{[]byte("alpha"), []byte("alpha")},
			wantCode: FactorErrorDuplicate,
		},
		{
			name: "policy mismatch", mode: CredentialModePasswordAndKeyfiles,
			keyfileMode: KeyfileModeOrdered, policy: FactorPolicyPasswordOnly,
			password: []byte("password"), keyfiles: [][]byte{[]byte("alpha")},
			wantCode: FactorErrorPolicyMismatch,
		},
		{
			name: "oversized password", mode: CredentialModePasswordOnly,
			keyfileMode: KeyfileModeNone, policy: FactorPolicyPasswordOnly,
			password: bytes.Repeat([]byte{'a'}, (1<<20)+1),
			wantCode: FactorErrorPasswordLength,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, passwordAlias, readers := newRealTranscriptRequest(
				test.mode,
				test.keyfileMode,
				test.policy,
				test.password,
				test.keyfiles...,
			)
			kdfCalls := 0
			transcriptPublications := 0
			err := WithValidatedFactors(
				context.Background(),
				request,
				func(factors *ValidatedFactors) error {
					transcript, transcriptErr := NewCanonicalTranscript(factors)
					if transcriptErr != nil {
						return transcriptErr
					}
					transcriptPublications++
					input, inputErr := NewCredentialInputNormal(transcript)
					if inputErr != nil {
						return inputErr
					}
					return input.consume(func(borrow []byte) error {
						kdfCalls++
						if len(borrow) != 64 {
							return errors.New("KDF seam received a non-64-byte input")
						}
						return nil
					})
				},
			)
			requireRealInputsReleased(t, request, passwordAlias, readers)
			if test.wantCode != 0 {
				requireFactorCode(t, err, test.wantCode)
				if kdfCalls != 0 || transcriptPublications != 0 {
					t.Fatalf(
						"rejected factors reached transcript/KDF %d/%d times; want 0/0",
						transcriptPublications,
						kdfCalls,
					)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid positive control failed: %v", err)
			}
			if transcriptPublications != 1 || kdfCalls != test.wantKDF {
				t.Fatalf(
					"positive transcript/KDF calls = %d/%d; want 1/%d",
					transcriptPublications,
					kdfCalls,
					test.wantKDF,
				)
			}
		})
	}
}

func TestCanonicalTranscriptClose(t *testing.T) {
	request, passwordAlias, readers := newRealTranscriptRequest(
		CredentialModePasswordOnly,
		KeyfileModeNone,
		FactorPolicyPasswordOnly,
		[]byte("Cafe\u0301"),
	)
	transcript, err := canonicalTranscriptFromRequest(request)
	if err != nil {
		t.Fatalf("canonical transcript failed: %v", err)
	}
	requireRealInputsReleased(t, request, passwordAlias, readers)
	if transcript.secret == nil || transcript.secret.Len() == 0 {
		t.Fatal("canonical transcript owner was already closed")
	}
	ownerHandle := transcript.secret
	backingAlias := ownerHandle.Bytes()
	copiedOwner := *transcript

	transcript.Close()
	if transcript.secret != nil {
		t.Fatal("closed transcript retained its owner field")
	}
	if ownerHandle.Len() != 0 || copiedOwner.secret == nil ||
		copiedOwner.secret.Len() != 0 || !allZero(backingAlias) {
		t.Fatal("transcript close did not clear retained backing/copy handles")
	}
	transcript.Close()
	var nilTranscript *CanonicalTranscript
	nilTranscript.Close()
}

func TestNormalCredentialInputLiteralKAT(t *testing.T) {
	tests := []struct {
		name        string
		mode        CredentialMode
		keyfileMode KeyfileMode
		policy      FactorPolicy
		password    []byte
		keyfiles    [][]byte
		transcript  string
		normal      string
	}{
		{
			name:        "password only Unicode NFC",
			mode:        CredentialModePasswordOnly,
			keyfileMode: KeyfileModeNone,
			policy:      FactorPolicyPasswordOnly,
			password:    []byte("Cafe\u0301"),
			transcript:  "0101000000000005436166c3a90000",
			normal:      "47156ab898a6329d3388ca7d762b35af622897e7ce3e7da960aa55f9b1051073afeb902632ea30ddef7d6da4fc6f12c34493bb5abda4ee9a3ac191cba09dd011",
		},
		{
			name:        "keyfiles only ordered alpha beta",
			mode:        CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeOrdered,
			policy:      FactorPolicyKeyfilesOnly,
			keyfiles:    [][]byte{[]byte("alpha"), []byte("beta")},
			transcript:  "0102010000000000000208fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e78655037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d5",
			normal:      "b46f148394701876e14463e4e49ea0e47a5ba76bf798f165452413902273081f466f22547c86aeca4185d13e706cd3eec72eaa59a6983fe9115ea27d25715420",
		},
		{
			name:        "keyfiles only unordered beta alpha",
			mode:        CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeUnordered,
			policy:      FactorPolicyKeyfilesOnly,
			keyfiles:    [][]byte{[]byte("beta"), []byte("alpha")},
			transcript:  "0102020000000000000208fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e78655037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d5",
			normal:      "6374229b64bd0980e8e7a4ab7315bac9e373ad6a99f10b0aa23c4c4979262d7551a059bb3483ad3077884fe592e2cd5266fea57b502a95fbc11ff72b1436b181",
		},
		{
			name:        "combined ordered mix red blue",
			mode:        CredentialModePasswordAndKeyfiles,
			keyfileMode: KeyfileModeOrdered,
			policy:      FactorPolicyPasswordAndKeyfiles,
			password:    []byte("mix"),
			keyfiles:    [][]byte{[]byte("red"), []byte("blue")},
			transcript:  "01030100000000036d697800026d6788bf3bb7ebee87c9c2503a97aacdd7912e8b4093d4c99f17843af69f2f549eb695bdf185f656ac1ee1f68647bbd6c2288ef9f8a5c5b9ef3fec6336b7e3e0",
			normal:      "d4ac95f6c2f0d7ddfe7eadd0a7a01d527acc8c302876884f9c5fb240446f0655d5e0201aecfb73af77e07ac7e18692271a6bec281bc8fc7b270aec30d99f1b02",
		},
		{
			name:        "combined unordered mix blue red",
			mode:        CredentialModePasswordAndKeyfiles,
			keyfileMode: KeyfileModeUnordered,
			policy:      FactorPolicyPasswordAndKeyfiles,
			password:    []byte("mix"),
			keyfiles:    [][]byte{[]byte("blue"), []byte("red")},
			transcript:  "01030200000000036d697800026d6788bf3bb7ebee87c9c2503a97aacdd7912e8b4093d4c99f17843af69f2f549eb695bdf185f656ac1ee1f68647bbd6c2288ef9f8a5c5b9ef3fec6336b7e3e0",
			normal:      "5089ee8f6c1fcce5338e0fb2054b8ec9d461d5d5987627d866329e8bc6eb07965af1a1fdd1c3f89c92838ac6e0080629eacf5935decdaff29301678550085544",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, passwordAlias, readers := newRealTranscriptRequest(
				test.mode,
				test.keyfileMode,
				test.policy,
				test.password,
				test.keyfiles...,
			)
			var input *CredentialInputNormal
			var consumedTranscript *CanonicalTranscript
			var consumedTranscriptHandle *pcsecret.Secret
			var consumedTranscriptBacking []byte
			var consumedTranscriptCopy CanonicalTranscript
			err := WithValidatedFactors(
				context.Background(),
				request,
				func(factors *ValidatedFactors) error {
					transcript, transcriptErr := NewCanonicalTranscript(factors)
					if transcriptErr != nil {
						return transcriptErr
					}
					requireTranscriptLiteral(t, transcript, test.transcript)
					consumedTranscript = transcript
					consumedTranscriptHandle = transcript.secret
					consumedTranscriptBacking = transcript.secret.Bytes()
					consumedTranscriptCopy = *transcript
					var inputErr error
					input, inputErr = NewCredentialInputNormal(transcript)
					return inputErr
				},
			)
			if err != nil {
				t.Fatalf("normal input derivation failed: %v", err)
			}
			requireRealInputsReleased(t, request, passwordAlias, readers)
			if consumedTranscript == nil || consumedTranscript.secret != nil {
				t.Fatal("normal input constructor did not consume transcript owner")
			}
			if consumedTranscriptHandle == nil ||
				consumedTranscriptHandle.Len() != 0 ||
				consumedTranscriptCopy.secret == nil ||
				consumedTranscriptCopy.secret.Len() != 0 ||
				!allZero(consumedTranscriptBacking) {
				t.Fatal("normal input constructor did not clear transcript aliases")
			}
			if input == nil || input.secret == nil {
				t.Fatal("normal input constructor published no owner")
			}
			defer input.Close()
			want := decodeTranscriptLiteral(t, test.normal)
			if !bytes.Equal(input.secret.Bytes(), want) {
				t.Fatalf(
					"normal credential input = %x; want literal %x",
					input.secret.Bytes(),
					want,
				)
			}
			input.Close()
		})
	}
}

func TestNormalCredentialInputDomainIsolation(t *testing.T) {
	const (
		normalHex = "47156ab898a6329d3388ca7d762b35af622897e7ce3e7da960aa55f9b1051073afeb902632ea30ddef7d6da4fc6f12c34493bb5abda4ee9a3ac191cba09dd011"
		outerHex  = "ef8903e78a235daafd3f5678bd99bcf74e7d7d63e2f12cf27211a5d1dde1227c6962068ab0079c82ccba28d3f5ebbaa75d0f91bc4bf1e01be38af02faa9d629e"
	)
	input := newPasswordNormalInput(t)
	defer input.Close()
	normal := decodeTranscriptLiteral(t, normalHex)
	outer := decodeTranscriptLiteral(t, outerHex)
	if bytes.Equal(normal, outer) {
		t.Fatal("independent normal/outer literal fixtures unexpectedly match")
	}
	if !bytes.Equal(input.secret.Bytes(), normal) ||
		bytes.Equal(input.secret.Bytes(), outer) {
		t.Fatalf(
			"normal-domain input = %x; want normal %x and not outer %x",
			input.secret.Bytes(),
			normal,
			outer,
		)
	}
	input.Close()
}

func TestNormalCredentialInputClose(t *testing.T) {
	t.Run("constructor rejection consumes and clears transcript", func(t *testing.T) {
		backingAlias := []byte("short")
		ownerHandle := pcsecret.SecretFrom(backingAlias)
		transcript := &CanonicalTranscript{secret: ownerHandle}
		input, err := NewCredentialInputNormal(transcript)
		requireTranscriptCode(t, err, TranscriptErrorLength)
		if input != nil {
			input.Close()
			t.Fatal("invalid transcript published a normal credential input")
		}
		if transcript.secret != nil || ownerHandle.Len() != 0 ||
			!allZero(backingAlias) {
			t.Fatal("constructor rejection did not consume and clear transcript")
		}

		input, err = NewCredentialInputNormal(nil)
		requireTranscriptCode(t, err, TranscriptErrorClosed)
		if input != nil {
			input.Close()
			t.Fatal("nil transcript published a normal credential input")
		}
	})

	t.Run("Close clears retained backing and copy handles", func(t *testing.T) {
		input := newPasswordNormalInput(t)
		ownerHandle := input.secret
		backingAlias := ownerHandle.Bytes()
		copiedOwner := *input
		input.Close()
		if input.secret != nil {
			t.Fatal("closed normal input retained its owner field")
		}
		if ownerHandle.Len() != 0 || copiedOwner.secret == nil ||
			copiedOwner.secret.Len() != 0 || !allZero(backingAlias) {
			t.Fatal("normal input close did not clear retained backing/copy handles")
		}
		input.Close()
		var nilInput *CredentialInputNormal
		nilInput.Close()
	})

	t.Run("consume calls once and clears success borrow", func(t *testing.T) {
		input := newPasswordNormalInput(t)
		ownerHandle := input.secret
		backingAlias := ownerHandle.Bytes()
		copiedOwner := *input
		calls := 0
		var callbackBorrow []byte
		err := input.consume(func(borrow []byte) error {
			calls++
			callbackBorrow = borrow
			if len(borrow) != 64 {
				t.Fatalf("normal input borrow length = %d; want 64", len(borrow))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("consume success failed: %v", err)
		}
		if calls != 1 || input.secret != nil || ownerHandle.Len() != 0 ||
			copiedOwner.secret == nil || copiedOwner.secret.Len() != 0 ||
			!allZero(backingAlias) || !allZero(callbackBorrow) {
			t.Fatal("successful consume did not call once and clear every retained borrow")
		}
	})

	t.Run("consume returns callback error and clears borrow", func(t *testing.T) {
		callbackErr := errors.New("callback failure")
		input := newPasswordNormalInput(t)
		ownerHandle := input.secret
		backingAlias := ownerHandle.Bytes()
		calls := 0
		var callbackBorrow []byte
		err := input.consume(func(borrow []byte) error {
			calls++
			callbackBorrow = borrow
			return callbackErr
		})
		if err != callbackErr { //nolint:errorlint // Exact callback error identity is the contract.
			t.Fatalf("consume error = %v; want callback error", err)
		}
		if calls != 1 || input.secret != nil || ownerHandle.Len() != 0 ||
			!allZero(backingAlias) || !allZero(callbackBorrow) {
			t.Fatal("error consume did not call once and clear every retained borrow")
		}
	})

	t.Run("consume clears borrow after callback panic", func(t *testing.T) {
		input := newPasswordNormalInput(t)
		ownerHandle := input.secret
		backingAlias := ownerHandle.Bytes()
		copiedOwner := *input
		var callbackBorrow []byte
		var recovered any
		func() {
			defer func() {
				recovered = recover()
			}()
			_ = input.consume(func(borrow []byte) error {
				callbackBorrow = borrow
				panic("normal-callback-panic")
			})
		}()
		if recovered != "normal-callback-panic" {
			t.Fatalf("consume panic = %#v; want callback panic", recovered)
		}
		if input.secret != nil || ownerHandle.Len() != 0 ||
			copiedOwner.secret == nil || copiedOwner.secret.Len() != 0 ||
			!allZero(backingAlias) || !allZero(callbackBorrow) {
			t.Fatal("panic consume did not clear every retained borrow")
		}
	})

	t.Run("nil closed and nil callback are rejected without a call", func(t *testing.T) {
		calls := 0
		callback := func([]byte) error {
			calls++
			return nil
		}
		var nilInput *CredentialInputNormal
		requireTranscriptCode(
			t,
			nilInput.consume(callback),
			TranscriptErrorClosed,
		)

		closedInput := newPasswordNormalInput(t)
		closedInput.Close()
		requireTranscriptCode(
			t,
			closedInput.consume(callback),
			TranscriptErrorClosed,
		)

		nilCallbackInput := newPasswordNormalInput(t)
		nilCallbackOwner := nilCallbackInput.secret
		nilCallbackBacking := nilCallbackOwner.Bytes()
		requireTranscriptCode(
			t,
			nilCallbackInput.consume(nil),
			TranscriptErrorClosed,
		)
		if nilCallbackInput.secret != nil ||
			nilCallbackOwner.Len() != 0 ||
			!allZero(nilCallbackBacking) {
			t.Fatal("nil callback rejection did not clear normal input backing")
		}
		if calls != 0 {
			t.Fatalf("rejected consume callback calls = %d; want 0", calls)
		}
	})
}
