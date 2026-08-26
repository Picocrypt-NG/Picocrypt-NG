package pcv3

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestNormalAuthResultRegistryAndRedaction(t *testing.T) {
	tests := []struct {
		outcome Outcome
		stage   Stage
		code    Code
		wantOut string
		wantStg string
	}{
		{OutcomeSuccess, StageNone, CodeSuccess, "success", "none"},
		{OutcomeInvalidStructurePreKDF, StageCapsuleStructure, CodeInvalidStructure, "invalid-structure-pre-kdf", "capsule-structure"},
		{OutcomeCredentialsOrDamage, StageWrapAuth, CodeCredentialsOrDamage, "credentials-or-damage", "wrap-auth"},
		{OutcomeAuthenticatedDegraded, StageReplicaAuth, CodeAuthenticatedDegraded, "authenticated-degraded", "replica-auth"},
		{OutcomeAmbiguousVolume, StageCapsuleStructure, CodeAmbiguousVolume, "ambiguous-volume", "capsule-structure"},
	}
	for _, test := range tests {
		if got := test.outcome.String(); got != test.wantOut {
			t.Errorf("outcome string = %q; want %q", got, test.wantOut)
		}
		if got := test.stage.String(); got != test.wantStg {
			t.Errorf("stage string = %q; want %q", got, test.wantStg)
		}
		if got := newNormalAuthResult(test.outcome, test.stage, 0).Code(); got != test.code {
			t.Errorf("code = %v; want %v", got, test.code)
		}
	}

	result := newNormalAuthResult(
		OutcomeCredentialsOrDamage,
		StageWrapAuth,
		0,
	)
	canary := "credential-root=00112233445566778899aabbccddeeff"
	for _, rendered := range []string{
		result.Error(),
		result.String(),
		result.GoString(),
		fmt.Sprintf("%v", result),
		fmt.Sprintf("%+v", result),
		fmt.Sprintf("%#v", result),
	} {
		if strings.Contains(rendered, canary) ||
			rendered != "pcv3: credentials incorrect or volume damaged" {
			t.Fatalf("normal auth result rendered %q", rendered)
		}
	}
	result.Close()
}

func TestMetadataResultRedaction(t *testing.T) {
	codecs := metadataTestCodecs(t)
	auth := metadataTestAuthority(t, metadataTestStandardCore, 2, 1248)
	borrower := metadataTestBorrower(t, auth, metadataTestStandardKey)
	defer borrower.close()
	encoded := metadataFixture(t, "standard_unicode.bin")

	recovered, err := readMetadata(
		context.Background(),
		&metadataTrackingReader{base: int64(frontHeaderBase), data: encoded},
		auth,
		codecs,
	)
	if err != nil {
		t.Fatalf("recover TEST ONLY metadata tag canary: %v", err)
	}
	tagCanary := hex.EncodeToString(recovered.tag[:])
	recovered.close()

	authenticated, err := authenticateMetadata(
		context.Background(),
		&metadataTrackingReader{base: int64(frontHeaderBase), data: encoded},
		auth,
		codecs,
	)
	if err != nil {
		t.Fatalf("authenticate TEST ONLY metadata for redaction: %v", err)
	}
	defer authenticated.close()

	damagedAuth := metadataTestAuthority(t, metadataTestInvalidCore, 1, 1112)
	damagedBorrower := metadataTestBorrower(t, damagedAuth, metadataTestStandardKey)
	defer damagedBorrower.close()
	damaged, err := authenticateMetadata(
		context.Background(),
		&metadataTrackingReader{
			base: int64(frontHeaderBase),
			data: metadataFixture(t, "bad_tag.bin"),
		},
		damagedAuth,
		codecs,
	)
	if err != nil {
		t.Fatalf("authenticate TEST ONLY damaged metadata for redaction: %v", err)
	}
	defer damaged.close()

	canaries := []string{
		metadataTestUnicodeComment,
		metadataTestStandardKey,
		tagCanary,
	}
	tests := []struct {
		name   string
		result *metadataResult
		want   string
	}{
		{
			name:   "authenticated public",
			result: authenticated,
			want:   "pcv3: authenticated public metadata",
		},
		{
			name:   "metadata damaged",
			result: damaged,
			want:   "pcv3: metadata damaged",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			renderings := []struct {
				name string
				got  string
				want string
			}{
				{name: "Error", got: test.result.Error(), want: test.want},
				{name: "String", got: test.result.String(), want: test.want},
				{name: "GoString", got: test.result.GoString(), want: test.want},
				{name: "%s", got: fmt.Sprintf("%s", test.result), want: test.want},
				{name: "%q", got: fmt.Sprintf("%q", test.result), want: strconv.Quote(test.want)},
				{name: "%v", got: fmt.Sprintf("%v", test.result), want: test.want},
				{name: "%+v", got: fmt.Sprintf("%+v", test.result), want: test.want},
				{name: "%#v", got: fmt.Sprintf("%#v", test.result), want: test.want},
				{name: "%x", got: fmt.Sprintf("%x", test.result), want: test.want},
				{name: "%X", got: fmt.Sprintf("%X", test.result), want: test.want},
			}
			for _, rendering := range renderings {
				if rendering.got != rendering.want {
					t.Fatalf("metadata result %s rendered %q; want %q", rendering.name, rendering.got, rendering.want)
				}
				for _, canary := range canaries {
					if canary != "" && bytes.Contains([]byte(rendering.got), []byte(canary)) {
						t.Fatalf("metadata result disclosed TEST ONLY canary in %q", rendering.got)
					}
				}
			}
		})
	}
}
