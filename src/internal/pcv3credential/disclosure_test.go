package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"bytes"
	"context"
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

type credentialDisclosureCapture struct {
	diagnostics []string
	stdout      bytes.Buffer
	stderr      bytes.Buffer
	logs        bytes.Buffer
}

func credentialDisclosureSentinel(kind string) []byte {
	digest := sha3.Sum256(
		[]byte("Picocrypt-NG Credential disclosure sentinel: " + kind),
	)
	return append([]byte(nil), digest[:]...)
}

func credentialDisclosureVariants(secret []byte) []string {
	return []string{
		string(secret),
		hex.EncodeToString(secret),
		strings.ToUpper(hex.EncodeToString(secret)),
		base64.StdEncoding.EncodeToString(secret),
		base64.RawStdEncoding.EncodeToString(secret),
		base64.URLEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret),
		fmt.Sprintf("%v", secret),
	}
}

func (capture *credentialDisclosureCapture) add(values ...any) {
	for _, value := range values {
		capture.diagnostics = append(
			capture.diagnostics,
			fmt.Sprintf("%v\n%+v\n%#v", value, value, value),
		)
	}
}

func captureCredentialProcessOutput(
	t *testing.T,
	callback func(),
) (stdout string, stderr string, logs string) {
	t.Helper()
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	oldLogWriter := log.Writer()
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		t.Fatalf("stderr pipe: %v", err)
	}
	var logBuffer bytes.Buffer
	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter
	log.SetOutput(&logBuffer)
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		log.SetOutput(oldLogWriter)
	}()

	callback()
	if err := stdoutWriter.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	stdoutBytes := make([]byte, 0, 128)
	buffer := make([]byte, 128)
	for {
		n, readErr := stdoutReader.Read(buffer)
		stdoutBytes = append(stdoutBytes, buffer[:n]...)
		if readErr != nil {
			break
		}
	}
	stderrBytes := make([]byte, 0, 128)
	for {
		n, readErr := stderrReader.Read(buffer)
		stderrBytes = append(stderrBytes, buffer[:n]...)
		if readErr != nil {
			break
		}
	}
	if err := stdoutReader.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}
	if err := stderrReader.Close(); err != nil {
		t.Fatalf("close stderr reader: %v", err)
	}
	return string(stdoutBytes), string(stderrBytes), logBuffer.String()
}

func TestCredentialDisclosureSentinelMatrix(t *testing.T) {
	secrets := map[string][]byte{
		"password":       credentialDisclosureSentinel("password"),
		"transcript":     credentialDisclosureSentinel("transcript"),
		"kdf-result":     credentialDisclosureSentinel("kdf-result"),
		"volume-key":     credentialDisclosureSentinel("volume-key"),
		"credential-prk": credentialDisclosureSentinel("credential-prk"),
		"volume-prk":     credentialDisclosureSentinel("volume-prk"),
		"expanded-key":   credentialDisclosureSentinel("expanded-key"),
	}
	for _, secret := range secrets {
		defer crypto.SecureZero(secret)
	}
	secretVariants := make(map[string][]string, len(secrets)+10)
	for name, secret := range secrets {
		secretVariants[name] = credentialDisclosureVariants(secret)
	}

	capture := &credentialDisclosureCapture{}
	stdout, stderr, logs := captureCredentialProcessOutput(t, func() {
		passwordAlias := append([]byte(nil), secrets["password"]...)
		factorRequest := &FactorRequest{
			Mode:           CredentialModePasswordOnly,
			KeyfileMode:    KeyfileModeNone,
			ExpectedPolicy: FactorPolicyPasswordOnly,
			Password:       passwordAlias,
		}
		capture.add(*factorRequest)
		factorErr := WithValidatedFactors(
			context.Background(),
			factorRequest,
			func(factors *ValidatedFactors) error {
				capture.add(factors)
				return errors.New("public factor callback marker")
			},
		)
		capture.add(factorErr)
		if !allZero(passwordAlias) {
			t.Fatal("disclosure probe retained the transferred password")
		}

		transcriptAlias := append([]byte(nil), secrets["transcript"]...)
		transcript := &CanonicalTranscript{
			secret: crypto.SecretFrom(transcriptAlias),
		}
		capture.add(transcript)
		transcript.Close()
		if !allZero(transcriptAlias) {
			t.Fatal("disclosure probe retained the transcript")
		}

		inputAlias := bytes.Repeat([]byte{0x41}, credentialInputNormalBytes)
		input := &CredentialInputNormal{secret: crypto.SecretFrom(inputAlias)}
		kdfReturned := append([]byte(nil), secrets["kdf-result"]...)
		root, kdfErr := runCredentialKDF(
			context.Background(),
			input,
			bytes.Repeat([]byte{0x21}, kdfSaltBytes),
			SuiteStandard1,
			&pipelineAdmission{result: KDFAdmissionGranted},
			func([]byte, []byte, KDFProfile) ([]byte, error) {
				return kdfReturned, errors.New("public KDF provider marker")
			},
		)
		if root != nil {
			root.close()
			t.Fatal("failing KDF published a root")
		}
		capture.add(kdfErr)
		if !allZero(inputAlias) || !allZero(kdfReturned) {
			t.Fatal("disclosure KDF probe retained input or provider output")
		}

		rows, err := fixedScheduleForSuite(SuiteStandard1)
		if err != nil {
			t.Fatalf("fixedScheduleForSuite: %v", err)
		}
		ownerCredentialRoot := credentialDisclosureSentinel("owner-credential-root")
		secretVariants["owner-credential-root"] = credentialDisclosureVariants(ownerCredentialRoot)
		ownerAliases := map[string][]byte{
			"CredentialRoot": ownerCredentialRoot,
			"VolumeKey":      append([]byte(nil), secrets["volume-key"]...),
			"CredentialPRK":  append([]byte(nil), secrets["credential-prk"]...),
			"VolumePRK":      append([]byte(nil), secrets["volume-prk"]...),
			"DerivedKey":     append([]byte(nil), secrets["expanded-key"]...),
		}
		material := &keyMaterial{
			credentialRoot: &credentialRoot{
				secret: crypto.SecretFrom(ownerAliases["CredentialRoot"]),
			},
			volumeKey: &volumeKey{
				secret: crypto.SecretFrom(ownerAliases["VolumeKey"]),
			},
			credentialPRK: &credentialPRK{
				secret: crypto.SecretFrom(ownerAliases["CredentialPRK"]),
			},
			volumePRK: &volumePRK{
				secret: crypto.SecretFrom(ownerAliases["VolumePRK"]),
			},
			keys: make([]derivedKey, len(rows)),
		}
		for i, row := range rows {
			keyBytes := ownerAliases["DerivedKey"]
			if i > 0 {
				keyBytes = credentialDisclosureSentinel(
					fmt.Sprintf("expanded-key-%d", i),
				)
				secretVariants[fmt.Sprintf("expanded-key-%d", i)] = credentialDisclosureVariants(keyBytes)
				defer crypto.SecureZero(keyBytes)
			}
			material.keys[i] = derivedKey{
				row:    row,
				secret: crypto.SecretFrom(keyBytes),
			}
		}
		metadata := OwnerMetadata{
			Suite:          SuiteStandard1,
			ExpectedPolicy: FactorPolicyPasswordOnly,
			CredentialMode: CredentialModePasswordOnly,
			KeyfileMode:    KeyfileModeNone,
			KeyfileCount:   0,
		}
		owner, err := newOwner(metadata, material)
		if err != nil {
			material.close()
			t.Fatalf("newOwner: %v", err)
		}
		capture.add(
			owner,
			material,
			material.credentialRoot,
			material.volumeKey,
			material.credentialPRK,
			material.volumePRK,
			material.keys[0],
		)

		var retained *BorrowedKeys
		callbackErr := owner.WithKeys(
			context.Background(),
			func(keys *BorrowedKeys) error {
				retained = keys
				capture.add(keys)
				return errors.New("public owner callback marker")
			},
		)
		capture.add(callbackErr, retained)
		panicValue := func() (recovered any) {
			defer func() {
				recovered = recover()
			}()
			_ = owner.WithKeys(
				context.Background(),
				func(keys *BorrowedKeys) error {
					capture.add(keys)
					panic("public callback panic marker")
				},
			)
			return nil
		}()
		capture.add(panicValue)

		_ = fmt.Sprintf("%v %+v %#v", owner, owner, owner)
		_ = fmt.Sprintf("%v %+v %#v", callbackErr, callbackErr, callbackErr)
		owner.Close()
		for name, alias := range ownerAliases {
			if !allZero(alias) {
				t.Fatalf("disclosure owner retained %s", name)
			}
		}
	})
	capture.stdout.WriteString(stdout)
	capture.stderr.WriteString(stderr)
	capture.logs.WriteString(logs)

	surfaces := strings.Join(
		append([]string(nil), capture.diagnostics...),
		"\n",
	) + "\n" + capture.stdout.String() + "\n" +
		capture.stderr.String() + "\n" + capture.logs.String()
	for name, variants := range secretVariants {
		for _, variant := range variants {
			if variant != "" && strings.Contains(surfaces, variant) {
				t.Fatalf(
					"package-owned diagnostics disclosed %s as %q",
					name,
					variant,
				)
			}
		}
	}
}
