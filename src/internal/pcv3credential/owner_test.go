package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const ownerSecretSentinel = "pcv3-owner-secret-sentinel" //gitleaks:allow -- Synthetic disclosure-test sentinel.

type ownerFixture struct {
	owner     *Owner
	metadata  OwnerMetadata
	request   KeyRequest
	volumeKey []byte
	key       []byte
	aliases   map[string][]byte
}

func newOwnerFixture(t *testing.T) *ownerFixture {
	t.Helper()

	material, aliases, rows := newOwnerMaterial(t)
	metadata := validOwnerMetadataFixture()
	owner, err := newOwner(metadata, material)
	if err != nil {
		material.close()
		t.Fatalf("newOwner: %v", err)
	}
	return &ownerFixture{
		owner:     owner,
		metadata:  metadata,
		request:   rows[0].request,
		volumeKey: bytes.Repeat([]byte{0x22}, derivedKeyBytes),
		key:       bytes.Repeat([]byte{0x50}, derivedKeyBytes),
		aliases:   aliases,
	}
}

func newOwnerMaterial(t *testing.T) (*keyMaterial, map[string][]byte, []scheduleRow) {
	t.Helper()

	rows, err := fixedScheduleForSuite(SuiteStandard1)
	if err != nil {
		t.Fatalf("fixedScheduleForSuite: %v", err)
	}
	material := &keyMaterial{
		credentialRoot: &credentialRoot{
			secret: crypto.SecretFrom(bytes.Repeat([]byte{0x11}, credentialRootBytes)),
		},
		volumeKey: &volumeKey{
			secret: crypto.SecretFrom(bytes.Repeat([]byte{0x22}, derivedKeyBytes)),
		},
		credentialPRK: &credentialPRK{
			secret: crypto.SecretFrom(bytes.Repeat([]byte{0x33}, derivedKeyBytes)),
		},
		volumePRK: &volumePRK{
			secret: crypto.SecretFrom(bytes.Repeat([]byte{0x44}, derivedKeyBytes)),
		},
		keys: make([]derivedKey, len(rows)),
	}
	aliases := map[string][]byte{
		"CredentialRoot": material.credentialRoot.secret.Bytes(),
		"VolumeKey":      material.volumeKey.secret.Bytes(),
		"CredentialPRK":  material.credentialPRK.secret.Bytes(),
		"VolumePRK":      material.volumePRK.secret.Bytes(),
	}
	for i, row := range rows {
		value := byte(0x50 + i)
		material.keys[i] = derivedKey{
			row:    row,
			secret: crypto.SecretFrom(bytes.Repeat([]byte{value}, derivedKeyBytes)),
		}
		aliases[fmt.Sprintf("DerivedKey[%d]", i)] = material.keys[i].secret.Bytes()
	}
	return material, aliases, rows
}

func validOwnerMetadataFixture() OwnerMetadata {
	metadata := OwnerMetadata{
		Suite:          SuiteStandard1,
		ExpectedPolicy: FactorPolicyPasswordOnly,
		CredentialMode: CredentialModePasswordOnly,
		KeyfileMode:    KeyfileModeNone,
		KeyfileCount:   0,
	}
	for i := range metadata.ArgonSalt {
		metadata.ArgonSalt[i] = byte(i + 1)
	}
	for i := range metadata.VolumeID {
		metadata.VolumeID[i] = byte(0x80 + i)
	}
	return metadata
}

func requireOwnerCode(
	t *testing.T,
	err error,
	want OwnerErrorCode,
) *OwnerError {
	t.Helper()
	var ownerErr *OwnerError
	if !errors.As(err, &ownerErr) {
		t.Fatalf("error = %v; want *OwnerError", err)
	}
	if ownerErr.Code != want {
		t.Fatalf("owner error code = %v; want %v", ownerErr.Code, want)
	}
	return ownerErr
}

func requireOwnerAliasesZero(t *testing.T, aliases map[string][]byte) {
	t.Helper()
	for name, alias := range aliases {
		if !bytes.Equal(alias, make([]byte, len(alias))) {
			t.Fatalf("%s retained alias was not cleared", name)
		}
	}
}

func TestOwnerCloseIdempotent(t *testing.T) {
	fixture := newOwnerFixture(t)
	alias := fixture.aliases["VolumeKey"]
	copiedOwner := *fixture.owner

	fixture.owner.Close()
	if !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Fatal("first Close did not clear the owned VolumeKey")
	}

	// A second Close must not revisit an already released backing buffer.
	// Refill the retained test alias to make a duplicate cleanup observable.
	for i := range alias {
		alias[i] = 0x7e
	}
	copiedOwner.Close()
	fixture.owner.Close()
	if !bytes.Equal(alias, bytes.Repeat([]byte{0x7e}, len(alias))) {
		t.Fatal("copied or repeated Close revisited released backing storage")
	}
	crypto.SecureZero(alias)
}

func TestOwnerClearsEveryAlias(t *testing.T) {
	fixture := newOwnerFixture(t)

	fixture.owner.Close()

	requireOwnerAliasesZero(t, fixture.aliases)
}

func TestOwnerBorrowScope(t *testing.T) {
	fixture := newOwnerFixture(t)
	defer fixture.owner.Close()

	var retained *BorrowedKeys
	var copied BorrowedKeys
	volumeCopy := make([]byte, derivedKeyBytes)
	keyCopy := make([]byte, derivedKeyBytes)
	err := fixture.owner.WithKeys(
		context.Background(),
		func(keys *BorrowedKeys) error {
			retained = keys
			copied = *keys
			if err := keys.CopyVolumeKey(volumeCopy); err != nil {
				return err
			}
			return keys.CopyKey(fixture.request, keyCopy)
		},
	)
	if err != nil {
		t.Fatalf("WithKeys: %v", err)
	}
	if !bytes.Equal(volumeCopy, fixture.volumeKey) {
		t.Fatalf("VolumeKey copy = %x; want %x", volumeCopy, fixture.volumeKey)
	}
	if !bytes.Equal(keyCopy, fixture.key) {
		t.Fatalf("derived-key copy = %x; want %x", keyCopy, fixture.key)
	}

	volumeCopy[0] ^= 0xff
	keyCopy[0] ^= 0xff
	if fixture.aliases["VolumeKey"][0] != fixture.volumeKey[0] ||
		fixture.aliases["DerivedKey[0]"][0] != fixture.key[0] {
		t.Fatal("borrow API exposed a package-owned backing buffer")
	}

	requireOwnerCode(
		t,
		retained.CopyKey(fixture.request, make([]byte, derivedKeyBytes)),
		OwnerErrorBorrowExpired,
	)
	requireOwnerCode(
		t,
		copied.CopyKey(fixture.request, make([]byte, derivedKeyBytes)),
		OwnerErrorBorrowExpired,
	)
}

func TestOwnerCloseWaitsForBorrow(t *testing.T) {
	fixture := newOwnerFixture(t)
	copiedOwner := *fixture.owner
	borrowEntered := make(chan struct{})
	releaseBorrow := make(chan struct{})
	callbackDone := make(chan error, 1)
	go func() {
		callbackDone <- fixture.owner.WithKeys(
			context.Background(),
			func(keys *BorrowedKeys) error {
				close(borrowEntered)
				<-releaseBorrow
				return keys.CopyKey(
					fixture.request,
					make([]byte, derivedKeyBytes),
				)
			},
		)
	}()
	<-borrowEntered

	closeDone := make(chan struct{})
	go func() {
		copiedOwner.Close()
		close(closeDone)
	}()
	<-fixture.owner.state.closing

	select {
	case <-closeDone:
		t.Fatal("Close returned while a borrow was still active")
	default:
	}
	if bytes.Equal(
		fixture.aliases["VolumeKey"],
		make([]byte, derivedKeyBytes),
	) {
		t.Fatal("Close cleared secret bytes while they were borrowed")
	}
	called := false
	err := fixture.owner.WithKeys(
		context.Background(),
		func(*BorrowedKeys) error {
			called = true
			return nil
		},
	)
	requireOwnerCode(t, err, OwnerErrorClosed)
	if called {
		t.Fatal("new borrow callback ran after Close began")
	}

	close(releaseBorrow)
	if err := <-callbackDone; err != nil {
		t.Fatalf("active callback returned error: %v", err)
	}
	<-closeDone
	requireOwnerAliasesZero(t, fixture.aliases)
}

func TestOwnerRejectsBorrowAfterClose(t *testing.T) {
	fixture := newOwnerFixture(t)
	fixture.owner.Close()

	called := false
	err := fixture.owner.WithKeys(
		context.Background(),
		func(*BorrowedKeys) error {
			called = true
			return nil
		},
	)
	requireOwnerCode(t, err, OwnerErrorClosed)
	if called {
		t.Fatal("callback ran after owner Close")
	}
}

func TestOwnerCallbackErrorCleanup(t *testing.T) {
	t.Run("callback error", func(t *testing.T) {
		fixture := newOwnerFixture(t)
		var retained *BorrowedKeys
		callbackErr := errors.New(ownerSecretSentinel)
		err := fixture.owner.WithKeys(
			context.Background(),
			func(keys *BorrowedKeys) error {
				retained = keys
				return callbackErr
			},
		)
		requireOwnerCode(t, err, OwnerErrorCallback)
		if strings.Contains(err.Error(), ownerSecretSentinel) {
			t.Fatal("callback error text escaped through the owner")
		}
		requireOwnerCode(
			t,
			retained.CopyVolumeKey(make([]byte, derivedKeyBytes)),
			OwnerErrorBorrowExpired,
		)
		fixture.owner.Close()
		requireOwnerAliasesZero(t, fixture.aliases)
	})

	t.Run("cancellation after callback", func(t *testing.T) {
		fixture := newOwnerFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		var retained *BorrowedKeys
		err := fixture.owner.WithKeys(ctx, func(keys *BorrowedKeys) error {
			retained = keys
			cancel()
			return nil
		})
		requireOwnerCode(t, err, OwnerErrorCancelled)
		requireOwnerCode(
			t,
			retained.CopyVolumeKey(make([]byte, derivedKeyBytes)),
			OwnerErrorBorrowExpired,
		)
		fixture.owner.Close()
		requireOwnerAliasesZero(t, fixture.aliases)
	})

	t.Run("nested asynchronous close", func(t *testing.T) {
		fixture := newOwnerFixture(t)
		closeDone := make(chan struct{})
		err := fixture.owner.WithKeys(
			context.Background(),
			func(keys *BorrowedKeys) error {
				go func() {
					fixture.owner.Close()
					close(closeDone)
				}()
				<-fixture.owner.state.closing
				select {
				case <-closeDone:
					t.Fatal("nested Close returned before callback release")
				default:
				}
				return keys.CopyKey(
					fixture.request,
					make([]byte, derivedKeyBytes),
				)
			},
		)
		if err != nil {
			t.Fatalf("WithKeys: %v", err)
		}
		<-closeDone
		requireOwnerAliasesZero(t, fixture.aliases)
	})
}

func TestOwnerCallbackPanicCleanup(t *testing.T) {
	fixture := newOwnerFixture(t)
	var retained *BorrowedKeys
	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("callback panic was not propagated")
			}
		}()
		_ = fixture.owner.WithKeys(
			context.Background(),
			func(keys *BorrowedKeys) error {
				retained = keys
				panic("callback panic")
			},
		)
	}()

	requireOwnerCode(
		t,
		retained.CopyVolumeKey(make([]byte, derivedKeyBytes)),
		OwnerErrorBorrowExpired,
	)
	fixture.owner.Close()
	requireOwnerAliasesZero(t, fixture.aliases)
}

func TestOwnerDiagnosticsNoDisclosure(t *testing.T) {
	rows, err := fixedScheduleForSuite(SuiteStandard1)
	if err != nil {
		t.Fatalf("fixedScheduleForSuite: %v", err)
	}
	sentinel := []byte(ownerSecretSentinel)
	padded := append([]byte(nil), sentinel...)
	padded = append(padded, bytes.Repeat([]byte{'!'}, derivedKeyBytes-len(padded))...)
	material := &keyMaterial{
		credentialRoot: &credentialRoot{
			secret: crypto.SecretFrom(append([]byte(nil), padded...)),
		},
		volumeKey: &volumeKey{
			secret: crypto.SecretFrom(append([]byte(nil), padded...)),
		},
		credentialPRK: &credentialPRK{
			secret: crypto.SecretFrom(append([]byte(nil), padded...)),
		},
		volumePRK: &volumePRK{
			secret: crypto.SecretFrom(append([]byte(nil), padded...)),
		},
		keys: []derivedKey{{
			row:    rows[0],
			secret: crypto.SecretFrom(append([]byte(nil), padded...)),
		}},
	}
	owner, err := newOwner(
		OwnerMetadata{
			Suite:          SuiteStandard1,
			ExpectedPolicy: FactorPolicyPasswordOnly,
			CredentialMode: CredentialModePasswordOnly,
			KeyfileMode:    KeyfileModeNone,
			KeyfileCount:   0,
		},
		material,
	)
	if err != nil {
		material.close()
		t.Fatalf("newOwner: %v", err)
	}
	defer owner.Close()

	var borrow *BorrowedKeys
	callbackErr := owner.WithKeys(
		context.Background(),
		func(keys *BorrowedKeys) error {
			borrow = keys
			return errors.New(ownerSecretSentinel)
		},
	)
	diagnostics := strings.Join([]string{
		fmt.Sprintf("%v", owner),
		fmt.Sprintf("%+v", owner),
		fmt.Sprintf("%#v", owner),
		fmt.Sprintf("%v", borrow),
		fmt.Sprintf("%+v", borrow),
		fmt.Sprintf("%#v", borrow),
		fmt.Sprintf("%v", callbackErr),
		fmt.Sprintf("%+v", callbackErr),
		fmt.Sprintf("%#v", callbackErr),
		fmt.Sprintf("%v", owner.Metadata()),
	}, "\n")
	for _, encoded := range []string{
		ownerSecretSentinel,
		hex.EncodeToString(sentinel),
		base64.StdEncoding.EncodeToString(sentinel),
	} {
		if strings.Contains(diagnostics, encoded) {
			t.Fatalf("owner diagnostics disclosed secret sentinel encoding %q", encoded)
		}
	}
}

func TestOwnerRejectsInvalidCredentialTuple(t *testing.T) {
	tests := []struct {
		name string
		edit func(*OwnerMetadata)
	}{
		{name: "unknown credential mode", edit: func(metadata *OwnerMetadata) {
			metadata.CredentialMode = CredentialMode(0xff)
		}},
		{name: "password only with ordering", edit: func(metadata *OwnerMetadata) {
			metadata.KeyfileMode = KeyfileModeOrdered
		}},
		{name: "password only with keyfile", edit: func(metadata *OwnerMetadata) {
			metadata.KeyfileCount = 1
		}},
		{name: "keyfiles only without ordering", edit: func(metadata *OwnerMetadata) {
			metadata.ExpectedPolicy = FactorPolicyKeyfilesOnly
			metadata.CredentialMode = CredentialModeKeyfilesOnly
			metadata.KeyfileMode = KeyfileModeNone
			metadata.KeyfileCount = 1
		}},
		{name: "keyfiles only without keyfile", edit: func(metadata *OwnerMetadata) {
			metadata.ExpectedPolicy = FactorPolicyKeyfilesOnly
			metadata.CredentialMode = CredentialModeKeyfilesOnly
			metadata.KeyfileMode = KeyfileModeOrdered
			metadata.KeyfileCount = 0
		}},
		{name: "combined policy mismatch", edit: func(metadata *OwnerMetadata) {
			metadata.CredentialMode = CredentialModePasswordAndKeyfiles
			metadata.KeyfileMode = KeyfileModeOrdered
			metadata.KeyfileCount = 1
		}},
		{name: "too many keyfiles", edit: func(metadata *OwnerMetadata) {
			metadata.ExpectedPolicy = FactorPolicyKeyfilesOnly
			metadata.CredentialMode = CredentialModeKeyfilesOnly
			metadata.KeyfileMode = KeyfileModeUnordered
			metadata.KeyfileCount = maxKeyfiles + 1
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := validOwnerMetadataFixture()
			test.edit(&metadata)
			material, aliases, _ := newOwnerMaterial(t)
			owner, err := newOwner(metadata, material)
			if owner != nil {
				owner.Close()
				t.Fatal("invalid credential tuple published an owner")
			}
			requireOwnerCode(t, err, OwnerErrorInvalidRequest)
			requireOwnerAliasesZero(t, aliases)
		})
	}
}
