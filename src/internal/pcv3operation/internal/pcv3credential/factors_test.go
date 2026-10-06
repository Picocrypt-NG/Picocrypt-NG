package pcv3credential

import (
	pcsecret "Picocrypt-NG/internal/secret"
	"bytes"
	"context"
	"crypto/sha3"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

const testKeyfileDomain = "Picocrypt-NG/PCV3/keyfile\x00"

type trackedReadCloser struct {
	readFn     func([]byte) (int, error)
	closeFn    func() error
	closeErr   error
	readCalls  int
	bytesRead  int
	closeCalls int
}

func (r *trackedReadCloser) Read(p []byte) (int, error) {
	r.readCalls++
	n, err := r.readFn(p)
	if n > 0 && n <= len(p) {
		r.bytesRead += n
	}
	return n, err
}

func (r *trackedReadCloser) Close() error {
	r.closeCalls++
	if r.closeFn != nil {
		return r.closeFn()
	}
	return r.closeErr
}

func newChunkedReadCloser(data []byte, chunk int) *trackedReadCloser {
	offset := 0
	finished := false
	return &trackedReadCloser{readFn: func(p []byte) (int, error) {
		if finished {
			return 0, errors.New("reader was consumed more than once")
		}
		if offset == len(data) {
			finished = true
			return 0, io.EOF
		}
		n := len(data) - offset
		if chunk > 0 && n > chunk {
			n = chunk
		}
		if n > len(p) {
			n = len(p)
		}
		copy(p, data[offset:offset+n])
		offset += n
		return n, nil
	}}
}

func newImmediateErrorReadCloser(err error) *trackedReadCloser {
	return &trackedReadCloser{readFn: func([]byte) (int, error) {
		return 0, err
	}}
}

func ownKeyfileReaders(readers ...io.ReadCloser) []*KeyfileReader {
	owned := make([]*KeyfileReader, len(readers))
	for i, reader := range readers {
		owned[i] = OwnKeyfileReader(reader)
	}
	return owned
}

type nonComparableReadCloser struct {
	marker []byte
	reader *trackedReadCloser
}

func (reader nonComparableReadCloser) Read(p []byte) (int, error) {
	return reader.reader.Read(p)
}

func (reader nonComparableReadCloser) Close() error {
	return reader.reader.Close()
}

type comparableReaderWrapper struct {
	io.ReadCloser
}

func interfaceComparisonPanics(left, right any) (panicked bool) {
	defer func() {
		panicked = recover() != nil
	}()
	_ = left == right
	return false
}

func literalKeyfileDigest(data []byte) [32]byte {
	h := sha3.New256()
	_, _ = h.Write([]byte(testKeyfileDomain))
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func requireFactorCode(t *testing.T, err error, want FactorErrorCode) *FactorError {
	t.Helper()
	var factorErr *FactorError
	if !errors.As(err, &factorErr) {
		t.Fatalf("error = %T %v; want *FactorError code %d", err, err, want)
	}
	if factorErr.Code != want {
		t.Fatalf("factor error code = %d; want %d (error %v)", factorErr.Code, want, err)
	}
	return factorErr
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func descriptorsZero(descriptors []FactorDescriptor) bool {
	for i := range descriptors {
		if descriptors[i].digest != nil && descriptors[i].digest.Len() != 0 {
			return false
		}
	}
	return true
}

func descriptorDigestEqual(descriptor FactorDescriptor, want [32]byte) bool {
	return descriptor.digest != nil && bytes.Equal(descriptor.digest.Bytes(), want[:])
}

func digestCopyZero(digests [][32]byte) bool {
	for i := range digests {
		if !allZero(digests[i][:]) {
			return false
		}
	}
	return true
}

func TestFactorRequestCloseReleasesUnconsumedOwnership(t *testing.T) {
	passwordAlias := []byte("TEST ONLY unconsumed password")
	closeCanary := "TEST ONLY private close failure"
	reader := newChunkedReadCloser([]byte("TEST ONLY unread keyfile"), 4)
	reader.closeErr = errors.New(closeCanary)
	request := &FactorRequest{
		Mode:           CredentialModePasswordAndKeyfiles,
		KeyfileMode:    KeyfileModeOrdered,
		ExpectedPolicy: FactorPolicyPasswordAndKeyfiles,
		Password:       passwordAlias,
		Keyfiles:       ownKeyfileReaders(reader),
	}

	err := request.Close()
	var factorErr *FactorError
	if !errors.As(err, &factorErr) || factorErr.Code != FactorErrorClose {
		t.Fatalf("FactorRequest.Close error = %v; want close classification", err)
	}
	if strings.Contains(fmt.Sprintf("%v", err), closeCanary) {
		t.Fatal("FactorRequest.Close disclosed the underlying close failure")
	}
	if err := request.Close(); err != nil {
		t.Fatalf("second FactorRequest.Close = %v; want nil", err)
	}
	if request.Password != nil || request.Keyfiles != nil || !allZero(passwordAlias) {
		t.Fatal("FactorRequest.Close retained transferred factor ownership")
	}
	if reader.readCalls != 0 || reader.closeCalls != 1 {
		t.Fatalf(
			"FactorRequest.Close keyfile reads/closes = %d/%d; want 0/1",
			reader.readCalls,
			reader.closeCalls,
		)
	}
}

func TestFactorModeMatrix(t *testing.T) {
	if CredentialModePasswordOnly != 0x01 ||
		CredentialModeKeyfilesOnly != 0x02 ||
		CredentialModePasswordAndKeyfiles != 0x03 {
		t.Fatal("credential mode wire values changed")
	}
	if KeyfileModeNone != 0x00 ||
		KeyfileModeOrdered != 0x01 ||
		KeyfileModeUnordered != 0x02 {
		t.Fatal("keyfile mode wire values changed")
	}
	if FactorPolicyPasswordOnly != 0x01 ||
		FactorPolicyKeyfilesOnly != 0x02 ||
		FactorPolicyPasswordAndKeyfiles != 0x03 {
		t.Fatal("factor policy values changed")
	}

	tests := []struct {
		name      string
		mode      CredentialMode
		keyMode   KeyfileMode
		policy    FactorPolicy
		password  string
		keyfiles  []string
		wantCode  FactorErrorCode
		wantValid bool
	}{
		{
			name: "password only",
			mode: CredentialModePasswordOnly, keyMode: KeyfileModeNone,
			policy: FactorPolicyPasswordOnly, password: "password",
			wantValid: true,
		},
		{
			name: "keyfiles only ordered",
			mode: CredentialModeKeyfilesOnly, keyMode: KeyfileModeOrdered,
			policy: FactorPolicyKeyfilesOnly, keyfiles: []string{"alpha"},
			wantValid: true,
		},
		{
			name: "keyfiles only unordered",
			mode: CredentialModeKeyfilesOnly, keyMode: KeyfileModeUnordered,
			policy: FactorPolicyKeyfilesOnly, keyfiles: []string{"alpha"},
			wantValid: true,
		},
		{
			name: "combined ordered",
			mode: CredentialModePasswordAndKeyfiles, keyMode: KeyfileModeOrdered,
			policy: FactorPolicyPasswordAndKeyfiles, password: "password",
			keyfiles: []string{"alpha"}, wantValid: true,
		},
		{
			name: "combined unordered",
			mode: CredentialModePasswordAndKeyfiles, keyMode: KeyfileModeUnordered,
			policy: FactorPolicyPasswordAndKeyfiles, password: "password",
			keyfiles: []string{"alpha"}, wantValid: true,
		},
		{
			name: "unknown credential mode",
			mode: 0xff, keyMode: KeyfileModeNone,
			policy: FactorPolicyPasswordOnly, password: "password",
			wantCode: FactorErrorInvalidMode,
		},
		{
			name: "unknown keyfile mode",
			mode: CredentialModePasswordOnly, keyMode: 0xff,
			policy: FactorPolicyPasswordOnly, password: "password",
			wantCode: FactorErrorInvalidMode,
		},
		{
			name: "unknown policy",
			mode: CredentialModePasswordOnly, keyMode: KeyfileModeNone,
			policy: 0xff, password: "password",
			wantCode: FactorErrorInvalidPolicy,
		},
		{
			name: "password mode without password",
			mode: CredentialModePasswordOnly, keyMode: KeyfileModeNone,
			policy:   FactorPolicyPasswordOnly,
			wantCode: FactorErrorInvalidCombination,
		},
		{
			name: "password mode with keyfile",
			mode: CredentialModePasswordOnly, keyMode: KeyfileModeOrdered,
			policy: FactorPolicyPasswordOnly, password: "password",
			keyfiles: []string{"alpha"}, wantCode: FactorErrorInvalidCombination,
		},
		{
			name: "keyfile mode with password",
			mode: CredentialModeKeyfilesOnly, keyMode: KeyfileModeOrdered,
			policy: FactorPolicyKeyfilesOnly, password: "password",
			keyfiles: []string{"alpha"}, wantCode: FactorErrorInvalidCombination,
		},
		{
			name: "keyfile mode without keyfile",
			mode: CredentialModeKeyfilesOnly, keyMode: KeyfileModeOrdered,
			policy: FactorPolicyKeyfilesOnly, wantCode: FactorErrorInvalidCombination,
		},
		{
			name: "combined mode without password",
			mode: CredentialModePasswordAndKeyfiles, keyMode: KeyfileModeOrdered,
			policy: FactorPolicyPasswordAndKeyfiles, keyfiles: []string{"alpha"},
			wantCode: FactorErrorInvalidCombination,
		},
		{
			name: "combined mode without keyfile",
			mode: CredentialModePasswordAndKeyfiles, keyMode: KeyfileModeNone,
			policy: FactorPolicyPasswordAndKeyfiles, password: "password",
			wantCode: FactorErrorInvalidCombination,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			password := []byte(test.password)
			passwordAlias := password
			readers := make([]*trackedReadCloser, len(test.keyfiles))
			keyfiles := make([]*KeyfileReader, len(test.keyfiles))
			for i, contents := range test.keyfiles {
				readers[i] = newChunkedReadCloser([]byte(contents), 2)
				keyfiles[i] = OwnKeyfileReader(readers[i])
			}
			request := &FactorRequest{
				Mode: test.mode, KeyfileMode: test.keyMode,
				ExpectedPolicy: test.policy, Password: password, Keyfiles: keyfiles,
			}
			callbackCalls := 0
			err := WithValidatedFactors(context.Background(), request, func(got *ValidatedFactors) error {
				callbackCalls++
				if got.mode != test.mode || got.keyfileMode != test.keyMode ||
					got.expectedPolicy != test.policy {
					t.Fatalf("validated modes/policy = (%d,%d,%d); want (%d,%d,%d)",
						got.mode, got.keyfileMode, got.expectedPolicy,
						test.mode, test.keyMode, test.policy)
				}
				if len(got.descriptors) != len(test.keyfiles) {
					t.Fatalf("descriptor count = %d; want %d", len(got.descriptors), len(test.keyfiles))
				}
				return nil
			})

			if test.wantValid {
				if err != nil {
					t.Fatalf("valid factor request failed: %v", err)
				}
				if callbackCalls != 1 {
					t.Fatalf("callback calls = %d; want 1", callbackCalls)
				}
			} else {
				requireFactorCode(t, err, test.wantCode)
				if callbackCalls != 0 {
					t.Fatalf("callback calls = %d; invalid factors must not publish", callbackCalls)
				}
			}
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
		})
	}
}

func TestFactorBoundsBeforeRead(t *testing.T) {
	t.Run("password pre-normalization bound", func(t *testing.T) {
		password := bytes.Repeat([]byte{0x41}, (1<<20)+1)
		passwordAlias := password
		reader := newChunkedReadCloser([]byte("keyfile"), 2)
		request := &FactorRequest{
			Mode: CredentialModePasswordAndKeyfiles, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyPasswordAndKeyfiles,
			Password:       password, Keyfiles: ownKeyfileReaders(reader),
		}
		callbackCalls := 0
		err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error {
			callbackCalls++
			return nil
		})
		requireFactorCode(t, err, FactorErrorPasswordLength)
		if callbackCalls != 0 || reader.readCalls != 0 {
			t.Fatalf("callback/read calls = %d/%d; want 0/0", callbackCalls, reader.readCalls)
		}
		if reader.closeCalls != 1 || !allZero(passwordAlias) {
			t.Fatal("pre-read bound rejection did not clean owned inputs")
		}
	})

	t.Run("keyfile count bound", func(t *testing.T) {
		readers := make([]*trackedReadCloser, 65)
		keyfiles := make([]*KeyfileReader, 65)
		for i := range readers {
			readers[i] = newChunkedReadCloser([]byte{byte(i)}, 1)
			keyfiles[i] = OwnKeyfileReader(readers[i])
		}
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly, Keyfiles: keyfiles,
		}
		err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error {
			t.Fatal("callback ran for 65 keyfiles")
			return nil
		})
		requireFactorCode(t, err, FactorErrorKeyfileCount)
		for i, reader := range readers {
			if reader.readCalls != 0 || reader.closeCalls != 1 {
				t.Fatalf("reader %d read/close calls = %d/%d; want 0/1",
					i, reader.readCalls, reader.closeCalls)
			}
		}
	})

	t.Run("nil reader rejected before any read", func(t *testing.T) {
		reader := newChunkedReadCloser([]byte("unread"), 2)
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(reader, nil),
		}
		err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error {
			t.Fatal("callback ran with a nil reader")
			return nil
		})
		requireFactorCode(t, err, FactorErrorNilReader)
		if reader.readCalls != 0 || reader.closeCalls != 1 {
			t.Fatalf("valid reader read/close calls = %d/%d; want 0/1",
				reader.readCalls, reader.closeCalls)
		}
	})

	t.Run("typed nil reader rejected before any read", func(t *testing.T) {
		var reader *trackedReadCloser
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(reader),
		}
		err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error {
			t.Fatal("callback ran with a typed nil reader")
			return nil
		})
		requireFactorCode(t, err, FactorErrorNilReader)
	})

	t.Run("repeated reader identity rejected before any read", func(t *testing.T) {
		reader := newChunkedReadCloser([]byte("one-owned-descriptor"), 2)
		raw := comparableReaderWrapper{ReadCloser: nonComparableReadCloser{
			marker: []byte{0xa5},
			reader: reader,
		}}
		if !interfaceComparisonPanics(raw, raw) {
			t.Fatal("test fixture no longer exposes the unsafe interface-comparison case")
		}
		ownedReader := OwnKeyfileReader(raw)
		copiedHandle := *ownedReader
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       []*KeyfileReader{ownedReader, &copiedHandle},
		}
		err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error {
			t.Fatal("callback ran for a repeated reader identity")
			return nil
		})
		requireFactorCode(t, err, FactorErrorDuplicate)
		if reader.readCalls != 0 || reader.closeCalls != 1 {
			t.Fatalf("repeated reader read/close calls = %d/%d; want 0/1",
				reader.readCalls, reader.closeCalls)
		}
	})
}

func TestFactorDigestOnce(t *testing.T) {
	reader := newChunkedReadCloser([]byte("alpha-keyfile"), 1)
	request := &FactorRequest{
		Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
		ExpectedPolicy: FactorPolicyKeyfilesOnly,
		Keyfiles:       ownKeyfileReaders(reader),
	}
	want := literalKeyfileDigest([]byte("alpha-keyfile"))
	callbackCalls := 0
	var scratchBorrow []byte
	err := withValidatedFactors(
		context.Background(),
		request,
		func(got *ValidatedFactors) error {
			callbackCalls++
			if reader.closeCalls != 1 {
				t.Fatalf("reader close calls at publication = %d; want 1", reader.closeCalls)
			}
			if len(got.descriptors) != 1 {
				t.Fatalf("descriptor count = %d; want 1", len(got.descriptors))
			}
			if !descriptorDigestEqual(got.descriptors[0], want) {
				t.Fatalf("digest = %x; want literal %x", got.descriptors[0].digest.Bytes(), want)
			}
			return nil
		},
		&factorHooks{observeScratch: func(scratch []byte) {
			scratchBorrow = scratch
		}},
	)
	if err != nil {
		t.Fatalf("digest request failed: %v", err)
	}
	if callbackCalls != 1 || reader.bytesRead != len("alpha-keyfile") ||
		reader.closeCalls != 1 {
		t.Fatalf("callback/bytes/close = %d/%d/%d; want 1/%d/1",
			callbackCalls, reader.bytesRead, reader.closeCalls, len("alpha-keyfile"))
	}
	if len(scratchBorrow) != keyfileScratchBytes || !allZero(scratchBorrow) {
		t.Fatal("scratch buffer retained keyfile bytes after success")
	}
}

func TestFactorReaderContract(t *testing.T) {
	t.Run("owner handle close is idempotent", func(t *testing.T) {
		reader := newChunkedReadCloser([]byte("unused"), 1)
		handle := OwnKeyfileReader(reader)
		if err := handle.Close(); err != nil {
			t.Fatalf("first owner close failed: %v", err)
		}
		if err := handle.Close(); err != nil {
			t.Fatalf("second owner close failed: %v", err)
		}
		if reader.readCalls != 0 || reader.closeCalls != 1 {
			t.Fatalf("reader read/close calls = %d/%d; want 0/1",
				reader.readCalls, reader.closeCalls)
		}
	})

	t.Run("ordinary short reads", func(t *testing.T) {
		reader := newChunkedReadCloser([]byte("short-reads"), 1)
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(reader),
		}
		want := literalKeyfileDigest([]byte("short-reads"))
		err := WithValidatedFactors(context.Background(), request, func(got *ValidatedFactors) error {
			if !descriptorDigestEqual(got.descriptors[0], want) {
				t.Fatalf("short-read digest = %x; want %x",
					got.descriptors[0].digest.Bytes(), want)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("ordinary short reads failed: %v", err)
		}
		if reader.readCalls <= 2 {
			t.Fatalf("read calls = %d; test did not exercise short reads", reader.readCalls)
		}
		if reader.closeCalls != 1 {
			t.Fatalf("reader close calls = %d; want 1", reader.closeCalls)
		}
	})

	t.Run("bytes with EOF are processed", func(t *testing.T) {
		called := false
		reader := &trackedReadCloser{readFn: func(p []byte) (int, error) {
			if called {
				return 0, errors.New("read after terminal EOF")
			}
			called = true
			return copy(p, []byte("terminal")), io.EOF
		}}
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(reader),
		}
		want := literalKeyfileDigest([]byte("terminal"))
		err := WithValidatedFactors(context.Background(), request, func(got *ValidatedFactors) error {
			if !descriptorDigestEqual(got.descriptors[0], want) {
				t.Fatalf("terminal digest = %x; want %x",
					got.descriptors[0].digest.Bytes(), want)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("n>0 with EOF failed: %v", err)
		}
		if reader.readCalls != 1 || reader.bytesRead != len("terminal") {
			t.Fatalf("read calls/bytes = %d/%d; want 1/%d",
				reader.readCalls, reader.bytesRead, len("terminal"))
		}
		if reader.closeCalls != 1 {
			t.Fatalf("reader close calls = %d; want 1", reader.closeCalls)
		}
	})

	t.Run("bytes with non-EOF error fail after processing", func(t *testing.T) {
		sentinel := errors.New("private-read-error")
		called := false
		reader := &trackedReadCloser{readFn: func(p []byte) (int, error) {
			if called {
				return 0, io.EOF
			}
			called = true
			return copy(p, []byte("accepted-first")), sentinel
		}}
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(reader),
		}
		callbackCalls := 0
		processedChunk := false
		processedDigest := false
		var scratchBorrow []byte
		wantDigest := literalKeyfileDigest([]byte("accepted-first"))
		err := withValidatedFactors(
			context.Background(),
			request,
			func(*ValidatedFactors) error {
				callbackCalls++
				return nil
			},
			&factorHooks{
				observeScratch: func(scratch []byte) {
					scratchBorrow = scratch
				},
				observeProcessedChunk: func(index int, chunk, digest []byte) {
					processedChunk = index == 0 &&
						bytes.Equal(chunk, []byte("accepted-first"))
					processedDigest = bytes.Equal(digest, wantDigest[:])
				},
			},
		)
		requireFactorCode(t, err, FactorErrorRead)
		if callbackCalls != 0 || !processedChunk || !processedDigest {
			t.Fatalf("callback/chunk/digest = %d/%t/%t; want 0/true/true",
				callbackCalls, processedChunk, processedDigest)
		}
		if errors.Is(err, sentinel) {
			t.Fatal("private reader error escaped through error chain")
		}
		if reader.closeCalls != 1 {
			t.Fatalf("reader close calls = %d; want 1", reader.closeCalls)
		}
		if len(scratchBorrow) != keyfileScratchBytes || !allZero(scratchBorrow) {
			t.Fatal("scratch buffer retained bytes after a terminal read error")
		}
	})

	t.Run("later read failure clears prior digest and closes every reader", func(t *testing.T) {
		first := newChunkedReadCloser([]byte("first-keyfile"), 2)
		second := newImmediateErrorReadCloser(errors.New("private-second-read-error"))
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(first, second),
		}
		callbackCalls := 0
		var firstDigestBorrow []byte
		var scratchBorrow []byte
		err := withValidatedFactors(
			context.Background(),
			request,
			func(*ValidatedFactors) error {
				callbackCalls++
				return nil
			},
			&factorHooks{
				observeScratch: func(scratch []byte) {
					scratchBorrow = scratch
				},
				observeDescriptorDigest: func(index int, digest []byte) {
					if index == 0 {
						firstDigestBorrow = digest
					}
				},
			},
		)
		requireFactorCode(t, err, FactorErrorRead)
		if callbackCalls != 0 || first.closeCalls != 1 || second.closeCalls != 1 {
			t.Fatalf("callback/first close/second close = %d/%d/%d; want 0/1/1",
				callbackCalls, first.closeCalls, second.closeCalls)
		}
		if len(firstDigestBorrow) != 32 || !allZero(firstDigestBorrow) {
			t.Fatal("earlier descriptor digest survived a later reader failure")
		}
		if len(scratchBorrow) != keyfileScratchBytes || !allZero(scratchBorrow) {
			t.Fatal("scratch buffer survived a later reader failure")
		}
	})

	t.Run("scratch is cleared between readers", func(t *testing.T) {
		first := &trackedReadCloser{readFn: func(p []byte) (int, error) {
			for i := range p {
				p[i] = 0xa5
			}
			return 1, io.EOF
		}}
		dirtyTailObserved := false
		second := &trackedReadCloser{readFn: func(p []byte) (int, error) {
			dirtyTailObserved = !allZero(p)
			return copy(p, []byte("second-keyfile")), io.EOF
		}}
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(first, second),
		}
		err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error {
			return nil
		})
		if err != nil {
			t.Fatalf("distinct keyfiles failed: %v", err)
		}
		if dirtyTailObserved {
			t.Fatal("second reader observed bytes left in the shared scratch buffer")
		}
		if first.closeCalls != 1 || second.closeCalls != 1 {
			t.Fatalf("first/second close calls = %d/%d; want 1/1",
				first.closeCalls, second.closeCalls)
		}
	})

	t.Run("persistent no progress fails", func(t *testing.T) {
		reader := &trackedReadCloser{readFn: func([]byte) (int, error) {
			return 0, nil
		}}
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(reader),
		}
		callbackCalls := 0
		err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error {
			callbackCalls++
			return nil
		})
		requireFactorCode(t, err, FactorErrorNoProgress)
		if callbackCalls != 0 || reader.readCalls < 2 || reader.readCalls > 256 {
			t.Fatalf("callback/read calls = %d/%d; want 0 and bounded repeated reads",
				callbackCalls, reader.readCalls)
		}
		if reader.closeCalls != 1 {
			t.Fatalf("reader close calls = %d; want 1", reader.closeCalls)
		}
	})

	t.Run("reader count contract is enforced", func(t *testing.T) {
		reader := &trackedReadCloser{readFn: func(p []byte) (int, error) {
			return len(p) + 1, nil
		}}
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(reader),
		}
		err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error {
			t.Fatal("callback ran after invalid reader count")
			return nil
		})
		requireFactorCode(t, err, FactorErrorReaderContract)
		if reader.closeCalls != 1 {
			t.Fatalf("reader close calls = %d; want 1", reader.closeCalls)
		}
	})

	t.Run("reader panic is redacted", func(t *testing.T) {
		reader := &trackedReadCloser{readFn: func(p []byte) (int, error) {
			copy(p, []byte("panic-left-in-scratch"))
			panic("private-reader-panic")
		}}
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(reader),
		}
		var scratchBorrow []byte
		err := withValidatedFactors(
			context.Background(),
			request,
			func(*ValidatedFactors) error {
				t.Fatal("callback ran after reader panic")
				return nil
			},
			&factorHooks{observeScratch: func(scratch []byte) {
				scratchBorrow = scratch
			}},
		)
		requireFactorCode(t, err, FactorErrorRead)
		if strings.Contains(fmt.Sprintf("%+v", err), "private-reader-panic") {
			t.Fatal("reader panic sentinel escaped through diagnostics")
		}
		if reader.closeCalls != 1 {
			t.Fatalf("reader close calls = %d; want 1", reader.closeCalls)
		}
		if len(scratchBorrow) != keyfileScratchBytes || !allZero(scratchBorrow) {
			t.Fatal("scratch buffer retained bytes written before a reader panic")
		}
	})

	t.Run("close failure still closes every reader exactly once", func(t *testing.T) {
		tests := []struct {
			name      string
			sentinel  string
			configure func(*trackedReadCloser)
		}{
			{
				name:     "error",
				sentinel: "private-close-error",
				configure: func(reader *trackedReadCloser) {
					reader.closeErr = errors.New("private-close-error")
				},
			},
			{
				name:     "panic",
				sentinel: "private-close-panic",
				configure: func(reader *trackedReadCloser) {
					reader.closeFn = func() error {
						panic("private-close-panic")
					}
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				first := newChunkedReadCloser([]byte("first-close"), 2)
				second := newChunkedReadCloser([]byte("second-close"), 2)
				test.configure(first)
				firstHandle := OwnKeyfileReader(first)
				secondHandle := OwnKeyfileReader(second)
				request := &FactorRequest{
					Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
					ExpectedPolicy: FactorPolicyKeyfilesOnly,
					Keyfiles:       []*KeyfileReader{firstHandle, secondHandle},
				}
				callbackCalls := 0
				err := WithValidatedFactors(
					context.Background(),
					request,
					func(*ValidatedFactors) error {
						callbackCalls++
						return nil
					},
				)
				factorErr := requireFactorCode(t, err, FactorErrorClose)
				if factorErr.Index != 0 {
					t.Fatalf("close failure index = %d; want 0", factorErr.Index)
				}
				if callbackCalls != 0 || first.closeCalls != 1 || second.closeCalls != 1 {
					t.Fatalf("callback/first close/second close = %d/%d/%d; want 0/1/1",
						callbackCalls, first.closeCalls, second.closeCalls)
				}
				if closeErr := firstHandle.Close(); closeErr != nil {
					t.Fatalf("idempotent first-handle close failed: %v", closeErr)
				}
				if closeErr := secondHandle.Close(); closeErr != nil {
					t.Fatalf("idempotent second-handle close failed: %v", closeErr)
				}
				if first.closeCalls != 1 || second.closeCalls != 1 {
					t.Fatalf("repeated handle close retried underlying close: %d/%d",
						first.closeCalls, second.closeCalls)
				}
				if strings.Contains(fmt.Sprintf("%+v", err), test.sentinel) {
					t.Fatalf("close failure disclosed private sentinel %q", test.sentinel)
				}
			})
		}
	})

	t.Run("pre-read cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		reader := newChunkedReadCloser([]byte("unread"), 1)
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(reader),
		}
		err := WithValidatedFactors(ctx, request, func(*ValidatedFactors) error {
			t.Fatal("callback ran after cancellation")
			return nil
		})
		requireFactorCode(t, err, FactorErrorCancelled)
		if reader.readCalls != 0 || reader.closeCalls != 1 {
			t.Fatalf("cancelled reader read/close = %d/%d; want 0/1",
				reader.readCalls, reader.closeCalls)
		}
	})

	t.Run("mid-stream cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		read := false
		reader := &trackedReadCloser{readFn: func(p []byte) (int, error) {
			if read {
				return 0, errors.New("read continued after cancellation")
			}
			read = true
			n := copy(p, []byte("partial"))
			cancel()
			return n, nil
		}}
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(reader),
		}
		callbackCalls := 0
		var scratchBorrow []byte
		err := withValidatedFactors(
			ctx,
			request,
			func(*ValidatedFactors) error {
				callbackCalls++
				return nil
			},
			&factorHooks{observeScratch: func(scratch []byte) {
				scratchBorrow = scratch
			}},
		)
		requireFactorCode(t, err, FactorErrorCancelled)
		if callbackCalls != 0 || reader.readCalls != 1 ||
			reader.bytesRead != len("partial") || reader.closeCalls != 1 {
			t.Fatalf("callback/read/bytes/close = %d/%d/%d/%d; want 0/1/%d/1",
				callbackCalls, reader.readCalls, reader.bytesRead, reader.closeCalls,
				len("partial"))
		}
		if len(scratchBorrow) != keyfileScratchBytes || !allZero(scratchBorrow) {
			t.Fatal("scratch buffer retained bytes after mid-stream cancellation")
		}
	})

	t.Run("cancellation during close blocks publication", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		reader := newChunkedReadCloser([]byte("close-cancels"), 2)
		reader.closeFn = func() error {
			cancel()
			return nil
		}
		request := &FactorRequest{
			Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
			ExpectedPolicy: FactorPolicyKeyfilesOnly,
			Keyfiles:       ownKeyfileReaders(reader),
		}
		callbackCalls := 0
		err := WithValidatedFactors(ctx, request, func(*ValidatedFactors) error {
			callbackCalls++
			return nil
		})
		requireFactorCode(t, err, FactorErrorCancelled)
		if callbackCalls != 0 || reader.closeCalls != 1 {
			t.Fatalf("callback/close calls = %d/%d; want 0/1",
				callbackCalls, reader.closeCalls)
		}
	})
}

func TestFactorDuplicatePreservesOrder(t *testing.T) {
	inputs := [][]byte{[]byte("bravo"), []byte("alpha"), []byte("charlie")}
	readers := make([]*KeyfileReader, len(inputs))
	for i := range inputs {
		readers[i] = OwnKeyfileReader(newChunkedReadCloser(inputs[i], 2))
	}
	request := &FactorRequest{
		Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
		ExpectedPolicy: FactorPolicyKeyfilesOnly, Keyfiles: readers,
	}
	err := WithValidatedFactors(context.Background(), request, func(got *ValidatedFactors) error {
		if len(got.descriptors) != len(inputs) {
			t.Fatalf("descriptor count = %d; want %d", len(got.descriptors), len(inputs))
		}
		for i := range inputs {
			want := literalKeyfileDigest(inputs[i])
			if !descriptorDigestEqual(got.descriptors[i], want) {
				t.Fatalf("descriptor %d = %x; want input-order digest %x",
					i, got.descriptors[i].digest.Bytes(), want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ordered distinct factors failed: %v", err)
	}
}

func TestFactorNonAdjacentDuplicateABA(t *testing.T) {
	inputs := [][]byte{[]byte("alpha"), []byte("bravo"), []byte("alpha")}
	readers := make([]*KeyfileReader, len(inputs))
	for i := range inputs {
		readers[i] = OwnKeyfileReader(newChunkedReadCloser(inputs[i], 1))
	}
	request := &FactorRequest{
		Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
		ExpectedPolicy: FactorPolicyKeyfilesOnly, Keyfiles: readers,
	}
	callbackCalls := 0
	err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error {
		callbackCalls++
		return nil
	})
	if callbackCalls != 0 {
		t.Fatalf("callback calls = %d; duplicate A,B,A must not publish", callbackCalls)
	}
	requireFactorCode(t, err, FactorErrorDuplicate)
}

func TestFactorSortedDuplicateCopyCleared(t *testing.T) {
	callbackErr := errors.New("callback failure")
	tests := []struct {
		name     string
		inputs   [][]byte
		callback func(*ValidatedFactors) error
		wantCode FactorErrorCode
		wantErr  error
	}{
		{
			name: "success",
			inputs: [][]byte{
				[]byte("bravo"), []byte("alpha"), []byte("charlie"),
			},
			callback: func(*ValidatedFactors) error { return nil },
		},
		{
			name: "duplicate rejection",
			inputs: [][]byte{
				[]byte("alpha"), []byte("bravo"), []byte("alpha"),
			},
			callback: func(*ValidatedFactors) error {
				t.Fatal("callback ran for duplicate factors")
				return nil
			},
			wantCode: FactorErrorDuplicate,
		},
		{
			name: "callback error",
			inputs: [][]byte{
				[]byte("bravo"), []byte("alpha"), []byte("charlie"),
			},
			callback: func(*ValidatedFactors) error { return callbackErr },
			wantErr:  callbackErr,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			readers := make([]*KeyfileReader, len(test.inputs))
			for i := range test.inputs {
				readers[i] = OwnKeyfileReader(newChunkedReadCloser(test.inputs[i], 2))
			}
			request := &FactorRequest{
				Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeOrdered,
				ExpectedPolicy: FactorPolicyKeyfilesOnly, Keyfiles: readers,
			}
			var retained [][32]byte
			hooks := &factorHooks{observeSortedCopy: func(sorted [][32]byte) {
				retained = sorted
			}}
			err := withValidatedFactors(
				context.Background(),
				request,
				func(got *ValidatedFactors) error {
					if len(retained) != len(test.inputs) {
						t.Fatalf("observed sorted-copy length = %d; want %d",
							len(retained), len(test.inputs))
					}
					if digestCopyZero(retained) {
						t.Fatal("sorted duplicate copy was already zero during validation")
					}
					return test.callback(got)
				},
				hooks,
			)
			if test.wantCode != 0 {
				requireFactorCode(t, err, test.wantCode)
			} else if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("error = %v; want callback error", err)
				}
			} else if err != nil {
				t.Fatalf("factor validation failed: %v", err)
			}
			if len(retained) != len(test.inputs) || !digestCopyZero(retained) {
				t.Fatal("sorted duplicate-detection copy was not cleared after exit")
			}
		})
	}
}

func TestFactorPolicyMismatchPreKDF(t *testing.T) {
	password := []byte("policy-password")
	passwordAlias := password
	reader := newChunkedReadCloser([]byte("unread-keyfile"), 2)
	request := &FactorRequest{
		Mode: CredentialModePasswordAndKeyfiles, KeyfileMode: KeyfileModeOrdered,
		ExpectedPolicy: FactorPolicyPasswordOnly,
		Password:       password, Keyfiles: ownKeyfileReaders(reader),
	}
	callbackCalls := 0
	err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error {
		callbackCalls++
		return nil
	})
	requireFactorCode(t, err, FactorErrorPolicyMismatch)
	if callbackCalls != 0 || reader.readCalls != 0 {
		t.Fatalf("callback/read calls = %d/%d; policy mismatch must fail before KDF/read",
			callbackCalls, reader.readCalls)
	}
	if reader.closeCalls != 1 || !allZero(passwordAlias) {
		t.Fatal("policy mismatch did not clean transferred factors")
	}
}

func TestFactorOwnershipAllExits(t *testing.T) {
	type outcome struct {
		name           string
		configure      func(context.Context, *FactorRequest, *trackedReadCloser) context.Context
		callback       func(*ValidatedFactors) error
		forbidCallback bool
		nilCallback    bool
		wantCode       FactorErrorCode
		wantErr        error
		wantPanic      string
	}

	callbackErr := errors.New("callback-error")
	tests := []outcome{
		{name: "success", callback: func(*ValidatedFactors) error { return nil }},
		{
			name: "validation failure",
			configure: func(ctx context.Context, request *FactorRequest, _ *trackedReadCloser) context.Context {
				request.ExpectedPolicy = FactorPolicyPasswordOnly
				return ctx
			},
			callback: func(*ValidatedFactors) error {
				t.Fatal("callback ran after validation failure")
				return nil
			},
			wantCode: FactorErrorPolicyMismatch,
		},
		{
			name: "nil context",
			configure: func(
				context.Context,
				*FactorRequest,
				*trackedReadCloser,
			) context.Context {
				return nil
			},
			callback: func(*ValidatedFactors) error {
				t.Fatal("callback ran with a nil context")
				return nil
			},
			forbidCallback: true,
			wantCode:       FactorErrorInvalidRequest,
		},
		{
			name:        "nil callback",
			nilCallback: true,
			wantCode:    FactorErrorInvalidRequest,
		},
		{
			name: "read failure",
			configure: func(ctx context.Context, _ *FactorRequest, reader *trackedReadCloser) context.Context {
				reader.readFn = func([]byte) (int, error) {
					return 0, errors.New("private-read-failure")
				}
				return ctx
			},
			callback: func(*ValidatedFactors) error {
				t.Fatal("callback ran after read failure")
				return nil
			},
			wantCode: FactorErrorRead,
		},
		{
			name: "cancellation",
			configure: func(ctx context.Context, _ *FactorRequest, _ *trackedReadCloser) context.Context {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				return cancelled
			},
			callback: func(*ValidatedFactors) error {
				t.Fatal("callback ran after cancellation")
				return nil
			},
			wantCode: FactorErrorCancelled,
		},
		{
			name:     "callback error",
			callback: func(*ValidatedFactors) error { return callbackErr },
			wantErr:  callbackErr,
		},
		{
			name:      "callback panic",
			callback:  func(*ValidatedFactors) error { panic("callback-panic") },
			wantPanic: "callback-panic",
		},
		{
			name: "close failure",
			configure: func(ctx context.Context, _ *FactorRequest, reader *trackedReadCloser) context.Context {
				reader.closeErr = errors.New("private-close-failure")
				return ctx
			},
			forbidCallback: true,
			wantCode:       FactorErrorClose,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			password := []byte("owned-password")
			passwordAlias := password
			reader := newChunkedReadCloser([]byte("owned-keyfile"), 2)
			request := &FactorRequest{
				Mode: CredentialModePasswordAndKeyfiles, KeyfileMode: KeyfileModeOrdered,
				ExpectedPolicy: FactorPolicyPasswordAndKeyfiles,
				Password:       password, Keyfiles: ownKeyfileReaders(reader),
			}
			ctx := context.Background()
			if test.configure != nil {
				ctx = test.configure(ctx, request, reader)
			}

			var passwordBorrow []byte
			var descriptorBorrow []FactorDescriptor
			var descriptorBackingBorrows [][]byte
			var descriptorDigestHandle any
			var descriptorDigestBacking []byte
			var callback func(*ValidatedFactors) error
			if !test.nilCallback {
				callback = func(got *ValidatedFactors) error {
					if test.forbidCallback {
						t.Fatal("callback ran before all reader closes succeeded")
					}
					passwordBorrow = got.password.Bytes()
					descriptorBorrow = got.descriptors
					descriptorBackingBorrows = make([][]byte, len(got.descriptors))
					for i := range got.descriptors {
						descriptorBackingBorrows[i] = got.descriptors[i].digest.Bytes()
					}
					descriptorCopy := got.descriptors[0]
					descriptorDigestHandle = any(descriptorCopy.digest)
					if digestOwner, ok := descriptorDigestHandle.(*pcsecret.Secret); ok {
						descriptorDigestBacking = digestOwner.Bytes()
					}
					return test.callback(got)
				}
			}

			var err error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				err = WithValidatedFactors(ctx, request, callback)
			}()

			if test.wantPanic != "" {
				if recovered != test.wantPanic {
					t.Fatalf("panic = %#v; want %q", recovered, test.wantPanic)
				}
			} else if recovered != nil {
				t.Fatalf("unexpected panic: %#v", recovered)
			}
			if test.wantCode != 0 {
				requireFactorCode(t, err, test.wantCode)
			} else if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("error = %v; want callback error", err)
				}
			} else if test.wantPanic == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !allZero(passwordAlias) {
				t.Fatal("password alias retained secret bytes")
			}
			if len(passwordBorrow) > 0 && !allZero(passwordBorrow) {
				t.Fatal("callback password borrow retained secret bytes")
			}
			if len(descriptorBorrow) > 0 && !descriptorsZero(descriptorBorrow) {
				t.Fatal("callback descriptor borrow retained digest bytes")
			}
			for i, digestBorrow := range descriptorBackingBorrows {
				if !allZero(digestBorrow) {
					t.Fatalf("callback descriptor backing %d retained digest bytes", i)
				}
			}
			switch digestHandle := descriptorDigestHandle.(type) {
			case nil:
			case [32]byte:
				if !allZero(digestHandle[:]) {
					t.Fatal("copied descriptor orphaned digest bytes outside owner cleanup")
				}
			case *pcsecret.Secret:
				if digestHandle.Len() != 0 ||
					(len(descriptorDigestBacking) > 0 && !allZero(descriptorDigestBacking)) {
					t.Fatal("copied descriptor handle retained digest bytes after owner cleanup")
				}
			default:
				t.Fatalf("unexpected descriptor digest handle type %T", digestHandle)
			}
			if request.Password != nil || request.Keyfiles != nil {
				t.Fatal("request retained transferred fields")
			}
			if reader.closeCalls != 1 {
				t.Fatalf("reader close calls = %d; want exactly 1", reader.closeCalls)
			}
		})
	}
}

func TestFactorDiagnosticsPublicOnly(t *testing.T) {
	const (
		passwordSentinel = "PASSWORD-SENTINEL-7d497"
		readerSentinel   = "READER-SENTINEL-b4e1a"
		closeSentinel    = "CLOSE-SENTINEL-22f39"
	)

	tests := []struct {
		name     string
		reader   *trackedReadCloser
		wantCode FactorErrorCode
	}{
		{
			name:     "read error",
			reader:   newImmediateErrorReadCloser(errors.New(readerSentinel)),
			wantCode: FactorErrorRead,
		},
		{
			name: "close error",
			reader: func() *trackedReadCloser {
				reader := newChunkedReadCloser([]byte("public-keyfile"), 2)
				reader.closeErr = errors.New(closeSentinel)
				return reader
			}(),
			wantCode: FactorErrorClose,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			password := []byte(passwordSentinel)
			request := &FactorRequest{
				Mode: CredentialModePasswordAndKeyfiles, KeyfileMode: KeyfileModeOrdered,
				ExpectedPolicy: FactorPolicyPasswordAndKeyfiles,
				Password:       password, Keyfiles: ownKeyfileReaders(test.reader),
			}
			err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error {
				if test.wantCode == FactorErrorClose {
					t.Fatal("callback ran before a close failure was reported")
				}
				return nil
			})
			requireFactorCode(t, err, test.wantCode)
			rendered := fmt.Sprintf("%v\n%+v\n%#v", err, err, err)
			for _, sentinel := range []string{passwordSentinel, readerSentinel, closeSentinel} {
				if strings.Contains(rendered, sentinel) {
					t.Fatalf("diagnostics disclosed sentinel %q: %s", sentinel, rendered)
				}
			}
			if !allZero(password) {
				t.Fatal("diagnostic failure left password bytes live")
			}
			if test.reader.closeCalls != 1 {
				t.Fatalf("reader close calls = %d; want 1", test.reader.closeCalls)
			}
		})
	}

	t.Run("secret-bearing structs redact formatting", func(t *testing.T) {
		password := []byte(passwordSentinel)
		keyfile := OwnKeyfileReader(newImmediateErrorReadCloser(errors.New(readerSentinel)))
		request := &FactorRequest{
			Password: password,
			Keyfiles: []*KeyfileReader{keyfile},
		}
		descriptor := FactorDescriptor{
			digest: pcsecret.SecretFrom([]byte(readerSentinel)),
		}
		validated := &ValidatedFactors{
			password:    pcsecret.SecretFrom([]byte(passwordSentinel)),
			descriptors: []FactorDescriptor{descriptor},
		}
		defer validated.password.Close()
		defer descriptor.digest.Close()
		defer keyfile.Close()

		formatCases := []struct {
			name    string
			subject any
			want    string
		}{
			{"keyfile pointer", keyfile, "pcv3credential.KeyfileReader([REDACTED])"},
			{"keyfile value", *keyfile, "pcv3credential.KeyfileReader([REDACTED])"},
			{"request pointer", request, "pcv3credential.FactorRequest([REDACTED])"},
			{"request value", *request, "pcv3credential.FactorRequest([REDACTED])"},
			{"descriptor value", descriptor, "pcv3credential.FactorDescriptor([REDACTED])"},
			{"validated pointer", validated, "pcv3credential.ValidatedFactors([REDACTED])"},
			{"validated value", *validated, "pcv3credential.ValidatedFactors([REDACTED])"},
		}
		for _, formatCase := range formatCases {
			for _, verb := range []string{"%v", "%+v", "%#v"} {
				if rendered := fmt.Sprintf(verb, formatCase.subject); rendered != formatCase.want {
					t.Errorf("%s with %s = %q; want %q",
						formatCase.name, verb, rendered, formatCase.want)
				}
			}
		}
	})
}

func TestCreationRejectsEmptyOwnedKeyfileWithoutChangingReadCompatibility(t *testing.T) {
	for _, creation := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing read transcript", true: "new creation"}[creation], func(t *testing.T) {
			reader := newChunkedReadCloser(nil, 1)
			request := &FactorRequest{Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeUnordered, ExpectedPolicy: FactorPolicyKeyfilesOnly, Keyfiles: ownKeyfileReaders(reader)}
			if creation {
				request.RequireNonemptyKeyfiles()
			}
			called := false
			err := WithValidatedFactors(context.Background(), request, func(*ValidatedFactors) error { called = true; return nil })
			if creation {
				requireFactorCode(t, err, FactorErrorEmptyKeyfile)
				if called {
					t.Fatal("empty creation factor admitted")
				}
			} else if err != nil || !called {
				t.Fatalf("legacy empty-factor transcript changed: %v", err)
			}
			if reader.closeCalls != 1 {
				t.Fatalf("owned empty reader close count=%d", reader.closeCalls)
			}
		})
	}
}
