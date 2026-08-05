//go:build pcv3_private_corpus && pcv3_production_kdf

package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3corpus"
	"Picocrypt-NG/internal/pcv3credential"
	"bytes"
	"context"
	"io"
	"os"
	"testing"
)

const (
	productionKDFPrivateRootEnv    = "PCV3_PRIVATE_CORPUS_ROOT"
	productionKDFPrivateCustodyEnv = "PCV3_PRIVATE_CORPUS_CUSTODY_ID"

	productionKDFOrderedFixture   = "normal-standard-combined-ordered-one"
	productionKDFUnorderedFixture = "normal-paranoid-combined-unordered-rs-small"
)

type productionKDFKeyfileReadCloser struct {
	reader     *bytes.Reader
	ownedBytes []byte
	closeCalls int
}

func (reader *productionKDFKeyfileReadCloser) Read(destination []byte) (int, error) {
	return reader.reader.Read(destination)
}

func (reader *productionKDFKeyfileReadCloser) Close() error {
	reader.closeCalls++
	pcv3crypto.SecureZero(reader.ownedBytes)
	return nil
}

var _ io.ReadCloser = (*productionKDFKeyfileReadCloser)(nil)

func TestReadNormalVolumeProductionKDF(t *testing.T) {
	root, hasRoot := os.LookupEnv(productionKDFPrivateRootEnv)
	if !hasRoot || root == "" {
		t.Fatalf("%s must be set for the private production-KDF reader test", productionKDFPrivateRootEnv)
	}
	custodyID, hasCustodyID := os.LookupEnv(productionKDFPrivateCustodyEnv)
	if !hasCustodyID || custodyID == "" {
		t.Fatalf("%s must be set for the private production-KDF reader test", productionKDFPrivateCustodyEnv)
	}

	err := pcv3corpus.WithNormalVolumeFixtures(
		root,
		custodyID,
		[]string{productionKDFOrderedFixture, productionKDFUnorderedFixture},
		func(fixtures []*pcv3corpus.NormalVolumeFixture) error {
			if len(fixtures) != 2 {
				t.Fatalf("private production-KDF fixture count = %d; want 2", len(fixtures))
			}
			ordered := fixtures[0]
			unordered := fixtures[1]
			for _, test := range []struct {
				name        string
				fixture     *pcv3corpus.NormalVolumeFixture
				reverse     bool
				keyfileMode pcv3credential.KeyfileMode
				wantOutcome Outcome
				wantStage   Stage
				wantCode    Code
				wantAuth    int
				completion  bool
			}{
				{
					name:        "standard ordered manifest order succeeds",
					fixture:     ordered,
					keyfileMode: pcv3credential.KeyfileModeOrdered,
					wantOutcome: OutcomeSuccess,
					wantStage:   StageNone,
					wantCode:    CodeSuccess,
					wantAuth:    2,
					completion:  true,
				},
				{
					name:        "standard ordered reversed keyfiles fail generically",
					fixture:     ordered,
					reverse:     true,
					keyfileMode: pcv3credential.KeyfileModeOrdered,
					wantOutcome: OutcomeCredentialsOrDamage,
					wantStage:   StageWrapAuth,
					wantCode:    CodeCredentialsOrDamage,
					wantAuth:    0,
					completion:  false,
				},
				{
					name:        "paranoid unordered reversed keyfiles succeed",
					fixture:     unordered,
					reverse:     true,
					keyfileMode: pcv3credential.KeyfileModeUnordered,
					wantOutcome: OutcomeSuccess,
					wantStage:   StageNone,
					wantCode:    CodeSuccess,
					wantAuth:    2,
					completion:  true,
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					runNormalReaderProductionKDF(t, test.fixture, test.reverse, test.keyfileMode,
						test.wantOutcome, test.wantStage, test.wantCode, test.wantAuth, test.completion)
				})
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("load private production-KDF normal fixtures: %v", err)
	}
}

func runNormalReaderProductionKDF(
	t *testing.T,
	fixture *pcv3corpus.NormalVolumeFixture,
	reverse bool,
	keyfileMode pcv3credential.KeyfileMode,
	wantOutcome Outcome,
	wantStage Stage,
	wantCode Code,
	wantAuthenticated int,
	wantCompletion bool,
) {
	t.Helper()
	if fixture == nil {
		t.Fatal("private production-KDF fixture is nil")
	}
	volume := fixture.Volume()
	source := &normalBorrowedSource{reader: bytes.NewReader(volume)}
	route, structure, err := Probe(source, int64(len(volume)))
	if err != nil || route != RouteNormalPCV {
		t.Fatalf("Probe(private production-KDF volume) = %v, %v; want normal PCV admission", route, err)
	}

	factors, passwordAlias, keyfiles := newProductionKDFFactors(t, fixture, reverse, keyfileMode)
	provider := &readerCredentialProvider{
		factors:  factors,
		admitter: &literalKDFAdmitter{},
	}
	t.Cleanup(func() {
		provider.close()
		_ = factors.Close()
	})

	sink := &normalFixtureSink{}
	defer sink.abortUncommitted()
	result, completion := readNormalVolumeWithProvider(
		context.Background(), source, int64(len(volume)), structure, provider, sink,
	)
	if result == nil {
		t.Fatal("production-KDF normal reader returned no typed result")
	}
	defer result.Close()

	if result.Outcome() != wantOutcome || result.Stage() != wantStage ||
		result.Code() != wantCode || result.AuthenticatedCapsules() != wantAuthenticated {
		t.Fatalf(
			"production-KDF result = %v/%v/%v/%d; want %v/%v/%v/%d",
			result.Outcome(), result.Stage(), result.Code(), result.AuthenticatedCapsules(),
			wantOutcome, wantStage, wantCode, wantAuthenticated,
		)
	}
	assertNormalCompletion(t, completion, wantCompletion)
	if provider.admitter.(*literalKDFAdmitter).calls != 1 {
		t.Fatalf("production KDF admissions = %d; want one", provider.admitter.(*literalKDFAdmitter).calls)
	}
	if provider.factors != nil || factors.Password != nil || factors.Keyfiles != nil {
		t.Fatal("production-KDF factor request was not consumed")
	}
	if !allZero(passwordAlias) {
		t.Fatal("owned production-KDF password alias survived the reader session")
	}
	for index, keyfile := range keyfiles {
		if keyfile.closeCalls != 1 || !allZero(keyfile.ownedBytes) {
			t.Fatalf("owned production-KDF keyfile %d cleanup = closes %d, zeroed %v; want one and true", index, keyfile.closeCalls, allZero(keyfile.ownedBytes))
		}
	}
	if source.closeCalls != 0 {
		t.Fatalf("borrowed production-KDF source close calls = %d; want zero", source.closeCalls)
	}

	if !wantCompletion {
		if !sink.aborted || sink.records != nil || !sink.stagedBytesAreZero() ||
			sink.preAbortRecordCount != 0 || sink.preAbortPlaintextLen != 0 {
			t.Fatal("wrong ordered factors did not abort an empty uncommitted sink")
		}
		return
	}
	if sink.aborted {
		t.Fatal("successful production-KDF read aborted its uncommitted sink")
	}
	staged := sink.plaintext()
	defer pcv3crypto.SecureZero(staged)
	if !bytes.Equal(staged, fixture.Plaintext()) {
		t.Fatalf("successful production-KDF plaintext = %d bytes; want exact %d-byte private fixture", len(staged), len(fixture.Plaintext()))
	}
	comment := result.commentBytes()
	defer pcv3crypto.SecureZero(comment)
	if !bytes.Equal(comment, fixture.Comment()) {
		t.Fatalf("successful production-KDF comment = %d bytes; want exact %d-byte private fixture", len(comment), len(fixture.Comment()))
	}
	sink.abortUncommitted()
	if sink.records != nil || !sink.stagedBytesAreZero() {
		t.Fatal("successful production-KDF test sink retained plaintext after explicit abort")
	}
}

func newProductionKDFFactors(
	t *testing.T,
	fixture *pcv3corpus.NormalVolumeFixture,
	reverse bool,
	keyfileMode pcv3credential.KeyfileMode,
) (*pcv3credential.FactorRequest, []byte, []*productionKDFKeyfileReadCloser) {
	t.Helper()
	passwordAlias := append([]byte(nil), fixture.Password()...)
	borrowedKeyfiles := fixture.Keyfiles()
	keyfiles := make([]*pcv3credential.KeyfileReader, len(borrowedKeyfiles))
	owned := make([]*productionKDFKeyfileReadCloser, len(borrowedKeyfiles))
	for index := range borrowedKeyfiles {
		sourceIndex := index
		if reverse {
			sourceIndex = len(borrowedKeyfiles) - 1 - index
		}
		ownedBytes := append([]byte(nil), borrowedKeyfiles[sourceIndex]...)
		reader := &productionKDFKeyfileReadCloser{
			reader:     bytes.NewReader(ownedBytes),
			ownedBytes: ownedBytes,
		}
		owned[index] = reader
		keyfiles[index] = pcv3credential.OwnKeyfileReader(reader)
	}
	return &pcv3credential.FactorRequest{
		Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
		KeyfileMode:    keyfileMode,
		ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
		Password:       passwordAlias,
		Keyfiles:       keyfiles,
	}, passwordAlias, owned
}
