// Package mobile is the gomobile bridge between the Go crypto core and the
// Android (Kotlin/Compose) host application.
package mobile

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	perrors "Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3resource"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	runEncrypt                  = volume.Encrypt
	runDecrypt                  = volume.Decrypt
	openDecryptionInfoPCVInput  = volume.OpenLegacyPCVInput
	runPCV3OperationWithOptions = pcv3operation.RunWithOptions
	runPCV3Operation            = runAndroidPCV3Operation
	openPCV3Existing            = fileops.OpenExistingNoSymlink
)

func runAndroidPCV3Operation(
	ctx context.Context,
	request *pcv3operation.Request,
) *pcv3operation.Result {
	return runPCV3OperationWithOptions(ctx, request, pcv3operation.ExecutionOptions{
		RetainDurableOutput: true,
		JournalPrivateStage: true,
	})
}

const (
	maxPCV3EnvelopeBytes           = 64 << 10
	maxPCV3PathBytes               = 4096
	maxPCV3Keyfiles                = 64
	maxPCV3PasswordBytes           = 1 << 20
	pcv3BridgeInvalidRequest       = "PCV3_BRIDGE_INVALID_REQUEST"
	pcv3BridgeInputUnavailable     = "PCV3_BRIDGE_INPUT_UNAVAILABLE"
	pcv3BridgeKeyfileUnavailable   = "PCV3_BRIDGE_KEYFILE_UNAVAILABLE"
	pcv3BridgeOperationUnavailable = "PCV3_BRIDGE_OPERATION_UNAVAILABLE"
)

type pcv3Envelope struct {
	mode         pcv3operation.Mode
	factorMode   pcv3credential.CredentialMode
	keyfileMode  pcv3credential.KeyfileMode
	factorPolicy pcv3credential.FactorPolicy
	source       string
	target       string
	keyfiles     []string
}

// StartPCV3 starts one explicit PCV3 read/recovery operation. The JSON
// envelope is a strict, versioned, authority-free value; password remains a
// separate mutable byte buffer and is zeroed before this function returns.
func StartPCV3(requestJSON string, password []byte) *PCV3StartResult {
	defer crypto.SecureZero(password)

	envelope, err := decodePCV3Envelope(requestJSON)
	if err != nil || !envelope.acceptsPassword(password) {
		return newPCV3StartResult(pcv3BridgeInvalidRequest, nil)
	}

	passwordCopy := append([]byte(nil), password...)
	ownedPassword := true
	defer func() {
		if ownedPassword {
			crypto.SecureZero(passwordCopy)
		}
	}()

	source, err := openPCV3Regular(envelope.source)
	if err != nil {
		return newPCV3StartResult(pcv3BridgeInputUnavailable, nil)
	}
	ownedSource := true
	defer func() {
		if ownedSource {
			_ = source.Close()
		}
	}()

	keyfiles := make([]*os.File, 0, len(envelope.keyfiles))
	for _, path := range envelope.keyfiles {
		keyfile, openErr := openPCV3Regular(path)
		if openErr != nil {
			closePCV3Files(keyfiles)
			return newPCV3StartResult(pcv3BridgeKeyfileUnavailable, nil)
		}
		keyfiles = append(keyfiles, keyfile)
	}
	ownedKeyfiles := true
	defer func() {
		if ownedKeyfiles {
			closePCV3Files(keyfiles)
		}
	}()

	readers := make([]*pcv3credential.KeyfileReader, len(keyfiles))
	for index, keyfile := range keyfiles {
		readers[index] = pcv3credential.OwnKeyfileReader(keyfile)
		keyfiles[index] = nil
	}
	ownedKeyfiles = false

	factors := &pcv3credential.FactorRequest{
		Mode:           envelope.factorMode,
		KeyfileMode:    envelope.keyfileMode,
		ExpectedPolicy: envelope.factorPolicy,
		Password:       passwordCopy,
		Keyfiles:       readers,
	}
	passwordCopy = nil
	ownedPassword = false

	operation := startPCV3Operation()
	if operation == nil {
		_ = factors.Close()
		return newPCV3StartResult(pcv3BridgeOperationUnavailable, nil)
	}
	ownedSource = false

	request := &pcv3operation.Request{
		Mode:      envelope.mode,
		Source:    source,
		Factors:   factors,
		Target:    envelope.target,
		Protected: append(append([]string(nil), envelope.keyfiles...), envelope.source),
		Reporter:  pcv3Reporter(operation),
	}
	if envelope.mode == pcv3operation.ModeForceUnverifiedNormal ||
		envelope.mode == pcv3operation.ModeForceUnverifiedD1 {
		request.Consent = pcv3ConsentCallback(operation)
	}

	go executePCV3Operation(operation, request)
	return newPCV3StartResult("", operation)
}

func executePCV3Operation(operation *PCV3Operation, request *pcv3operation.Request) {
	var result *pcv3operation.Result
	defer func() {
		recovered := recover()
		releasePCV3Request(request)
		if recovered != nil {
			completePCV3Panic(operation)
			return
		}
		completePCV3Result(operation, result)
	}()
	ctx, ok := getContext(operation.id)
	if !ok {
		return
	}
	result = runPCV3Operation(ctx, request)
}

func releasePCV3Request(request *pcv3operation.Request) {
	if request == nil {
		return
	}
	if request.Factors != nil {
		_ = request.Factors.Close()
		request.Factors = nil
	}
	if request.Source != nil {
		_ = request.Source.Close()
		request.Source = nil
	}
	request.Mode = 0
	request.Target = ""
	for index := range request.Protected {
		request.Protected[index] = ""
	}
	request.Protected = nil
	request.Reporter = nil
	request.Consent = nil
}

func closePCV3Files(files []*os.File) {
	for index, file := range files {
		if file != nil {
			_ = file.Close()
			files[index] = nil
		}
	}
}

func decodePCV3Envelope(input string) (pcv3Envelope, error) {
	allowed := map[string]struct{}{
		"version": {}, "mode": {}, "factorPolicy": {}, "keyfileOrder": {},
		"source": {}, "target": {}, "keyfiles": {},
	}
	values, err := decodePCV3ExactObject(input, maxPCV3EnvelopeBytes, allowed)
	if err != nil {
		return pcv3Envelope{}, errors.New("invalid PCV3 envelope")
	}
	if string(bytes.TrimSpace(values["version"])) != "1" {
		return pcv3Envelope{}, errors.New("invalid PCV3 envelope")
	}

	modeText, err := decodePCV3String(values["mode"], 64, false)
	if err != nil {
		return pcv3Envelope{}, err
	}
	policyText, err := decodePCV3String(values["factorPolicy"], 64, false)
	if err != nil {
		return pcv3Envelope{}, err
	}
	orderText, err := decodePCV3String(values["keyfileOrder"], 64, false)
	if err != nil {
		return pcv3Envelope{}, err
	}
	source, err := decodePCV3String(values["source"], maxPCV3PathBytes, false)
	if err != nil {
		return pcv3Envelope{}, err
	}
	target, err := decodePCV3String(values["target"], maxPCV3PathBytes, false)
	if err != nil {
		return pcv3Envelope{}, err
	}
	keyfiles, err := decodePCV3StringArray(values["keyfiles"], maxPCV3Keyfiles, maxPCV3PathBytes)
	if err != nil {
		return pcv3Envelope{}, err
	}

	envelope := pcv3Envelope{source: source, target: target, keyfiles: keyfiles}
	switch modeText {
	case "read-normal":
		envelope.mode = pcv3operation.ModeReadNormal
	case "read-d1":
		envelope.mode = pcv3operation.ModeReadD1
	case "recover-normal":
		envelope.mode = pcv3operation.ModeRecoverNormal
	case "recover-d1":
		envelope.mode = pcv3operation.ModeRecoverD1
	case "force-normal":
		envelope.mode = pcv3operation.ModeForceNormal
	case "force-d1":
		envelope.mode = pcv3operation.ModeForceD1
	case "force-unverified-normal":
		envelope.mode = pcv3operation.ModeForceUnverifiedNormal
	case "force-unverified-d1":
		envelope.mode = pcv3operation.ModeForceUnverifiedD1
	default:
		return pcv3Envelope{}, errors.New("invalid PCV3 envelope")
	}
	switch policyText {
	case "password":
		envelope.factorMode = pcv3credential.CredentialModePasswordOnly
		envelope.factorPolicy = pcv3credential.FactorPolicyPasswordOnly
	case "keyfiles":
		envelope.factorMode = pcv3credential.CredentialModeKeyfilesOnly
		envelope.factorPolicy = pcv3credential.FactorPolicyKeyfilesOnly
	case "password-and-keyfiles":
		envelope.factorMode = pcv3credential.CredentialModePasswordAndKeyfiles
		envelope.factorPolicy = pcv3credential.FactorPolicyPasswordAndKeyfiles
	default:
		return pcv3Envelope{}, errors.New("invalid PCV3 envelope")
	}
	switch orderText {
	case "none":
		envelope.keyfileMode = pcv3credential.KeyfileModeNone
	case "ordered":
		envelope.keyfileMode = pcv3credential.KeyfileModeOrdered
	case "unordered":
		envelope.keyfileMode = pcv3credential.KeyfileModeUnordered
	default:
		return pcv3Envelope{}, errors.New("invalid PCV3 envelope")
	}
	if !envelope.validFactorShape() {
		return pcv3Envelope{}, errors.New("invalid PCV3 envelope")
	}
	return envelope, nil
}

func decodePCV3String(raw json.RawMessage, maximum int, allowEmpty bool) (string, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", errors.New("invalid PCV3 envelope")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value string
	if err := decoder.Decode(&value); err != nil || !jsonDecoderAtEOF(decoder) ||
		(!allowEmpty && value == "") || len(value) > maximum || strings.IndexByte(value, 0) >= 0 {
		return "", errors.New("invalid PCV3 envelope")
	}
	return value, nil
}

func decodePCV3StringArray(raw json.RawMessage, maximumItems, maximumBytes int) ([]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return nil, errors.New("invalid PCV3 envelope")
	}
	values := make([]string, 0)
	for decoder.More() {
		if len(values) == maximumItems {
			return nil, errors.New("invalid PCV3 envelope")
		}
		var rawValue json.RawMessage
		if err := decoder.Decode(&rawValue); err != nil {
			return nil, errors.New("invalid PCV3 envelope")
		}
		value, err := decodePCV3String(rawValue, maximumBytes, false)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim(']') || !jsonDecoderAtEOF(decoder) {
		return nil, errors.New("invalid PCV3 envelope")
	}
	return values, nil
}

func jsonDecoderAtEOF(decoder *json.Decoder) bool {
	var trailing any
	err := decoder.Decode(&trailing)
	return errors.Is(err, io.EOF)
}

func (envelope pcv3Envelope) validFactorShape() bool {
	switch envelope.factorMode {
	case pcv3credential.CredentialModePasswordOnly:
		return envelope.keyfileMode == pcv3credential.KeyfileModeNone && len(envelope.keyfiles) == 0
	case pcv3credential.CredentialModeKeyfilesOnly,
		pcv3credential.CredentialModePasswordAndKeyfiles:
		return envelope.keyfileMode != pcv3credential.KeyfileModeNone && len(envelope.keyfiles) > 0
	default:
		return false
	}
}

func (envelope pcv3Envelope) acceptsPassword(password []byte) bool {
	if len(password) > maxPCV3PasswordBytes {
		return false
	}
	switch envelope.factorMode {
	case pcv3credential.CredentialModePasswordOnly:
		return len(password) > 0
	case pcv3credential.CredentialModeKeyfilesOnly:
		return len(password) == 0
	case pcv3credential.CredentialModePasswordAndKeyfiles:
		return len(password) > 0
	default:
		return false
	}
}

// StartOperation creates a new operation and returns its ID.
// This should be called before StartEncrypt or StartDecrypt.
func StartOperation() string {
	id := startOperation()
	return id
}

// DetectOperation determines if a file should be encrypted or decrypted.
// Returns true for encrypt (non-.pcv files), false for decrypt (.pcv files).
func DetectOperation(filePath string) (isEncrypt bool, err error) {
	// Check if file exists
	if _, err := os.Stat(filePath); err != nil {
		return false, fmt.Errorf("file not found: %w", err)
	}
	if err := volume.PreflightPCV3(filePath, false); err != nil {
		if code, ok := pcv3ErrorCode(err); ok {
			return false, errors.New(code)
		}
		return false, err
	}

	// Check if it's a .pcv file (decrypt) or split volume chunk
	if fileops.IsSplitChunkPath(filePath) {
		return false, nil // Decrypt
	}

	// Check for .pcv extension
	baseName := filepath.Base(filePath)
	if strings.HasSuffix(strings.ToLower(baseName), ".pcv") {
		return false, nil // Decrypt
	}

	return true, nil // Encrypt
}

// PCV3AndroidPolicyState exposes the closed presentation state used by the
// Android host. This is not a resource or operation admission decision.
func PCV3AndroidPolicyState() string {
	if pcv3resource.AndroidReadPolicyConfigured() {
		return "configured"
	}
	return "unconfigured"
}

// DetectPCV3Route classifies one regular input with the Go-owned PCV3
// discriminator. It does not collect credentials, run a KDF, or authorize an
// operation. D1 intentionally remains legacy-eligible here because selecting
// D1 is an explicit user intent rather than an auto-detected format.
func DetectPCV3Route(filePath string) (route string, retErr error) {
	source, err := openPCV3Regular(filePath)
	if err != nil {
		return "", errors.New(pcv3BridgeInputUnavailable)
	}
	defer func() {
		if closeErr := source.Close(); closeErr != nil && retErr == nil {
			route = ""
			retErr = errors.New(pcv3BridgeInputUnavailable)
		}
	}()

	info, err := source.Stat()
	if err != nil {
		return "", errors.New(pcv3BridgeInputUnavailable)
	}
	detected, _, err := pcv3.Probe(source, info.Size())
	if err != nil {
		var failure pcv3.Failure
		if !errors.As(err, &failure) {
			return "", errors.New(pcv3BridgeInputUnavailable)
		}
		switch failure.Code() {
		case pcv3.CodeUnsupported:
			return "unsupported", nil
		case pcv3.CodeInvalidStructure:
			return "invalid", nil
		default:
			return "", errors.New(pcv3BridgeInputUnavailable)
		}
	}
	if detected == pcv3.RouteNormalPCV {
		return "normal", nil
	}
	return "legacy", nil
}

// EncryptRequestJSON represents the JSON structure for encryption requests
type EncryptRequestJSON struct {
	OperationID    string   `json:"operationID"`
	InputFile      string   `json:"inputFile"`
	InputFiles     []string `json:"inputFiles"`
	OnlyFolders    []string `json:"onlyFolders"`
	OnlyFiles      []string `json:"onlyFiles"`
	OutputFile     string   `json:"outputFile"`
	Comments       string   `json:"comments"`
	Keyfiles       []string `json:"keyfiles"`
	Paranoid       bool     `json:"paranoid"`
	ReedSolomon    bool     `json:"reedSolomon"`
	Deniability    bool     `json:"deniability"`
	Compress       bool     `json:"compress"`
	KeyfileOrdered bool     `json:"keyfileOrdered"`
}

// DecryptRequestJSON represents the JSON structure for decryption requests
type DecryptRequestJSON struct {
	OperationID  string   `json:"operationID"`
	InputFile    string   `json:"inputFile"`
	OutputFile   string   `json:"outputFile"`
	Keyfiles     []string `json:"keyfiles"`
	ForceDecrypt bool     `json:"forceDecrypt"`
	VerifyFirst  bool     `json:"verifyFirst"`
	AutoUnzip    bool     `json:"autoUnzip"`
	SameLevel    bool     `json:"sameLevel"`
	Recombine    bool     `json:"recombine"`
	Deniability  bool     `json:"deniability"`
}

// StartEncrypt starts an encryption operation in the background.
// The operationID should be obtained by calling StartOperation() first.
// Returns an error message (empty string on success).
// Errors during execution are also reported through the progress system (GetProgress).
// requestJSON is a JSON string containing all encryption parameters.
// password carries the plaintext password as raw bytes (kept out of the JSON so
// it never becomes an un-zeroable JVM String); it is zeroed before this returns.
func StartEncrypt(requestJSON string, password []byte) string {
	defer crypto.SecureZero(password)

	var req EncryptRequestJSON
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return fmt.Sprintf("failed to parse request JSON: %v", err)
	}

	// Verify the operation exists (should have been created by StartOperation)
	globalProgressMap.mu.RLock()
	_, exists := globalProgressMap.ops[req.OperationID]
	globalProgressMap.mu.RUnlock()

	if !exists {
		return fmt.Sprintf("operation %s not found - call StartOperation() first", req.OperationID)
	}

	// Validate inputs
	if req.InputFile == "" && len(req.InputFiles) == 0 {
		return failOperation(req.OperationID, errors.New("input file is required"))
	}
	if req.OutputFile == "" {
		return failOperation(req.OperationID, errors.New("output file is required"))
	}
	if len(req.Keyfiles) > 0 {
		return failOperation(req.OperationID, perrors.NewKeyfileWritesDisabledError())
	}
	if req.Deniability && len(password) == 0 {
		return failOperation(req.OperationID, perrors.NewDeniabilityPasswordRequiredError())
	}
	if len(password) == 0 {
		return failOperation(req.OperationID, perrors.NewEncryptionPasswordRequiredError())
	}

	// Own a goroutine-private []byte copy of the password BEFORE launching the
	// worker. The worker runs async and the outer `defer crypto.SecureZero(password)`
	// above fires on this function's return — the goroutine must NOT read `password`
	// itself or it races that zeroing. pwCopy is captured by the goroutine and zeroed
	// when the worker returns. No intermediate immutable string is created.
	pwCopy := append([]byte(nil), password...)

	// Capture only the operation ID for the delayed cleanup so the
	// credential-bearing worker goroutine below can drop pwCopy/req the instant it
	// returns, instead of holding them alive across the 60s poll window.
	opID := req.OperationID

	// Start the operation in a goroutine
	go func() {
		defer crypto.SecureZero(pwCopy)

		defer func() {
			// Delay cleanup to allow UI to poll for final status (60s handles the
			// app being backgrounded). Run it in its OWN goroutine capturing only
			// opID, so this worker goroutine returns immediately after
			// completeOperation, releasing pwCopy/req/encryptReq before the sleep.
			go func() {
				time.Sleep(60 * time.Second)
				cleanupOperation(opID)
			}()
		}()

		// Recover from panics to prevent silent failures
		defer func() {
			if r := recover(); r != nil {
				completeOperation(req.OperationID, fmt.Errorf("panic: %v", r))
			}
		}()

		// Initialize Reed-Solomon codecs (always needed for header encoding, even if payload RS is disabled)
		rsCodecs, err := encoding.NewRSCodecs()
		if err != nil {
			completeOperation(req.OperationID, fmt.Errorf("failed to initialize Reed-Solomon: %w", err))
			return
		}

		// Create progress reporter
		reporter := &androidProgressReporter{opID: req.OperationID}

		// Build encrypt request
		encryptReq := &volume.EncryptRequest{
			InputFile:      req.InputFile,
			InputFiles:     req.InputFiles,
			OnlyFolders:    req.OnlyFolders,
			OnlyFiles:      req.OnlyFiles,
			OutputFile:     req.OutputFile,
			Password:       pwCopy,
			Keyfiles:       req.Keyfiles,
			KeyfileOrdered: req.KeyfileOrdered,
			Comments:       req.Comments,
			Paranoid:       req.Paranoid,
			ReedSolomon:    req.ReedSolomon,
			Deniability:    req.Deniability,
			Compress:       req.Compress,
			Reporter:       reporter,
			RSCodecs:       rsCodecs,
		}

		// Get cancellation context
		opCtx, exists := getContext(req.OperationID)
		if !exists {
			completeOperation(req.OperationID, fmt.Errorf("operation context %s not found", req.OperationID))
			return
		}

		// Perform encryption
		err = runEncrypt(opCtx, encryptReq)
		if err != nil {
			completeOperation(req.OperationID, err)
			return
		}

		completeOperation(req.OperationID, nil)
	}()

	return "" // Success - operation started
}

// StartDecrypt starts a decryption operation in the background.
// The operationID should be obtained by calling StartOperation() first.
// Returns an error message (empty string on success).
// Errors during execution are also reported through the progress system (GetProgress).
// requestJSON is a JSON string containing all decryption parameters.
// password carries the plaintext password as raw bytes (kept out of the JSON so
// it never becomes an un-zeroable JVM String); it is zeroed before this returns.
func StartDecrypt(requestJSON string, password []byte) string {
	defer crypto.SecureZero(password)

	var req DecryptRequestJSON
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return fmt.Sprintf("failed to parse request JSON: %v", err)
	}

	// Verify the operation exists (should have been created by StartOperation)
	globalProgressMap.mu.RLock()
	_, exists := globalProgressMap.ops[req.OperationID]
	globalProgressMap.mu.RUnlock()

	if !exists {
		return fmt.Sprintf("operation %s not found - call StartOperation() first", req.OperationID)
	}

	// Validate inputs
	if req.InputFile == "" {
		return failOperation(req.OperationID, errors.New("input file is required"))
	}
	if err := volume.PreflightPCV3(req.InputFile, req.Recombine); err != nil {
		if code, ok := pcv3ErrorCode(err); ok {
			cleanupOperation(req.OperationID)
			return code
		}
		return failOperation(req.OperationID, err)
	}
	if req.OutputFile == "" {
		return failOperation(req.OperationID, errors.New("output file is required"))
	}
	if len(password) == 0 && len(req.Keyfiles) == 0 {
		return failOperation(req.OperationID, errors.New("password or keyfiles required"))
	}

	// Own a goroutine-private []byte copy of the password BEFORE launching the
	// worker. The worker runs async and the outer `defer crypto.SecureZero(password)`
	// above fires on this function's return — the goroutine must NOT read `password`
	// itself or it races that zeroing. pwCopy is captured by the goroutine and zeroed
	// when the worker returns. No intermediate immutable string is created.
	pwCopy := append([]byte(nil), password...)

	// Capture only the operation ID for the delayed cleanup so the
	// credential-bearing worker goroutine below can drop pwCopy/req the instant it
	// returns, instead of holding them alive across the 60s poll window.
	opID := req.OperationID

	// Start the operation in a goroutine
	go func() {
		defer crypto.SecureZero(pwCopy)

		defer func() {
			// Delay cleanup to allow UI to poll for final status (60s handles the
			// app being backgrounded). Run it in its OWN goroutine capturing only
			// opID, so this worker goroutine returns immediately after
			// completeOperation, releasing pwCopy/req/decryptReq before the sleep.
			go func() {
				time.Sleep(60 * time.Second)
				cleanupOperation(opID)
			}()
		}()

		defer func() {
			if r := recover(); r != nil {
				completeOperation(req.OperationID, fmt.Errorf("panic: %v", r))
			}
		}()

		// Initialize Reed-Solomon codecs (needed for header reading)
		rsCodecs, err := encoding.NewRSCodecs()
		if err != nil {
			completeOperation(req.OperationID, fmt.Errorf("failed to initialize Reed-Solomon: %w", err))
			return
		}

		// Create progress reporter
		reporter := &androidProgressReporter{opID: req.OperationID}

		// Build decrypt request
		decryptReq := &volume.DecryptRequest{
			InputFile:    req.InputFile,
			OutputFile:   req.OutputFile,
			Password:     pwCopy,
			Keyfiles:     req.Keyfiles,
			ForceDecrypt: req.ForceDecrypt,
			VerifyFirst:  req.VerifyFirst,
			AutoUnzip:    req.AutoUnzip,
			SameLevel:    req.SameLevel,
			Recombine:    req.Recombine,
			Deniability:  req.Deniability,
			Reporter:     reporter,
			RSCodecs:     rsCodecs,
		}

		// Get cancellation context
		opCtx, exists := getContext(req.OperationID)
		if !exists {
			completeOperation(req.OperationID, fmt.Errorf("operation context %s not found", req.OperationID))
			return
		}

		// Perform decryption
		err = runDecrypt(opCtx, decryptReq)
		if err != nil {
			completeOperation(req.OperationID, err)
			return
		}

		completeOperation(req.OperationID, nil)
	}()

	return "" // Success - operation started
}

func failOperation(id string, err error) string {
	completeOperation(id, err)
	cleanupOperation(id)
	return err.Error()
}

// ProgressResult contains the progress information for an operation.
// Go mobile bindings require struct returns instead of multiple values.
type ProgressResult struct {
	Status                  string
	StatusCode              string
	StatusSpeedMiBPerSecond float64
	StatusETA               string
	Progress                float32
	Info                    string
	InfoCode                string
	InfoCurrent             int64
	InfoTotal               int64
	Done                    bool
	Error                   string
	// Code is the stable, locale-independent error classification (see
	// errorCode); empty unless the operation failed. The Kotlin layer switches
	// on it instead of substring-matching Error.
	Code string
}

// GetProgress retrieves the current progress state for an operation.
func GetProgress(operationID string) (*ProgressResult, error) {
	state, err := getProgress(operationID)
	if err != nil {
		return nil, err
	}
	return progressResultFromState(state), nil
}

func progressResultFromState(state *ProgressState) *ProgressResult {
	return &ProgressResult{
		Status:                  state.Status,
		StatusCode:              state.StatusCode,
		StatusSpeedMiBPerSecond: state.StatusSpeedMiBPerSecond,
		StatusETA:               state.StatusETA,
		Progress:                state.Progress,
		Info:                    state.Info,
		InfoCode:                state.InfoCode,
		InfoCurrent:             state.InfoCurrent,
		InfoTotal:               state.InfoTotal,
		Done:                    state.Done,
		Error:                   state.Error,
		Code:                    state.Code,
	}
}

// CancelOperation cancels a running operation and returns the canonical
// terminal snapshot. If the operation completed first, that result wins.
func CancelOperation(operationID string) (*ProgressResult, error) {
	state, err := cancelOperationAndGetProgress(operationID)
	if err != nil {
		return nil, err
	}
	return progressResultFromState(state), nil
}

// DecryptionInfoJSON represents the JSON structure for decryption metadata
type DecryptionInfoJSON struct {
	KeyfilesRequired bool   `json:"keyfilesRequired"`
	KeyfileOrdered   bool   `json:"keyfileOrdered"`
	ReedSolomon      bool   `json:"reedSolomon"`
	Deniability      bool   `json:"deniability"`
	Paranoid         bool   `json:"paranoid"`
	Comments         string `json:"comments"`
	Readable         bool   `json:"readable"` // false if deniable (can't read other fields without password)
}

type decryptionInfoErrorJSON struct {
	ErrorCode string `json:"errorCode"`
}

// GetDecryptionInfo reads metadata from an encrypted file without decrypting it.
// Returns a JSON string containing encryption settings and requirements.
// For deniable files, only the deniability flag will be set (readable=false).
func GetDecryptionInfo(filePath string) (string, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); err != nil {
		return "", fmt.Errorf("file not found: %w", err)
	}
	fin, err := openDecryptionInfoPCVInput(filePath, false)
	if err != nil {
		if code, ok := pcv3ErrorCode(err); ok {
			jsonData, marshalErr := json.Marshal(decryptionInfoErrorJSON{ErrorCode: code})
			if marshalErr != nil {
				return "", fmt.Errorf("failed to marshal JSON: %w", marshalErr)
			}
			return string(jsonData), nil
		}
		return "", err
	}
	defer func() { _ = fin.Close() }()

	// Initialize Reed-Solomon codecs (needed for header reading)
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return "", fmt.Errorf("failed to initialize Reed-Solomon: %w", err)
	}

	// Check if file is deniable
	isDeniable := volume.IsDeniableFile(fin, rsCodecs)

	info := DecryptionInfoJSON{
		Deniability: isDeniable,
		Readable:    !isDeniable,
	}

	// If deniable, we can't read the header without the password
	if isDeniable {
		// Return minimal info - deniability is true, but other fields can't be read
		jsonData, err := json.Marshal(info)
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON: %w", err)
		}
		return string(jsonData), nil
	}

	// Read header
	reader := header.NewReader(fin, rsCodecs)
	result, err := reader.ReadHeader()
	if err != nil {
		return "", fmt.Errorf("failed to read header: %w", err)
	}

	// Extract metadata from header
	h := result.Header
	info.KeyfilesRequired = h.Flags.UseKeyfiles
	info.KeyfileOrdered = h.Flags.KeyfileOrdered
	info.ReedSolomon = h.Flags.ReedSolomon
	info.Paranoid = h.Flags.Paranoid
	info.Comments = h.Comments
	info.Readable = true

	// Marshal to JSON
	jsonData, err := json.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(jsonData), nil
}

// androidProgressReporter implements volume.ProgressReporter for Android
type androidProgressReporter struct {
	opID string
}

func (r *androidProgressReporter) SetStatus(text string) {
	status := classifyStatus(text)

	globalProgressMap.mu.Lock()
	op, exists := globalProgressMap.ops[r.opID]
	if exists && !op.Done {
		op.Status = text
		op.StatusCode = status.Code
		op.StatusSpeedMiBPerSecond = status.SpeedMiBPerSecond
		op.StatusETA = status.ETA
	}
	globalProgressMap.mu.Unlock()

	if !exists {
		log.Printf("mobile progress status dropped for unknown operation %s", r.opID)
	}
}

func (r *androidProgressReporter) SetProgress(fraction float32, info string) {
	classified := classifyInfo(info)

	globalProgressMap.mu.Lock()
	op, exists := globalProgressMap.ops[r.opID]
	if exists && !op.Done {
		op.Progress = fraction
		op.Info = info
		op.InfoCode = classified.Code
		op.InfoCurrent = classified.Current
		op.InfoTotal = classified.Total
	}
	globalProgressMap.mu.Unlock()

	if !exists {
		log.Printf("mobile progress update dropped for unknown operation %s", r.opID)
	}
}

func (r *androidProgressReporter) SetCanCancel(can bool) {
	// Not needed for Android implementation
}

func (r *androidProgressReporter) Update() {
	// Not needed for Android implementation (polling-based)
}

func (r *androidProgressReporter) IsCancelled() bool {
	ctx, exists := getContext(r.opID)
	if !exists {
		return false
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
