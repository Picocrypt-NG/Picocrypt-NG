// Package mobile is the gomobile bridge between the Go crypto core and the
// Android (Kotlin/Compose) host application.
package mobile

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	perrors "Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	runEncrypt = volume.Encrypt
	runDecrypt = volume.Decrypt
)

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

// GetDecryptionInfo reads metadata from an encrypted file without decrypting it.
// Returns a JSON string containing encryption settings and requirements.
// For deniable files, only the deniability flag will be set (readable=false).
func GetDecryptionInfo(filePath string) (string, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); err != nil {
		return "", fmt.Errorf("file not found: %w", err)
	}

	// Initialize Reed-Solomon codecs (needed for header reading)
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return "", fmt.Errorf("failed to initialize Reed-Solomon: %w", err)
	}

	// Check if file is deniable
	isDeniable := volume.IsDeniable(filePath, rsCodecs)

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

	// Open file and read header
	// #nosec G304 -- filePath is the user-selected encrypted volume to inspect.
	fin, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = fin.Close() }()

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
