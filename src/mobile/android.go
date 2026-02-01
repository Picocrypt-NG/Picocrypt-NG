package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"
)

// StartOperation creates a new operation and returns its ID.
// This should be called before StartEncrypt or StartDecrypt.
func StartOperation() string {
	id, _, _ := startOperation()
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
	baseName := filepath.Base(filePath)

	// Check for split volume chunks (e.g., file.pcv.0, file.pcv.1)
	if strings.Contains(baseName, ".pcv.") {
		// Check if it ends with a digit (split chunk)
		lastChar := baseName[len(baseName)-1]
		if lastChar >= '0' && lastChar <= '9' {
			return false, nil // Decrypt
		}
	}

	// Check for .pcv extension
	if strings.HasSuffix(strings.ToLower(baseName), ".pcv") {
		return false, nil // Decrypt
	}

	return true, nil // Encrypt
}

// EncryptRequestJSON represents the JSON structure for encryption requests
type EncryptRequestJSON struct {
	OperationID    string   `json:"operationID"`
	InputFile      string   `json:"inputFile"`
	OutputFile     string   `json:"outputFile"`
	Password       string   `json:"password"`
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
	Password     string   `json:"password"`
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
func StartEncrypt(requestJSON string) string {

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
	if req.InputFile == "" {
		err := fmt.Errorf("input file is required")
		completeOperation(req.OperationID, err)
		return err.Error()
	}
	if req.OutputFile == "" {
		err := fmt.Errorf("output file is required")
		completeOperation(req.OperationID, err)
		return err.Error()
	}
	if req.Password == "" && len(req.Keyfiles) == 0 {
		err := fmt.Errorf("password or keyfiles required")
		completeOperation(req.OperationID, err)
		return err.Error()
	}

	// Start the operation in a goroutine
	go func() {

		defer func() {
			// Delay cleanup to allow UI to poll for final status
			// Extended to 60 seconds to handle cases where app is backgrounded
			// and user returns after operation completes
			time.Sleep(60 * time.Second)
			cleanupOperation(req.OperationID)
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
			OutputFile:     req.OutputFile,
			Password:       req.Password,
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
			// If context doesn't exist, create a new one (shouldn't happen, but be safe)
			opCtx = context.Background()
		}

		// Perform encryption
		err = volume.Encrypt(opCtx, encryptReq)
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
func StartDecrypt(requestJSON string) string {
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
		err := fmt.Errorf("input file is required")
		completeOperation(req.OperationID, err)
		return err.Error()
	}
	if req.OutputFile == "" {
		err := fmt.Errorf("output file is required")
		completeOperation(req.OperationID, err)
		return err.Error()
	}
	if req.Password == "" && len(req.Keyfiles) == 0 {
		err := fmt.Errorf("password or keyfiles required")
		completeOperation(req.OperationID, err)
		return err.Error()
	}

	// Start the operation in a goroutine
	go func() {
		defer func() {
			// Delay cleanup to allow UI to poll for final status
			// Extended to 60 seconds to handle cases where app is backgrounded
			// and user returns after operation completes
			time.Sleep(60 * time.Second)
			cleanupOperation(req.OperationID)
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
			Password:     req.Password,
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
			// If context doesn't exist, create a new one (shouldn't happen, but be safe)
			opCtx = context.Background()
		}

		// Perform decryption
		err = volume.Decrypt(opCtx, decryptReq)
		if err != nil {
			completeOperation(req.OperationID, err)
			return
		}

		completeOperation(req.OperationID, nil)
	}()

	return "" // Success - operation started
}

// ProgressResult contains the progress information for an operation.
// Go mobile bindings require struct returns instead of multiple values.
type ProgressResult struct {
	Status   string
	Progress float32
	Info     string
	Done     bool
	Error    string
}

// GetProgress retrieves the current progress state for an operation.
func GetProgress(operationID string) (*ProgressResult, error) {
	state, err := getProgress(operationID)
	if err != nil {
		return nil, err
	}
	return &ProgressResult{
		Status:   state.Status,
		Progress: state.Progress,
		Info:     state.Info,
		Done:     state.Done,
		Error:    state.Error,
	}, nil
}

// CancelOperation cancels a running operation.
func CancelOperation(operationID string) error {
	return cancelOperation(operationID)
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

	globalProgressMap.mu.RLock()
	op, exists := globalProgressMap.ops[r.opID]
	globalProgressMap.mu.RUnlock()

	if exists {
		updateProgress(r.opID, text, op.Progress, op.Info)
	} else {
	}
}

func (r *androidProgressReporter) SetProgress(fraction float32, info string) {

	globalProgressMap.mu.RLock()
	op, exists := globalProgressMap.ops[r.opID]
	globalProgressMap.mu.RUnlock()

	if exists {
		updateProgress(r.opID, op.Status, fraction, info)
	} else {
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
