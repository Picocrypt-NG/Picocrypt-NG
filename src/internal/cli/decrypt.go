package cli

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	// Silence Cobra's default error/usage printing - we handle it ourselves
	decryptCmd.SilenceErrors = true
	decryptCmd.SilenceUsage = true
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt VOLUME",
	Short: "Decrypt a .pcv volume",
	Long: `Decrypt a Picocrypt volume (.pcv) back to its original files.

If no password is provided, you will be prompted to enter one interactively.
The password is hidden while typing.

Pass the volume as a literal operand. Use -- before a volume filename that
begins with -.

Examples:
  # Decrypt interactively (prompts for password)
	  Picocrypt-NG decrypt secret.pcv -o secret.txt

  # Decrypt with password on command line (visible in shell history)
	  Picocrypt-NG decrypt secret.pcv -o secret.txt -p "mypassword"

  # Decrypt with keyfile (prompts for password, press Enter if keyfile-only)
	  Picocrypt-NG decrypt secret.pcv -k keyfile.key

  # Decrypt with keyfile only, no password prompt
	  Picocrypt-NG decrypt secret.pcv -k keyfile.key -p ""

  # Decrypt and auto-extract zip
	  Picocrypt-NG decrypt archive.pcv --auto-unzip

  # Force decryption despite errors (may produce corrupted output)
	  Picocrypt-NG decrypt damaged.pcv --force

  # Read password from stdin (for scripts)
	  echo "mypassword" | Picocrypt-NG decrypt secret.pcv -P

  # Decrypt from stdin (use -p since stdin is taken by data)
	  curl https://example.com/file.pcv | Picocrypt-NG decrypt - -o file.txt -p "pw"

  # Decrypt to stdout
	  Picocrypt-NG decrypt secret.pcv -o - -p "pw" | less`,
	Args: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("input") {
			return errors.New("--input/-i was removed; pass the volume path as an argument")
		}
		return cobra.ExactArgs(1)(cmd, args)
	},
	RunE: runDecrypt,
}

// Decrypt flags
var (
	decLegacyInputs  []string
	decOutput        string
	decPassword      string
	decPasswordStdin bool
	decKeyfiles      []string
	decForce         bool
	decVerifyFirst   bool
	decAutoUnzip     bool
	decSameLevel     bool
	decRecombine     bool
	decDeniability   bool
	decQuiet         bool
	decYes           bool
)

func init() {
	rootCmd.AddCommand(decryptCmd)

	// Input/Output
	decryptCmd.Flags().StringArrayVarP(&decLegacyInputs, "input", "i", nil, "")
	_ = decryptCmd.Flags().MarkHidden("input")
	decryptCmd.Flags().StringVarP(&decOutput, "output", "o", "", "Output file path (auto-detected if not specified)")

	// Credentials
	decryptCmd.Flags().StringVarP(&decPassword, "password", "p", "", "Decryption password")
	decryptCmd.Flags().BoolVarP(&decPasswordStdin, "password-stdin", "P", false, "Read password from stdin")
	decryptCmd.Flags().StringArrayVarP(&decKeyfiles, "keyfile", "k", nil, "Keyfile path(s) (can be specified multiple times)")

	// Decryption options
	decryptCmd.Flags().BoolVar(&decForce, "force", false, "Continue despite MAC verification failure")
	decryptCmd.Flags().BoolVar(&decVerifyFirst, "verify-first", false, "Verify integrity before decryption (slower but more secure)")
	decryptCmd.Flags().BoolVar(&decAutoUnzip, "auto-unzip", false, "Automatically extract if output is a zip file")
	decryptCmd.Flags().BoolVar(&decSameLevel, "same-level", false, "Extract zip to same directory (not subdirectory)")

	// Volume state
	decryptCmd.Flags().BoolVar(&decRecombine, "recombine", false, "Recombine split chunks first")
	decryptCmd.Flags().BoolVar(&decDeniability, "deniability", false, "Remove deniability wrapper first")

	// Other
	decryptCmd.Flags().BoolVarP(&decQuiet, "quiet", "q", false, "Suppress progress output")
	decryptCmd.Flags().BoolVarP(&decYes, "yes", "y", false, "Overwrite output file without prompting")
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	if cmd.Flags().Changed("input") || len(decLegacyInputs) > 0 {
		return errors.New("--input/-i was removed; pass the volume path as an argument")
	}
	if err := cobra.ExactArgs(1)(cmd, args); err != nil {
		return err
	}
	inputPath := args[0]

	// Check for stdin/stdout
	useStdin := IsStdin(inputPath)
	useStdout := IsStdout(decOutput)

	// Validate stdin/stdout constraints
	if useStdin && decPasswordStdin {
		return errors.New("cannot use -P (password from stdin) with - (input from stdin)")
	}
	if useStdin && decRecombine {
		return errors.New("stdin not compatible with --recombine")
	}
	if useStdin && decDeniability {
		return errors.New("stdin not compatible with --deniability")
	}
	if useStdout && decAutoUnzip {
		return errors.New("stdout not compatible with --auto-unzip")
	}
	if useStdout && decRecombine {
		return errors.New("stdout not compatible with --recombine")
	}

	// Auto-quiet when outputting to stdout
	if useStdout {
		decQuiet = true
	}

	// Track temp files for cleanup. The stdout temp holds decrypted plaintext and
	// the stdin temp holds the .pcv input; both are removed when the run ends.
	var stdinTempFile string
	var stdoutTempFile string
	defer func() { cleanupTempFiles(stdinTempFile, stdoutTempFile) }()

	outputFile := decOutput
	if outputFile == "" && useStdin {
		outputFile = "decrypted"
	}
	if useStdin && !useStdout && !decYes {
		if info, err := os.Stat(outputFile); err == nil {
			if info.IsDir() {
				return fmt.Errorf("output path is a directory: %s", outputFile)
			}
			return fmt.Errorf("output file %s already exists; when reading input from stdin use -y to overwrite", outputFile)
		}
	}

	// Handle stdin input
	inputFile := inputPath
	if useStdin {
		var err error
		stdinTempFile, err = BufferStdinToTemp(decOutput)
		if err != nil {
			return fmt.Errorf("buffering stdin: %w", err)
		}
		inputFile = stdinTempFile
	} else {
		inputInfo, err := os.Stat(inputPath)
		if err != nil {
			return fmt.Errorf("input file not found: %s", inputPath)
		}
		if inputInfo.IsDir() {
			return fmt.Errorf("input must be a file, not a directory: %s", inputPath)
		}
	}

	// Check if this looks like a split volume (skip for stdin)
	if !useStdin && strings.Contains(inputPath, ".pcv.") && !decRecombine {
		// Check if it's a chunk file like .pcv.0, .pcv.1, etc.
		ext := inputPath[strings.LastIndex(inputPath, ".pcv.")+5:]
		if _, err := fmt.Sscanf(ext, "%d", new(int)); err == nil {
			if !decQuiet {
				fmt.Fprintln(os.Stderr, "Detected split volume. Use --recombine to recombine chunks first.")
			}
			decRecombine = true
		}
	}

	// Determine output file
	if useStdout {
		// Create temp file for stdout output
		var err error
		stdoutTempFile, err = CreateTempOutput(0)
		if err != nil {
			return fmt.Errorf("creating temp output: %w", err)
		}
		outputFile = stdoutTempFile
	} else if outputFile == "" {
		// Auto-generate from input by removing .pcv extension
		if useStdin {
			outputFile = "decrypted"
		} else {
			outputFile = strings.TrimSuffix(inputPath, ".pcv")
			if decRecombine {
				// For split files like file.pcv.0, need to strip more
				if idx := strings.LastIndex(outputFile, ".pcv."); idx > 0 {
					outputFile = outputFile[:idx]
				}
			}
			// If we're left with the same name, add .decrypted
			if outputFile == inputPath {
				outputFile = inputPath + ".decrypted"
			}
		}
	}

	// Check if output exists (skip for stdout)
	if !useStdout {
		if info, err := os.Stat(outputFile); err == nil {
			if info.IsDir() {
				return fmt.Errorf("output path is a directory: %s", outputFile)
			}
			if !decYes {
				fmt.Fprintf(os.Stderr, "Output file %s already exists. Overwrite? [y/N]: ", outputFile)
				reader := bufio.NewReader(os.Stdin)
				response, err := reader.ReadString('\n')
				if err != nil && err != io.EOF {
					return fmt.Errorf("reading confirmation: %w", err)
				}
				response = strings.TrimSpace(strings.ToLower(response))
				if response != "y" && response != "yes" {
					return errors.New("operation cancelled")
				}
			}
		}
	}

	// Get password. Owned []byte from boundary to KDF; zeroed when this returns.
	// A closure (not `defer crypto.SecureZero(password)`) so the FINAL value is
	// zeroed — password is reassigned below by the stdin/interactive readers, and
	// a plain defer would bind the initial []byte(decPassword) at defer time.
	password := []byte(decPassword)
	defer func() { crypto.SecureZero(password) }()
	if decPasswordStdin {
		var err error
		password, err = ReadPasswordFromStdin()
		if err != nil {
			return err
		}
	}

	// Validate keyfiles exist
	for _, kf := range decKeyfiles {
		if _, err := os.Stat(kf); err != nil {
			return fmt.Errorf("keyfile not found: %s", kf)
		}
	}

	// Initialize RS codecs
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return fmt.Errorf("initializing Reed-Solomon codecs: %w", err)
	}

	// Try to read header to check if keyfiles are required
	// Note: with deniability, we can't read the header until wrapper is removed
	var volumeUsesKeyfiles bool
	if len(password) == 0 && !decDeniability {
		hdr, err := readHeaderInfo(inputFile, rsCodecs)
		if err == nil {
			volumeUsesKeyfiles = hdr.Flags.UseKeyfiles
			if !decQuiet && volumeUsesKeyfiles && len(decKeyfiles) == 0 {
				fmt.Fprintln(os.Stderr, "Warning: This volume requires keyfiles")
			}
		}
	}

	// Prompt for password interactively if not provided via -p/-P
	if len(password) == 0 {
		hasKeyfiles := len(decKeyfiles) > 0

		// With deniability, we can't know if volume uses keyfiles until wrapper is removed.
		// Allow empty password if keyfiles are provided (deniability wrapper may use empty password).
		// Without deniability, we can check the header to know if keyfiles are used.
		allowEmpty := hasKeyfiles || volumeUsesKeyfiles

		if !decQuiet {
			if decDeniability {
				fmt.Fprintln(os.Stderr, "Deniability mode: enter the password used for the deniability wrapper.")
				if hasKeyfiles {
					fmt.Fprintln(os.Stderr, "Press Enter if the volume was encrypted with keyfiles only.")
				}
			} else if hasKeyfiles {
				fmt.Fprintln(os.Stderr, "Keyfiles provided. Press Enter if the volume uses keyfile-only encryption.")
			}
		}
		var err error
		password, err = ReadPasswordInteractive(false, allowEmpty) // confirm=false for decryption
		if err != nil {
			return fmt.Errorf("password input: %w", err)
		}
	}

	// Create reporter
	reporter := NewReporter(decQuiet)
	globalReporter.Store(reporter)

	// Build request
	var kept bool
	req := &volume.DecryptRequest{
		InputFile:    inputFile,
		OutputFile:   outputFile,
		Password:     password,
		Keyfiles:     decKeyfiles,
		ForceDecrypt: decForce,
		VerifyFirst:  decVerifyFirst,
		AutoUnzip:    decAutoUnzip,
		SameLevel:    decSameLevel,
		Recombine:    decRecombine,
		Deniability:  decDeniability,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
		Kept:         &kept,
	}

	// Print info
	if !decQuiet {
		srcName := inputPath
		if useStdin {
			srcName = "stdin"
		}
		fmt.Fprintf(os.Stderr, "Decrypting %s\n", srcName)
		if decVerifyFirst {
			fmt.Fprintln(os.Stderr, "Mode: Verify-first (two-pass, slower but more secure)")
		}
		if decForce {
			fmt.Fprintln(os.Stderr, "Warning: Force mode enabled - may produce corrupted output")
		}
		fmt.Fprintln(os.Stderr)
	}

	// Run decryption
	err = volume.Decrypt(context.Background(), req)
	reporter.Finish()

	if err != nil {
		reporter.PrintError("%v", err)
		// Clean up partial output on error (temp files cleaned by defer).
		// Remove the partially-written .incomplete output.
		if !useStdout {
			_ = os.Remove(outputFile + ".incomplete")
		}
		return err
	}

	// Stream to stdout if requested
	if useStdout {
		if err := StreamFileToStdout(outputFile); err != nil {
			return fmt.Errorf("streaming to stdout: %w", err)
		}
		if kept {
			return forceDecryptKeptResult("stdout")
		}
		return nil
	}

	if kept {
		return forceDecryptKeptResult(outputFile)
	}
	reporter.PrintSuccess("Decryption completed successfully: %s", outputFile)
	return nil
}

func forceDecryptKeptResult(destination string) error {
	fmt.Fprintf(os.Stderr, "Warning: Force decrypt kept output after MAC verification failed; recovered data is untrusted: %s\n", destination)
	return newExitCodeError(ExitForceDecryptKept, "force decrypt kept output after MAC verification failed")
}

// readHeaderInfo reads just the header to get volume information
func readHeaderInfo(inputFile string, rsCodecs *encoding.RSCodecs) (*header.VolumeHeader, error) {
	// #nosec G304 -- inputFile is user-provided .pcv file
	f, err := os.Open(inputFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	reader := header.NewReader(f, rsCodecs)
	result, err := reader.ReadHeader()
	if err != nil {
		return nil, err
	}
	return result.Header, nil
}
