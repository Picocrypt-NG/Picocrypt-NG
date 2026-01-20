package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"

	"github.com/spf13/cobra"
)

func init() {
	// Silence Cobra's default error/usage printing - we handle it ourselves
	decryptCmd.SilenceErrors = true
	decryptCmd.SilenceUsage = true
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a .pcv volume",
	Long: `Decrypt a Picocrypt volume (.pcv) back to its original files.

If no password is provided, you will be prompted to enter one interactively.
The password is hidden while typing.

Examples:
  # Decrypt interactively (prompts for password)
  Picocrypt-NG decrypt -i secret.pcv

  # Decrypt with password on command line (visible in shell history)
  Picocrypt-NG decrypt -i secret.pcv -o secret.txt -p "mypassword"

  # Decrypt with keyfile (prompts for password, press Enter if keyfile-only)
  Picocrypt-NG decrypt -i secret.pcv -k keyfile.key

  # Decrypt with keyfile only, no password prompt
  Picocrypt-NG decrypt -i secret.pcv -k keyfile.key -p ""

  # Decrypt and auto-extract zip
  Picocrypt-NG decrypt -i archive.pcv --auto-unzip

  # Force decryption despite errors (may produce corrupted output)
  Picocrypt-NG decrypt -i damaged.pcv --force

  # Read password from stdin (for scripts)
  echo "mypassword" | Picocrypt-NG decrypt -i secret.pcv -P`,
	RunE: runDecrypt,
}

// Decrypt flags
var (
	decInput         string
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
	decryptCmd.Flags().StringVarP(&decInput, "input", "i", "", "Input .pcv file to decrypt")
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

	// Mark required
	_ = decryptCmd.MarkFlagRequired("input")
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	// Validate input exists
	if decInput == "" {
		return fmt.Errorf("input file is required (-i)")
	}

	inputInfo, err := os.Stat(decInput)
	if err != nil {
		return fmt.Errorf("input file not found: %s", decInput)
	}
	if inputInfo.IsDir() {
		return fmt.Errorf("input must be a file, not a directory: %s", decInput)
	}

	// Check if this looks like a split volume
	if strings.Contains(decInput, ".pcv.") && !decRecombine {
		// Check if it's a chunk file like .pcv.0, .pcv.1, etc.
		ext := decInput[strings.LastIndex(decInput, ".pcv.")+5:]
		if _, err := fmt.Sscanf(ext, "%d", new(int)); err == nil {
			if !decQuiet {
				fmt.Fprintln(os.Stderr, "Detected split volume. Use --recombine to recombine chunks first.")
			}
			decRecombine = true
		}
	}

	// Determine output file
	outputFile := decOutput
	if outputFile == "" {
		// Auto-generate from input by removing .pcv extension
		outputFile = strings.TrimSuffix(decInput, ".pcv")
		if decRecombine {
			// For split files like file.pcv.0, need to strip more
			if idx := strings.LastIndex(outputFile, ".pcv."); idx > 0 {
				outputFile = outputFile[:idx]
			}
		}
		// If we're left with the same name, add .decrypted
		if outputFile == decInput {
			outputFile = decInput + ".decrypted"
		}
	}

	// Check if output exists
	if _, err := os.Stat(outputFile); err == nil && !decYes {
		fmt.Fprintf(os.Stderr, "Output file %s already exists. Overwrite? [y/N]: ", outputFile)
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			return fmt.Errorf("operation cancelled")
		}
	}

	// Get password
	password := decPassword
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
	if password == "" && !decDeniability {
		hdr, err := readHeaderInfo(decInput, rsCodecs)
		if err == nil {
			volumeUsesKeyfiles = hdr.Flags.UseKeyfiles
			if !decQuiet && volumeUsesKeyfiles && len(decKeyfiles) == 0 {
				fmt.Fprintln(os.Stderr, "Warning: This volume requires keyfiles")
			}
		}
	}

	// Prompt for password interactively if not provided via -p/-P
	if password == "" {
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
	globalReporter = reporter

	// Build request
	var kept bool
	req := &volume.DecryptRequest{
		InputFile:    decInput,
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
		fmt.Fprintf(os.Stderr, "Decrypting %s\n", decInput)
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
		// Clean up partial output on error
		_ = os.Remove(outputFile + ".incomplete")
		return err
	}

	if kept {
		reporter.PrintSuccess("Decryption completed with warnings (MAC verification failed): %s", outputFile)
	} else {
		reporter.PrintSuccess("Decryption completed successfully: %s", outputFile)
	}
	return nil
}

// readHeaderInfo reads just the header to get volume information
func readHeaderInfo(inputFile string, rsCodecs *encoding.RSCodecs) (*header.VolumeHeader, error) {
	f, err := os.Open(inputFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := header.NewReader(f, rsCodecs)
	result, err := reader.ReadHeader()
	if err != nil {
		return nil, err
	}
	return result.Header, nil
}
