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

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a .pcv volume",
	Long: `Decrypt a Picocrypt volume (.pcv) back to its original files.

Examples:
  # Decrypt a file (prompts for password interactively)
  Picocrypt-NG decrypt -i secret.pcv

  # Decrypt with password on command line (for scripts)
  Picocrypt-NG decrypt -i secret.pcv -o secret.txt -p "mypassword"

  # Decrypt with auto-detection of output name
  Picocrypt-NG decrypt -i secret.pcv -p "mypassword"

  # Decrypt with keyfile
  Picocrypt-NG decrypt -i secret.pcv -p "mypassword" -k keyfile.key

  # Decrypt and auto-extract zip
  Picocrypt-NG decrypt -i archive.pcv -p "mypassword" --auto-unzip

  # Force decryption despite errors (may produce corrupted output)
  Picocrypt-NG decrypt -i damaged.pcv -p "mypassword" --force

  # Read password from stdin (for scripts)
  echo "mypassword" | Picocrypt-NG decrypt -i secret.pcv -P`,
	RunE:          runDecrypt,
	SilenceErrors: true,
	SilenceUsage:  true,
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
		reader := bufio.NewReader(os.Stdin)
		pw, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading password from stdin: %w", err)
		}
		password = strings.TrimSuffix(pw, "\n")
		password = strings.TrimSuffix(password, "\r")
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
	if !decQuiet && password == "" {
		hdr, err := readHeaderInfo(decInput, rsCodecs)
		if err == nil {
			if hdr.Flags.UseKeyfiles && len(decKeyfiles) == 0 {
				fmt.Fprintln(os.Stderr, "Warning: This volume requires keyfiles")
			}
		}
	}

	// Interactive password prompt if needed (works with or without keyfiles)
	if password == "" {
		prompt := "Password: "
		if len(decKeyfiles) > 0 {
			prompt = "Password (empty for keyfile-only): "
		}
		pw, err := readPasswordInteractive(prompt)
		if err != nil {
			return err
		}
		if pw == "" && len(decKeyfiles) == 0 {
			return fmt.Errorf("password or keyfile required\nSee 'Picocrypt-NG decrypt --help' for usage")
		}
		password = pw
	}

	// Validate credentials
	if password == "" && len(decKeyfiles) == 0 {
		return fmt.Errorf("password or keyfile required\nSee 'Picocrypt-NG decrypt --help' for usage")
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
