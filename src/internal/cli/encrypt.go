package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/volume"

	"github.com/spf13/cobra"
)

func init() {
	// Silence Cobra's default error/usage printing - we handle it ourselves
	encryptCmd.SilenceErrors = true
	encryptCmd.SilenceUsage = true
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt files into a .pcv volume",
	Long: `Encrypt one or more files into a Picocrypt volume (.pcv).

If no password is provided, you will be prompted to enter one interactively
(with confirmation). The password is hidden while typing.

Examples:
  # Encrypt interactively (prompts for password)
  Picocrypt-NG encrypt -i secret.txt -o secret.pcv

  # Encrypt with password on command line (visible in shell history)
  Picocrypt-NG encrypt -i secret.txt -o secret.pcv -p "mypassword"

  # Encrypt multiple files (creates zip archive internally)
  Picocrypt-NG encrypt -i file1.txt -i file2.txt -o archive.pcv

  # Encrypt with paranoid mode and Reed-Solomon error correction
  Picocrypt-NG encrypt -i data.db -o data.pcv --paranoid --reed-solomon

  # Encrypt with keyfile (prompts for password, can leave empty for keyfile-only)
  Picocrypt-NG encrypt -i secret.txt -o secret.pcv -k keyfile.key

  # Encrypt with keyfile only (no password)
  Picocrypt-NG encrypt -i secret.txt -o secret.pcv -k keyfile.key -p ""

  # Read password from stdin (for scripts)
  echo "mypassword" | Picocrypt-NG encrypt -i secret.txt -o secret.pcv -P`,
	RunE: runEncrypt,
}

// Encrypt flags
var (
	encInput         []string
	encOutput        string
	encPassword      string
	encPasswordStdin bool
	encKeyfiles      []string
	encKeyfileOrder  bool
	encComments      string
	encParanoid      bool
	encReedSolomon   bool
	encDeniability   bool
	encCompress      bool
	encSplit         bool
	encSplitSize     int
	encSplitUnit     string
	encQuiet         bool
	encYes           bool
)

func init() {
	rootCmd.AddCommand(encryptCmd)

	// Input/Output
	encryptCmd.Flags().StringArrayVarP(&encInput, "input", "i", nil, "Input file(s) to encrypt (can be specified multiple times)")
	encryptCmd.Flags().StringVarP(&encOutput, "output", "o", "", "Output .pcv file path")

	// Credentials
	encryptCmd.Flags().StringVarP(&encPassword, "password", "p", "", "Encryption password")
	encryptCmd.Flags().BoolVarP(&encPasswordStdin, "password-stdin", "P", false, "Read password from stdin")
	encryptCmd.Flags().StringArrayVarP(&encKeyfiles, "keyfile", "k", nil, "Keyfile path(s) (can be specified multiple times)")
	encryptCmd.Flags().BoolVar(&encKeyfileOrder, "keyfile-ordered", false, "Keyfile order matters (sequential hashing)")

	// Security options
	encryptCmd.Flags().StringVarP(&encComments, "comments", "c", "", "Comments to store in header (NOT encrypted)")
	encryptCmd.Flags().BoolVar(&encParanoid, "paranoid", false, "Enable paranoid mode (Serpent + XChaCha20, HMAC-SHA3)")
	encryptCmd.Flags().BoolVar(&encReedSolomon, "reed-solomon", false, "Enable Reed-Solomon error correction (6% overhead)")
	encryptCmd.Flags().BoolVar(&encDeniability, "deniability", false, "Add deniability wrapper")
	encryptCmd.Flags().BoolVar(&encCompress, "compress", false, "Compress files before encryption")

	// Split options
	encryptCmd.Flags().BoolVar(&encSplit, "split", false, "Split output into chunks")
	encryptCmd.Flags().IntVar(&encSplitSize, "split-size", 0, "Size of each chunk (requires --split)")
	encryptCmd.Flags().StringVar(&encSplitUnit, "split-unit", "MiB", "Unit for split size: KiB, MiB, GiB, TiB, or Total")

	// Other
	encryptCmd.Flags().BoolVarP(&encQuiet, "quiet", "q", false, "Suppress progress output")
	encryptCmd.Flags().BoolVarP(&encYes, "yes", "y", false, "Overwrite output file without prompting")

	// Mark required
	_ = encryptCmd.MarkFlagRequired("input")
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	// Validate inputs
	if len(encInput) == 0 {
		return fmt.Errorf("at least one input file is required (-i)")
	}

	// Check input files exist
	var allFiles []string
	var onlyFiles []string
	var onlyFolders []string

	for _, input := range encInput {
		// Expand glob patterns
		matches, err := filepath.Glob(input)
		if err != nil {
			return fmt.Errorf("invalid glob pattern %q: %w", input, err)
		}
		if len(matches) == 0 {
			return fmt.Errorf("input file not found: %s", input)
		}

		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				return fmt.Errorf("cannot access %s: %w", match, err)
			}

			if info.IsDir() {
				onlyFolders = append(onlyFolders, match)
				// Walk directory to get all files
				err := filepath.Walk(match, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if !info.IsDir() {
						allFiles = append(allFiles, path)
					}
					return nil
				})
				if err != nil {
					return fmt.Errorf("walking directory %s: %w", match, err)
				}
			} else {
				onlyFiles = append(onlyFiles, match)
				allFiles = append(allFiles, match)
			}
		}
	}

	if len(allFiles) == 0 {
		return fmt.Errorf("no files found to encrypt")
	}

	// Determine output file
	outputFile := encOutput
	if outputFile == "" {
		// Auto-generate output name
		if len(encInput) == 1 {
			outputFile = encInput[0] + ".pcv"
		} else {
			outputFile = "encrypted.pcv"
		}
	}

	// Add .pcv extension if missing
	if !strings.HasSuffix(outputFile, ".pcv") {
		outputFile += ".pcv"
	}

	// Check if output exists
	if _, err := os.Stat(outputFile); err == nil && !encYes {
		fmt.Fprintf(os.Stderr, "Output file %s already exists. Overwrite? [y/N]: ", outputFile)
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			return fmt.Errorf("operation cancelled")
		}
	}

	// Get password
	password := encPassword
	if encPasswordStdin {
		var err error
		password, err = ReadPasswordFromStdin()
		if err != nil {
			return err
		}
	} else if password == "" {
		// Prompt for password interactively
		// Allow empty password only if keyfiles are provided
		hasKeyfiles := len(encKeyfiles) > 0
		if hasKeyfiles {
			fmt.Fprintln(os.Stderr, "Keyfiles provided. Press Enter for keyfile-only encryption, or enter a password.")
		}
		var err error
		password, err = ReadPasswordInteractive(true, hasKeyfiles) // confirm=true, allowEmpty=hasKeyfiles
		if err != nil {
			return fmt.Errorf("password input: %w", err)
		}
	}

	// Validate keyfiles exist
	for _, kf := range encKeyfiles {
		if _, err := os.Stat(kf); err != nil {
			return fmt.Errorf("keyfile not found: %s", kf)
		}
	}

	// Validate split options
	var chunkSize int
	var chunkUnit fileops.SplitUnit
	if encSplit {
		if encSplitSize <= 0 {
			return fmt.Errorf("--split-size is required when --split is enabled")
		}
		chunkSize = encSplitSize

		switch strings.ToLower(encSplitUnit) {
		case "kib":
			chunkUnit = fileops.SplitUnitKiB
		case "mib":
			chunkUnit = fileops.SplitUnitMiB
		case "gib":
			chunkUnit = fileops.SplitUnitGiB
		case "tib":
			chunkUnit = fileops.SplitUnitTiB
		case "total":
			chunkUnit = fileops.SplitUnitTotal
		default:
			return fmt.Errorf("invalid split unit: %s (must be KiB, MiB, GiB, TiB, or Total)", encSplitUnit)
		}
	}

	// Initialize RS codecs
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return fmt.Errorf("initializing Reed-Solomon codecs: %w", err)
	}

	// Create reporter
	reporter := NewReporter(encQuiet)
	globalReporter = reporter

	// Build request
	req := &volume.EncryptRequest{
		InputFiles:     allFiles,
		OnlyFiles:      onlyFiles,
		OnlyFolders:    onlyFolders,
		OutputFile:     outputFile,
		Password:       password,
		Keyfiles:       encKeyfiles,
		KeyfileOrdered: encKeyfileOrder,
		Comments:       encComments,
		Paranoid:       encParanoid,
		ReedSolomon:    encReedSolomon,
		Deniability:    encDeniability,
		Compress:       encCompress,
		Split:          encSplit,
		ChunkSize:      chunkSize,
		ChunkUnit:      chunkUnit,
		Reporter:       reporter,
		RSCodecs:       rsCodecs,
	}

	// Print info
	if !encQuiet {
		fmt.Fprintf(os.Stderr, "Encrypting %d file(s) to %s\n", len(allFiles), outputFile)
		if encParanoid {
			fmt.Fprintln(os.Stderr, "Mode: Paranoid (Serpent-CTR + XChaCha20, HMAC-SHA3)")
		}
		if encReedSolomon {
			fmt.Fprintln(os.Stderr, "Reed-Solomon: Enabled (6% size overhead)")
		}
		if encDeniability {
			fmt.Fprintln(os.Stderr, "Deniability: Enabled")
		}
		fmt.Fprintln(os.Stderr)
	}

	// Run encryption
	err = volume.Encrypt(context.Background(), req)
	reporter.Finish()

	if err != nil {
		reporter.PrintError("%v", err)
		// Clean up partial output on error
		_ = os.Remove(outputFile)
		_ = os.Remove(outputFile + ".incomplete")
		return err
	}

	reporter.PrintSuccess("Encryption completed successfully: %s", outputFile)
	return nil
}
