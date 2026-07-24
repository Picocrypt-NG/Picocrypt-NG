package cli

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	perrors "Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/fileops"
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
	encryptCmd.SilenceErrors = true
	encryptCmd.SilenceUsage = true
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt [PATH...]",
	Short: "Encrypt files into a .pcv volume",
	Long: `Encrypt one or more files into a Picocrypt volume (.pcv).

If no password is provided, you will be prompted to enter one interactively
(with confirmation). The password is hidden while typing.
Deniability always requires a non-empty password.

Examples:
  # Encrypt interactively (prompts for password)
	  Picocrypt-NG encrypt secret.txt -o secret.pcv

  # Encrypt with password on command line (visible in shell history)
	  Picocrypt-NG encrypt secret.txt -o secret.pcv -p "mypassword"

  # Encrypt multiple files (creates zip archive internally)
	  Picocrypt-NG encrypt file1.txt file2.txt -o archive.pcv

  # Encrypt files selected by explicit, quoted glob patterns
	  Picocrypt-NG encrypt --glob "*.jpg" --glob "*.png" -o images.pcv

  # Encrypt with paranoid mode and Reed-Solomon error correction
	  Picocrypt-NG encrypt data.db -o data.pcv --paranoid --reed-solomon

  # Read password from stdin (for scripts)
	  echo "mypassword" | Picocrypt-NG encrypt secret.txt -o secret.pcv -P

  # Encrypt from stdin to stdout (use -p since stdin is taken by data)
	  cat data.txt | Picocrypt-NG encrypt - -o - -p "pw" > data.pcv

  # Encrypt to stdout
	  Picocrypt-NG encrypt secret.txt -o - -p "pw" > secret.pcv`,
	Args: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("input") {
			return errors.New("--input/-i was removed; pass literal paths as arguments or use --glob for patterns")
		}
		if len(args) == 0 && len(encGlob) == 0 {
			return errors.New("at least one input path or --glob pattern is required")
		}
		return nil
	},
	RunE: runEncrypt,
}

// Encrypt flags
var (
	encGlob           []string
	encLegacyInputs   []string
	encOutput         string
	encPassword       string
	encPasswordStdin  bool
	encKeyfiles       []string
	encKeyfileOrder   bool
	encComments       string
	encParanoid       bool
	encReedSolomon    bool
	encDeniability    bool
	encCompress       bool
	encSplit          bool
	encSplitSize      int
	encSplitUnit      string
	encQuiet          bool
	encYes            bool
	encFollowSymlinks bool
)

func init() {
	rootCmd.AddCommand(encryptCmd)

	// Input/Output
	encryptCmd.Flags().StringArrayVarP(&encGlob, "glob", "g", nil, "Add paths matching PATTERN (can be specified multiple times)")
	encryptCmd.Flags().StringArrayVarP(&encLegacyInputs, "input", "i", nil, "")
	_ = encryptCmd.Flags().MarkHidden("input")
	encryptCmd.Flags().StringVarP(&encOutput, "output", "o", "", "Output .pcv file path")

	// Credentials
	encryptCmd.Flags().StringVarP(&encPassword, "password", "p", "", "Encryption password")
	encryptCmd.Flags().BoolVarP(&encPasswordStdin, "password-stdin", "P", false, "Read password from stdin")
	encryptCmd.Flags().StringArrayVarP(&encKeyfiles, "keyfile", "k", nil, "Unavailable for encryption in 2.19; retained to return a migration error")
	encryptCmd.Flags().BoolVar(&encKeyfileOrder, "keyfile-ordered", false, "Unavailable while v2 keyfile writing is disabled")

	// Security options
	encryptCmd.Flags().StringVarP(&encComments, "comments", "c", "", "Comments to store in header (NOT encrypted)")
	encryptCmd.Flags().BoolVar(&encParanoid, "paranoid", false, "Enable paranoid mode (Serpent + XChaCha20, HMAC-SHA3)")
	encryptCmd.Flags().BoolVar(&encReedSolomon, "reed-solomon", false, "Enable Reed-Solomon error correction (6% overhead)")
	encryptCmd.Flags().BoolVar(&encDeniability, "deniability", false, "Add deniability wrapper (requires a non-empty password)")
	encryptCmd.Flags().BoolVar(&encCompress, "compress", false, "Compress files before encryption")

	// Split options
	encryptCmd.Flags().BoolVar(&encSplit, "split", false, "Split output into chunks")
	encryptCmd.Flags().IntVar(&encSplitSize, "split-size", 0, "Size of each chunk (requires --split)")
	encryptCmd.Flags().StringVar(&encSplitUnit, "split-unit", "MiB", "Unit for split size: KiB, MiB, GiB, TiB, or Total")

	// Other
	encryptCmd.Flags().BoolVarP(&encQuiet, "quiet", "q", false, "Suppress progress output")
	encryptCmd.Flags().BoolVarP(&encYes, "yes", "y", false, "Overwrite output file without prompting")
	encryptCmd.Flags().BoolVar(&encFollowSymlinks, "follow-symlinks", false, "Follow symlinks to regular files")
}

func defaultEncryptOutput(rawInput string, allFiles []string, onlyFolders []string, useStdin, payloadZip bool) string {
	extension := ".pcv"
	if payloadZip {
		extension = ".zip.pcv"
	}

	if useStdin {
		return "encrypted" + extension
	}

	if payloadZip && len(onlyFolders) == 1 && rawInput != "" {
		return rawInput + extension
	}
	if len(allFiles) == 1 && len(onlyFolders) == 0 {
		return allFiles[0] + extension
	}
	if len(allFiles) == 0 && rawInput != "" {
		return rawInput + extension
	}
	return "encrypted" + extension
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	if cmd.Flags().Changed("input") || len(encLegacyInputs) > 0 {
		return errors.New("--input/-i was removed; pass literal paths as arguments or use --glob for patterns")
	}
	if len(args) == 0 && len(encGlob) == 0 {
		return errors.New("at least one input path or --glob pattern is required")
	}

	// Check for stdin/stdout
	useStdout := IsStdout(encOutput)

	// A stdin operand must be the sole literal input, without glob patterns.
	hasStdinInput := false
	for _, input := range args {
		if IsStdin(input) {
			hasStdinInput = true
			break
		}
	}
	useStdin := len(args) == 1 && hasStdinInput && len(encGlob) == 0

	// Validate stdin/stdout constraints
	if hasStdinInput && !useStdin {
		return errors.New("stdin (-) cannot be combined with other input paths or --glob")
	}
	if useStdin && encPasswordStdin {
		return errors.New("cannot use -P (password from stdin) with - (input from stdin)")
	}
	if (useStdin || useStdout) && encSplit {
		return errors.New("stdin/stdout not compatible with --split")
	}
	if (useStdin || useStdout) && encDeniability {
		return errors.New("stdin/stdout not compatible with --deniability")
	}
	if len(encKeyfiles) > 0 {
		return perrors.NewKeyfileWritesDisabledError()
	}

	// Validate split options before any input buffering, temp creation,
	// overwrite confirmation, or credential prompting.
	var chunkSize int
	var chunkUnit fileops.SplitUnit
	if encSplit {
		if encSplitSize <= 0 {
			return errors.New("--split-size is required when --split is enabled")
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
		if _, err := fileops.ChunkSizeToBytes(chunkSize, chunkUnit); err != nil {
			return err
		}
	}

	// Keyfiles must exist before stdin buffering or stdout temp creation.
	for _, kf := range encKeyfiles {
		if _, err := os.Stat(kf); err != nil {
			return fmt.Errorf("keyfile not found: %s", kf)
		}
	}

	// Auto-quiet when outputting to stdout (avoid mixing progress with data)
	if useStdout {
		encQuiet = true
	}

	// Track temp files for cleanup. The stdin temp holds raw piped plaintext and
	// the stdout temp holds the .pcv output; both are removed when the run ends.
	var stdinTempFile string
	var stdoutTempFile string
	defer func() { cleanupTempFiles(stdinTempFile, stdoutTempFile) }()

	outputFile := encOutput
	if outputFile == "" && useStdin {
		outputFile = "encrypted.pcv"
		if encCompress {
			outputFile = "encrypted.zip.pcv"
		}
	}
	if outputFile != "" && !useStdout && !strings.HasSuffix(outputFile, ".pcv") {
		outputFile += ".pcv"
	}
	if useStdin && !useStdout {
		if err := validateEncryptOutputPaths(encryptInputs{}, encKeyfiles, outputFile, false); err != nil {
			return err
		}
	}
	if useStdin && !useStdout && !encYes {
		if info, err := os.Stat(outputFile); err == nil {
			if info.IsDir() {
				return fmt.Errorf("output path is a directory: %s", outputFile)
			}
			return fmt.Errorf("output file %s already exists; when reading input from stdin use -y to overwrite", outputFile)
		}
	}

	var inputs encryptInputs
	var err error

	// Handle stdin input
	if useStdin {
		stdinTempFile, err = BufferStdinToTemp(encOutput)
		if err != nil {
			return fmt.Errorf("buffering stdin: %w", err)
		}
		inputs.inputFiles = []string{stdinTempFile}
		inputs.onlyFiles = []string{stdinTempFile}
	} else {
		inputs, err = resolveEncryptInputs(args, encGlob, encFollowSymlinks)
		if err != nil {
			return err
		}
	}
	allFiles := inputs.inputFiles
	onlyFiles := inputs.onlyFiles
	onlyFolders := inputs.onlyFolders
	payloadZip := len(allFiles) > 1 || len(onlyFolders) > 0 || encCompress

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
		rawInput := ""
		if len(inputs.selections) == 1 {
			rawInput = inputs.selections[0]
		}
		outputFile = defaultEncryptOutput(rawInput, allFiles, onlyFolders, useStdin, payloadZip)
	}

	// Add .pcv extension if missing (not for stdout temp)
	if !useStdout && !strings.HasSuffix(outputFile, ".pcv") {
		outputFile += ".pcv"
	}

	// Validate output collisions before confirmation or password work.
	if !useStdin && !useStdout {
		if err := validateEncryptOutputPaths(inputs, encKeyfiles, outputFile, encSplit); err != nil {
			return err
		}
	}

	// Check if output exists (skip for stdout)
	if !useStdout {
		if info, err := os.Stat(outputFile); err == nil {
			if info.IsDir() {
				return fmt.Errorf("output path is a directory: %s", outputFile)
			}
			if !encYes {
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
	// a plain defer would bind the initial []byte(encPassword) at defer time.
	password := []byte(encPassword)
	defer func() { crypto.SecureZero(password) }()
	if encPasswordStdin {
		var err error
		password, err = ReadPasswordFromStdin()
		if err != nil {
			return err
		}
		if encDeniability && len(password) == 0 {
			return perrors.NewDeniabilityPasswordRequiredError()
		}
		if len(password) == 0 {
			return fmt.Errorf("password input: %w", ErrPasswordEmpty)
		}
	} else if len(password) == 0 {
		// Prompt for password interactively
		var err error
		password, err = ReadPasswordInteractive(true, encDeniability)
		if err != nil {
			return fmt.Errorf("password input: %w", err)
		}
	}
	if encDeniability && len(password) == 0 {
		return perrors.NewDeniabilityPasswordRequiredError()
	}

	// Initialize RS codecs
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return fmt.Errorf("initializing Reed-Solomon codecs: %w", err)
	}

	// Create reporter
	reporter := NewReporter(encQuiet)
	globalReporter.Store(reporter)

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
		destName := outputFile
		if useStdout {
			destName = "stdout"
		}
		srcName := fmt.Sprintf("%d file(s)", len(allFiles))
		if useStdin {
			srcName = "stdin"
		}
		fmt.Fprintf(os.Stderr, "Encrypting %s to %s\n", srcName, destName)
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
		// Core owns and removes every unpublished stage. If a later deniability
		// or split step fails after publication, retain the complete encrypted
		// volume instead of unlinking a pathname the CLI no longer owns.
		return err
	}

	// Stream to stdout if requested
	if useStdout {
		if err := StreamFileToStdout(outputFile); err != nil {
			return fmt.Errorf("streaming to stdout: %w", err)
		}
		return nil
	}

	reporter.PrintSuccess("Encryption completed successfully: %s", outputFile)
	return nil
}
