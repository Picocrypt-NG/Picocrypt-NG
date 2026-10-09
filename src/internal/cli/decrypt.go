package cli

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/secret"
	"Picocrypt-NG/internal/volume"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
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
PCV3 requires an explicit expected factor policy. Legacy v1/v2 remains readable
without the PCV3 flags. Deniable PCV3 input also requires --pcv3-format=d1.

Pass the volume as a literal operand. Use -- before a volume filename that
begins with -.

Examples:
  # Decrypt interactively (prompts for password)
	  Picocrypt-NG decrypt secret.pcv --pcv3-factors=password -o secret.txt

  # Decrypt with password on command line (visible in shell history)
	  Picocrypt-NG decrypt secret.pcv --pcv3-factors=password -o secret.txt -p "mypassword"

  # Decrypt with password and keyfile
	  Picocrypt-NG decrypt secret.pcv --pcv3-factors=combined --pcv3-keyfile-order=unordered -k keyfile.key

  # Decrypt with keyfile only, no password prompt
	  Picocrypt-NG decrypt secret.pcv --pcv3-factors=keyfiles --pcv3-keyfile-order=unordered -k keyfile.key -p ""

  # Decrypt and auto-extract zip
	  Picocrypt-NG decrypt archive.pcv --pcv3-factors=password --pcv3-archive=extract --pcv3-extract-to=./extracted

  # Legacy v1/v2 Force decryption (may produce corrupted output)
	  Picocrypt-NG decrypt damaged.pcv --force

  # Read password from stdin (for scripts)
	  echo "mypassword" | Picocrypt-NG decrypt secret.pcv --pcv3-factors=password -P

  # Decrypt from stdin (use -p since stdin is taken by data)
	  curl https://example.com/file.pcv | Picocrypt-NG decrypt - --pcv3-factors=password -o file.txt -p "pw"

  # Decrypt to stdout
	  Picocrypt-NG decrypt secret.pcv --pcv3-factors=password -o - -p "pw" | less`,
	Args: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("input") {
			return errors.New("--input/-i was removed; pass the volume path as an argument")
		}
		return cobra.ExactArgs(1)(cmd, args)
	},
	RunE: runDecrypt,
}

type pcv3CLIArchiveFollowUp interface {
	Extract(context.Context, *os.Root) pcv3CLIResult
	Close() pcv3CLIResult
}

type pcv3CLIOutputFollowUp interface {
	StreamTo(context.Context, *os.File) pcv3operation.OutputActionResult
}

type pcv3CLIResult interface {
	Outcome() pcv3operation.Outcome
	Stage() pcv3operation.Stage
	Code() pcv3operation.Code
	PublicationAttempted() bool
	PublicationState() pcv3publication.State
	PublicationStage() pcv3operation.Stage
	PublicationCode() pcv3publication.Code
	Warnings() []pcv3operation.Warning
	WithCleanupWarning()
	CompletionClass() pcv3operation.CompletionClass
	ArchiveFollowUp() pcv3CLIArchiveFollowUp
	OutputFollowUp() pcv3CLIOutputFollowUp
}

type pcv3CLIResultAdapter struct {
	result *pcv3operation.Result
}

func (adapter pcv3CLIResultAdapter) Outcome() pcv3operation.Outcome { return adapter.result.Outcome() }

func (adapter pcv3CLIResultAdapter) Stage() pcv3operation.Stage { return adapter.result.Stage() }
func (adapter pcv3CLIResultAdapter) Code() pcv3operation.Code   { return adapter.result.Code() }

func (adapter pcv3CLIResultAdapter) AuthenticatedComment() string {
	return adapter.result.AuthenticatedComment()
}

func (adapter pcv3CLIResultAdapter) SplitOutputUncertain() bool {
	return adapter.result.SplitOutputUncertain()
}

func (adapter pcv3CLIResultAdapter) PublicationAttempted() bool {
	return adapter.result.PublicationAttempted()
}

func (adapter pcv3CLIResultAdapter) PublicationState() pcv3publication.State {
	return adapter.result.PublicationState()
}

func (adapter pcv3CLIResultAdapter) PublicationStage() pcv3operation.Stage {
	return adapter.result.PublicationStage()
}

func (adapter pcv3CLIResultAdapter) PublicationCode() pcv3publication.Code {
	return adapter.result.PublicationCode()
}

func (adapter pcv3CLIResultAdapter) Warnings() []pcv3operation.Warning {
	return adapter.result.Warnings()
}

func (adapter pcv3CLIResultAdapter) WithCleanupWarning() {
	adapter.result.WithCleanupWarning()
}

func (adapter pcv3CLIResultAdapter) CompletionClass() pcv3operation.CompletionClass {
	return adapter.result.CompletionClass()
}

func (adapter pcv3CLIResultAdapter) ArchiveFollowUp() pcv3CLIArchiveFollowUp {
	followUp := adapter.result.ArchiveFollowUp()
	if followUp == nil {
		return nil
	}
	return pcv3CLIArchiveAdapter{followUp: followUp}
}

func (adapter pcv3CLIResultAdapter) OutputFollowUp() pcv3CLIOutputFollowUp {
	followUp := adapter.result.OutputFollowUp()
	if followUp == nil {
		return nil
	}
	return followUp
}

type pcv3CLIArchiveAdapter struct {
	followUp *pcv3operation.ArchiveFollowUp
}

func (adapter pcv3CLIArchiveAdapter) Extract(ctx context.Context, root *os.Root) pcv3CLIResult {
	return pcv3CLIResultAdapter{result: adapter.followUp.Extract(ctx, root)}
}

func (adapter pcv3CLIArchiveAdapter) Close() pcv3CLIResult {
	return pcv3CLIResultAdapter{result: adapter.followUp.Close()}
}

var (
	pcv3CLIRunOperation = func(
		ctx context.Context,
		request *pcv3operation.Request,
		retainOutput bool,
	) pcv3CLIResult {
		return pcv3CLIResultAdapter{result: pcv3operation.RunWithOptions(
			ctx,
			request,
			pcv3operation.ExecutionOptions{RetainDurableOutput: retainOutput},
		)}
	}
	pcv3CLIOpenKeyfile   = fileops.OpenRegularReadNoSymlink
	pcv3CLIIsInteractive = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	pcv3CLIReadConsent   = readConsentLine
)

const pcv3UnavailableMessage = "this PCV volume is not supported by this version; no output was created"

type pcv3UnavailableError struct {
	cause error
}

func (err pcv3UnavailableError) Error() string {
	return pcv3UnavailableMessage
}

func (err pcv3UnavailableError) Unwrap() error {
	return err.cause
}

func translatePCV3PreflightError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pcv3operation.ErrReaderUnavailable) {
		return pcv3UnavailableError{cause: err}
	}
	var failure pcv3operation.Failure
	if errors.As(err, &failure) && failure.Outcome() != pcv3operation.OutcomeOperationFailed {
		return pcv3UnavailableError{cause: err}
	}
	return err
}

// Decrypt flags
var (
	decLegacyInputs  []string
	decOutput        string
	decPassword      string
	decPasswordStdin bool
	decPasswordFD    int
	decKeyfiles      []string
	decForce         bool
	decVerifyFirst   bool
	decAutoUnzip     bool
	decSameLevel     bool
	decRecombine     bool
	decDeniability   bool
	decQuiet         bool
	decYes           bool
	decPCV3Format    string
	decPCV3Action    string
	decPCV3Factors   string
	decPCV3Order     string
	decPCV3Role      string
	decPCV3Archive   string
	decPCV3ExtractTo string
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
	decryptCmd.Flags().IntVar(&decPasswordFD, "password-fd", -1, "Read password from inherited Unix file descriptor (3 or higher)")
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

	decryptCmd.Flags().StringVar(&decPCV3Format, "pcv3-format", "", "PCV3 format intent: d1")
	decryptCmd.Flags().StringVar(&decPCV3Action, "pcv3-action", "", "PCV3 action: recovery or force")
	decryptCmd.Flags().StringVar(&decPCV3Factors, "pcv3-factors", "", "PCV3 credential policy: password, keyfiles, or combined")
	decryptCmd.Flags().StringVar(&decPCV3Order, "pcv3-keyfile-order", "", "PCV3 keyfile order: ordered or unordered")
	decryptCmd.Flags().StringVar(&decPCV3Role, "pcv3-role", "", "PCV3 unverified physical role")
	decryptCmd.Flags().StringVar(&decPCV3Archive, "pcv3-archive", "", "PCV3 archive action: extract or close")
	decryptCmd.Flags().StringVar(&decPCV3ExtractTo, "pcv3-extract-to", "", "Existing directory for PCV3 archive extraction")
}

func runDecrypt(cmd *cobra.Command, args []string) (retErr error) {
	if cmd.Flags().Changed("input") || len(decLegacyInputs) > 0 {
		return errors.New("--input/-i was removed; pass the volume path as an argument")
	}
	if err := cobra.ExactArgs(1)(cmd, args); err != nil {
		return err
	}
	inputPath := args[0]
	pcv3Explicit := decPCV3Format != "" || decPCV3Action != "" || decPCV3Factors != "" ||
		decPCV3Order != "" || decPCV3Role != "" || decPCV3Archive != "" || decPCV3ExtractTo != ""

	// Check for stdin/stdout
	useStdin := IsStdin(inputPath)
	useStdout := IsStdout(decOutput)
	passwordFDSet := cmd.Flags().Changed("password-fd")

	// Validate stdin/stdout constraints
	if useStdin && decPasswordStdin {
		return errors.New("cannot use -P (password from stdin) with - (input from stdin)")
	}
	if passwordFDSet {
		if decPasswordFD < 3 {
			return errors.New("--password-fd must be 3 or higher")
		}
		if decPasswordStdin || cmd.Flags().Changed("password") {
			return errors.New("--password-fd cannot be combined with -p or -P")
		}
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
	if pcv3Explicit {
		if err := validatePCV3CLICompatibility(); err != nil {
			return err
		}
		if decPCV3Format != "" && decPCV3Format != "d1" {
			return errors.New("invalid --pcv3-format; use d1")
		}
	}

	// Detect legacy split naming before PCV3 routing so a claimed PCV3 chunk is
	// rejected as an unsupported split input rather than treated as a volume.
	// The legacy informational message remains deferred until routing completes.
	autoDetectedSplit := false
	if !useStdin && strings.Contains(inputPath, ".pcv.") && !decRecombine {
		ext := inputPath[strings.LastIndex(inputPath, ".pcv.")+5:]
		if _, err := fmt.Sscanf(ext, "%d", new(int)); err == nil {
			decRecombine = true
			autoDetectedSplit = true
		}
	}

	// Auto-quiet when outputting to stdout
	if useStdout {
		decQuiet = true
	}

	// Track temp files for cleanup. The stdout temp holds decrypted plaintext and
	// the stdin temp holds the .pcv input; both are removed when the run ends.
	var stdinTempFile string
	var stdoutTempFile string
	defer func() {
		retErr = errors.Join(retErr, cleanupTempFiles(stdinTempFile, stdoutTempFile))
	}()

	outputFile := decOutput
	if outputFile == "" {
		if useStdin {
			outputFile = "decrypted"
		} else if filepath.Base(inputPath) == ".pcv" {
			outputFile = inputPath + ".decrypted"
		} else {
			outputFile = strings.TrimSuffix(inputPath, ".pcv")
			if decRecombine {
				if idx := strings.LastIndex(outputFile, ".pcv."); idx > 0 {
					outputFile = outputFile[:idx]
				}
			}
			if outputFile == inputPath {
				outputFile = inputPath + ".decrypted"
			}
		}
	}

	// Handle stdin input
	inputFile := inputPath
	leafIsSymlink := false
	if useStdin {
		var err error
		stdinTempFile, err = BufferStdinToTemp(decOutput)
		if err != nil {
			return fmt.Errorf("buffering stdin: %w", err)
		}
		inputFile = stdinTempFile
	} else {
		leafInfo, err := os.Lstat(inputPath)
		if err != nil {
			return fmt.Errorf("input file not found: %s", inputPath)
		}
		leafIsSymlink = leafInfo.Mode()&os.ModeSymlink != 0
		if leafIsSymlink && pcv3Explicit {
			return errors.New("input source must not be a symlink")
		}
		inputInfo, err := os.Stat(inputPath)
		if err != nil {
			return fmt.Errorf("input file not found: %s", inputPath)
		}
		if inputInfo.IsDir() {
			return fmt.Errorf("input must be a file, not a directory: %s", inputPath)
		}
	}

	// Route a direct input from the same no-follow descriptor that is handed to
	// PCV3. Once the normal discriminator is claimed, structural damage is still
	// a PCV3 result and must never fall back to the legacy reader.
	pcv3RoutePath := inputFile
	pcv3RouteDirect := !leafIsSymlink
	preparePCV3Target := func() (string, error) {
		if !useStdout {
			decOutput = outputFile
			return "", nil
		}
		path, err := CreateTempOutput(0)
		if err != nil {
			return "", err
		}
		stdoutTempFile = path
		if err := os.Remove(path); err != nil {
			return "", fmt.Errorf("prepare PCV3 stdout target: %w", err)
		}
		decOutput = path
		return path, nil
	}
	if !useStdin && !leafIsSymlink && decRecombine {
		prepared, err := volume.PrepareDecryptInputContext(cmd.Context(), inputFile, true)
		if err != nil {
			return err
		}
		normal := prepared.ClaimsNormalPCV3()
		if normal || decPCV3Format == "d1" {
			if decPCV3Format == "d1" {
				normal = false
			}
			source := prepared.DetachSource()
			if source == nil {
				return errors.Join(errors.New("PCV3 split source is unavailable"), prepared.Close())
			}
			stdoutPath, outputErr := preparePCV3Target()
			if outputErr != nil {
				return errors.Join(outputErr, source.Close(), prepared.Close())
			}
			if stdoutPath != "" {
				stdoutTempFile = ""
			}
			splitBase := inputFile
			if base, ok := fileops.SplitChunkBase(inputFile); ok {
				splitBase = base
			}
			decRecombine = false
			return errors.Join(
				runPCV3CLI(cmd.Context(), source, normal, stdoutPath, splitBase),
				prepared.Close(),
			)
		}
		if err := prepared.Close(); err != nil {
			return err
		}
	}
	if !useStdin && decRecombine && decPCV3Format != "d1" {
		base := inputFile
		if chunkBase, ok := fileops.SplitChunkBase(inputFile); ok {
			base = chunkBase
		}
		pcv3RoutePath = base + ".0"
		routeInfo, err := os.Lstat(pcv3RoutePath)
		pcv3RouteDirect = pcv3RouteDirect && err == nil && routeInfo.Mode()&os.ModeSymlink == 0
	}
	if pcv3RouteDirect {
		pcv3Source, err := fileops.OpenExistingNoSymlink(pcv3RoutePath, os.O_RDONLY)
		if err != nil {
			return errors.New("input source could not be opened safely")
		}
		pcv3SourceTransferred := false
		defer func() {
			if !pcv3SourceTransferred {
				_ = pcv3Source.Close()
			}
		}()

		info, err := pcv3Source.Stat()
		if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
			return errors.New("input source is not a regular file")
		}
		if decPCV3Format == "d1" {
			stdoutPath, outputErr := preparePCV3Target()
			if outputErr != nil {
				return outputErr
			}
			if stdoutPath != "" {
				stdoutTempFile = ""
			}
			pcv3SourceTransferred = true
			if err := runPCV3CLI(cmd.Context(), pcv3Source, false, stdoutPath, ""); err != nil {
				return err
			}
			return nil
		}
		route, probeErr := pcv3operation.Probe(pcv3Source, info.Size())
		if route == pcv3operation.RouteNormalPCV {
			stdoutPath, outputErr := preparePCV3Target()
			if outputErr != nil {
				return outputErr
			}
			if stdoutPath != "" {
				stdoutTempFile = ""
			}
			pcv3SourceTransferred = true
			if err := runPCV3CLI(cmd.Context(), pcv3Source, true, stdoutPath, ""); err != nil {
				return err
			}
			return nil
		}
		if probeErr != nil {
			return errors.New("input source could not be classified safely")
		}
		if pcv3Explicit {
			return errors.New("normal PCV3 must be selected by content; use --pcv3-format=d1 for D1")
		}
		if err := pcv3Source.Close(); err != nil {
			return errors.New("input routing descriptor could not be closed")
		}
		pcv3SourceTransferred = true
	}

	preparedInput, err := volume.PrepareDecryptInputContext(cmd.Context(), inputFile, decRecombine)
	if err != nil {
		var failure pcv3operation.Failure
		if useStdin && (errors.Is(err, pcv3operation.ErrReaderUnavailable) ||
			(errors.As(err, &failure) && failure.Outcome() != pcv3operation.OutcomeOperationFailed)) {
			return errors.New("PCV3 input from stdin could not be routed safely")
		}
		return err
	}
	defer func() { retErr = errors.Join(retErr, preparedInput.Close()) }()
	if pcv3Explicit {
		return errors.New("normal PCV3 must be selected by content; use --pcv3-format=d1 for D1")
	}
	if autoDetectedSplit && !decQuiet {
		fmt.Fprintln(os.Stderr, "Detected split volume. Use --recombine to recombine chunks first.")
	}

	if useStdin && !useStdout && !decYes {
		if info, err := os.Stat(outputFile); err == nil {
			if info.IsDir() {
				return fmt.Errorf("output path is a directory: %s", outputFile)
			}
			return fmt.Errorf("output file %s already exists; when reading input from stdin use -y to overwrite", outputFile)
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
	}

	// Reject protected aliases before an overwrite confirmation or password
	// prompt. The core repeats this check immediately before publication.
	if err := (&volume.DecryptRequest{
		InputFile:  inputFile,
		OutputFile: outputFile,
		Keyfiles:   decKeyfiles,
		Recombine:  decRecombine,
	}).ValidateOutputSafety(); err != nil {
		return err
	}
	if err := preparedInput.ValidateOutputAlias(outputFile); err != nil {
		return err
	}

	// A non-same-level auto-unzip publishes into a directory that is not an
	// overwriteable output file. Refuse an occupied extraction root before
	// prompting for credentials or deriving keys; --yes only applies to the
	// decrypted archive file itself.
	if decAutoUnzip && !decSameLevel {
		extractRoot := outputFile
		if strings.HasSuffix(outputFile, ".zip") {
			extractRoot = filepath.Join(
				filepath.Dir(outputFile),
				strings.TrimSuffix(filepath.Base(outputFile), ".zip"),
			)
		}
		if _, err := os.Lstat(extractRoot); err == nil {
			return fmt.Errorf(
				"auto-unzip extraction root already exists and --yes does not authorize replacing it: %s: %w",
				extractRoot,
				os.ErrExist,
			)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect auto-unzip extraction root %s: %w", extractRoot, err)
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
	// A closure (not `defer secret.SecureZero(password)`) so the FINAL value is
	// zeroed — password is reassigned below by the stdin/interactive readers, and
	// a plain defer would bind the initial []byte(decPassword) at defer time.
	password := []byte(decPassword)
	defer func() { secret.SecureZero(password) }()
	if passwordFDSet {
		var err error
		secret.SecureZero(password)
		password, err = ReadPasswordFromFD(decPasswordFD)
		if err != nil {
			return err
		}
	} else if decPasswordStdin {
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
		hdr, headerErr := preparedInput.ReadLegacyHeader(rsCodecs)
		if headerErr != nil {
			translated := translatePCV3PreflightError(headerErr)
			var unavailable pcv3UnavailableError
			if errors.As(translated, &unavailable) {
				return translated
			}
		} else {
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
	operationCtx, cancelOperation := context.WithCancel(cmd.Context())
	reporter.setCancel(cancelOperation)
	defer func() {
		reporter.setCancel(nil)
		cancelOperation()
	}()
	globalReporter.Store(reporter)
	defer globalReporter.CompareAndSwap(reporter, nil)

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
	err = volume.DecryptPrepared(operationCtx, req, preparedInput)
	err = errors.Join(err, preparedInput.Close())
	reporter.Finish()

	if err != nil {
		reporter.PrintError("%v", err)
		return err
	}

	// Stream to stdout if requested
	if useStdout {
		stdoutTempFile = ""
		if err := StreamFileToStdout(operationCtx, outputFile); err != nil {
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

func runPCV3CLI(
	ctx context.Context,
	source *os.File,
	normal bool,
	stdoutPath string,
	splitBase string,
) (retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	request := &pcv3operation.Request{Source: source}
	transferred := false
	defer func() {
		if transferred {
			return
		}
		cleanupFailed := false
		if request.Factors != nil {
			cleanupFailed = request.Factors.Close() != nil
			request.Factors = nil
		}
		if request.Source != nil {
			cleanupFailed = request.Source.Close() != nil || cleanupFailed
			request.Source = nil
		}
		request.SplitBase = ""
		request.Target = ""
		for index := range request.Protected {
			request.Protected[index] = ""
		}
		request.Protected = nil
		request.Consent = nil
		request.Reporter = nil
		if cleanupFailed {
			retErr = errors.New("PCV3 request cleanup could not be confirmed")
		}
	}()
	if source == nil {
		return errors.New("PCV3 source is unavailable")
	}
	defer func() {
		decPassword = ""
		for index := range decKeyfiles {
			decKeyfiles[index] = ""
		}
		decKeyfiles = nil
	}()
	if err := validatePCV3CLICompatibility(); err != nil {
		return err
	}
	if decForce {
		return errors.New("legacy --force cannot authorize a PCV3 operation; use --pcv3-action")
	}
	if decPCV3Factors == "" {
		return errors.New("PCV3 requires explicit --pcv3-factors=password|keyfiles|combined")
	}
	if decOutput == "" || decOutput == "-" {
		return errors.New("PCV3 requires an explicit file destination")
	}
	if err := requireVacantPCV3Output(decOutput); err != nil {
		return err
	}
	if !normal && (decPCV3Archive != "" || decPCV3ExtractTo != "") {
		return errors.New("D1 archive payload is returned as a .zip file; D1 automatic extraction is not available")
	}
	switch decPCV3Archive {
	case "", "close":
		if decPCV3ExtractTo != "" {
			return errors.New("--pcv3-extract-to requires --pcv3-archive=extract")
		}
	case "extract":
		if decPCV3ExtractTo == "" {
			return errors.New("--pcv3-archive=extract requires --pcv3-extract-to")
		}
	default:
		return errors.New("invalid --pcv3-archive; use extract or close")
	}
	mode, needsConsent, err := pcv3CLIMode(normal, decPCV3Action, decPCV3Role)
	if err != nil {
		return err
	}
	factorMode, keyfileMode, policy, err := pcv3CLIFactorPolicy(
		decPCV3Factors,
		decPCV3Order,
		len(decPassword) > 0,
		len(decKeyfiles),
	)
	if err != nil {
		return err
	}
	password := []byte(decPassword)
	decPassword = ""
	defer func() { secret.SecureZero(password) }()
	if decPasswordFD >= 3 {
		if factorMode == pcv3operation.CredentialModeKeyfilesOnly {
			return errors.New("keyfiles-only PCV3 policy cannot read a password from a file descriptor")
		}
		secret.SecureZero(password)
		password, err = ReadPasswordFromFD(decPasswordFD)
		if err != nil {
			return err
		}
	} else if decPasswordStdin {
		if factorMode == pcv3operation.CredentialModeKeyfilesOnly {
			return errors.New("keyfiles-only PCV3 policy cannot read a password from stdin")
		}
		secret.SecureZero(password)
		password, err = ReadPasswordFromStdin()
		if err != nil {
			return err
		}
	}
	if (factorMode == pcv3operation.CredentialModePasswordOnly ||
		factorMode == pcv3operation.CredentialModePasswordAndKeyfiles) && len(password) == 0 {
		password, err = ReadPasswordInteractive(false, false)
		if err != nil {
			return fmt.Errorf("password input: %w", err)
		}
	}

	request.Mode = mode
	request.Target = decOutput
	decOutput = ""
	request.SplitBase = splitBase
	request.Protected = append([]string(nil), decKeyfiles...)

	request.Factors = &pcv3operation.FactorRequest{
		Mode:           factorMode,
		KeyfileMode:    keyfileMode,
		ExpectedPolicy: policy,
		Password:       password,
		Keyfiles:       make([]*pcv3operation.KeyfileReader, 0, len(decKeyfiles)),
	}
	password = nil
	for _, path := range decKeyfiles {
		file, openErr := pcv3CLIOpenKeyfile(path)
		if openErr != nil {
			return errors.New("PCV3 keyfile could not be opened safely")
		}
		info, statErr := file.Stat()
		if statErr != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
			_ = file.Close()
			return errors.New("PCV3 keyfile must be a regular file")
		}
		request.Factors.Keyfiles = append(
			request.Factors.Keyfiles,
			pcv3operation.OwnKeyfileReader(file),
		)
	}
	for index := range decKeyfiles {
		decKeyfiles[index] = ""
	}
	decKeyfiles = nil
	operationCtx, cancelOperation := context.WithCancel(ctx)
	defer cancelOperation()
	if needsConsent {
		selectedRole, ok := pcv3CLIPhysicalRole(normal, decPCV3Role)
		if !ok {
			return errors.New("PCV3 unverified Force requires a valid explicit physical role")
		}
		request.Consent = pcv3CLIConsent(operationCtx, selectedRole)
	}

	reporter := NewReporter(decQuiet)
	request.Reporter = reporter.PrintPCV3Status
	reporter.setCancel(cancelOperation)
	defer reporter.setCancel(nil)
	globalReporter.Store(reporter)
	defer globalReporter.CompareAndSwap(reporter, nil)
	transferred = true
	result := pcv3CLIRunOperation(operationCtx, request, stdoutPath != "")
	result = finishPCV3CLIArchive(operationCtx, result, decPCV3Archive, decPCV3ExtractTo)
	transportErr := finishPCV3CLIStdout(operationCtx, result, stdoutPath != "")
	exitCode := renderPCV3CLIResult(os.Stderr, result)
	if transportErr != nil {
		return transportErr
	}
	if exitCode != 0 {
		return newExitCodeError(exitCode, "PCV3 operation did not complete cleanly")
	}
	return nil
}

func requireVacantPCV3Output(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return errors.New("PCV3 output already exists; choose a different path (--yes does not replace PCV3 outputs)")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("PCV3 output path could not be inspected safely")
	}
	return nil
}

func validatePCV3CLICompatibility() error {
	if decDeniability || decVerifyFirst ||
		decAutoUnzip || decSameLevel {
		return errors.New("PCV3 does not support legacy transform flags")
	}
	return nil
}

func pcv3CLIMode(normal bool, action, role string) (pcv3operation.Mode, bool, error) {
	switch action {
	case "":
		if role != "" {
			return 0, false, errors.New("--pcv3-role is valid only for unverified Force")
		}
		if normal {
			return pcv3operation.ModeReadNormal, false, nil
		}
		return pcv3operation.ModeReadD1, false, nil
	case "recovery":
		if role != "" {
			return 0, false, errors.New("--pcv3-role is valid only for unverified Force")
		}
		if normal {
			return pcv3operation.ModeRecoverNormal, false, nil
		}
		return pcv3operation.ModeRecoverD1, false, nil
	case "force":
		if role == "" {
			if normal {
				return pcv3operation.ModeForceNormal, false, nil
			}
			return pcv3operation.ModeForceD1, false, nil
		}
		if normal {
			return pcv3operation.ModeForceUnverifiedNormal, true, nil
		}
		return pcv3operation.ModeForceUnverifiedD1, true, nil
	default:
		return 0, false, errors.New("invalid --pcv3-action; use recovery or force")
	}
}

func pcv3CLIFactorPolicy(
	policyName,
	orderName string,
	hasPassword bool,
	keyfileCount int,
) (pcv3operation.CredentialMode, pcv3operation.KeyfileMode, pcv3operation.FactorPolicy, error) {
	var order pcv3operation.KeyfileMode
	switch orderName {
	case "":
		order = pcv3operation.KeyfileModeNone
	case "ordered":
		order = pcv3operation.KeyfileModeOrdered
	case "unordered":
		order = pcv3operation.KeyfileModeUnordered
	default:
		return 0, 0, 0, errors.New("invalid --pcv3-keyfile-order; use ordered or unordered")
	}
	switch policyName {
	case "password":
		if keyfileCount != 0 || order != pcv3operation.KeyfileModeNone {
			return 0, 0, 0, errors.New("password-only PCV3 policy cannot include keyfiles or keyfile order")
		}
		return pcv3operation.CredentialModePasswordOnly, order,
			pcv3operation.FactorPolicyPasswordOnly, nil
	case "keyfiles":
		if hasPassword || keyfileCount == 0 || order == pcv3operation.KeyfileModeNone {
			return 0, 0, 0, errors.New("keyfiles-only PCV3 policy requires keyfiles, explicit order, and an empty password")
		}
		return pcv3operation.CredentialModeKeyfilesOnly, order,
			pcv3operation.FactorPolicyKeyfilesOnly, nil
	case "combined":
		if keyfileCount == 0 || order == pcv3operation.KeyfileModeNone {
			return 0, 0, 0, errors.New("combined PCV3 policy requires keyfiles and explicit order")
		}
		return pcv3operation.CredentialModePasswordAndKeyfiles, order,
			pcv3operation.FactorPolicyPasswordAndKeyfiles, nil
	default:
		return 0, 0, 0, errors.New("invalid --pcv3-factors; use password, keyfiles, or combined")
	}
}

func pcv3CLIPhysicalRole(normal bool, name string) (pcv3operation.PhysicalRole, bool) {
	if normal {
		switch name {
		case "primary":
			return pcv3operation.RolePrimary, true
		case "backup":
			return pcv3operation.RoleBackup, true
		}
		return pcv3operation.RoleNone, false
	}
	switch name {
	case "front":
		return pcv3operation.RoleD1Front, true
	case "tail":
		return pcv3operation.RoleD1Tail, true
	default:
		return pcv3operation.RoleNone, false
	}
}

func pcv3CLIConsent(ctx context.Context, selected pcv3operation.PhysicalRole) pcv3operation.Consent {
	return func(request pcv3operation.ConsentRequest, action pcv3operation.ConsentAction) error {
		if action == nil || !pcv3CLIIsInteractive() {
			return pcv3operation.ErrConsentExpired
		}
		allowed := false
		for _, role := range request.AllowedRoles() {
			if role == selected {
				allowed = true
				break
			}
		}
		if !allowed {
			return pcv3operation.ErrConsentRole
		}
		fmt.Fprintln(os.Stderr, "Type RECOVER UNVERIFIED to authorize this unverified recovery:")
		line, err := pcv3CLIReadConsent(ctx)
		if ctx.Err() != nil {
			return nil //nolint:nilerr // The runner owns cancellation classification; no action was authorized.
		}
		if err != nil || line != "RECOVER UNVERIFIED" {
			return pcv3operation.ErrConsentExpired
		}
		return action(selected)
	}
}

func finishPCV3CLIArchive(
	ctx context.Context,
	result pcv3CLIResult,
	action, destination string,
) pcv3CLIResult {
	if result == nil || result.CompletionClass() != pcv3operation.CompletionArchivePending {
		return result
	}
	followUp := result.ArchiveFollowUp()
	if followUp == nil {
		return nil
	}
	if action == "extract" && destination != "" {
		root, err := fileops.OpenRootNoSymlink(destination)
		if err != nil {
			return followUp.Extract(ctx, nil)
		}
		return followUp.Extract(ctx, root)
	}
	return followUp.Close()
}
