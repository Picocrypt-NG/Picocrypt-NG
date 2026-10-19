package cli

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/secret"
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

func init() { rootCmd.AddCommand(newVerifyCommand()) }

func newVerifyCommand() *cobra.Command {
	var deniability, passwordStdin, quiet bool
	var password, policyName, order string
	passwordFD := -1
	var keyfiles []string
	cmd := &cobra.Command{
		Use:   "verify VOLUME",
		Short: "Fully verify a PCV3 D1 volume without creating output",
		Long:  "Authenticate both D1 bootstraps and the complete outer/inner payload. Requires --deniability and an explicit --pcv3-factors policy. A healthy verification performs two fixed 1 GiB Argon2id derivations sequentially. The source is not modified; no plaintext file is created.",
		Args:  cobra.ExactArgs(1), SilenceErrors: true, SilenceUsage: true,
	}
	cmd.Flags().BoolVar(&deniability, "deniability", false, "Explicitly select PCV3 D1 input")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Verification password")
	cmd.Flags().BoolVarP(&passwordStdin, "password-stdin", "P", false, "Read password from stdin")
	cmd.Flags().IntVar(&passwordFD, "password-fd", -1, "Read password from inherited Unix file descriptor (3 or higher)")
	cmd.Flags().StringArrayVarP(&keyfiles, "keyfile", "k", nil, "Keyfile path(s)")
	cmd.Flags().StringVar(&policyName, "pcv3-factors", "", "PCV3 credential policy: password, keyfiles, or combined")
	cmd.Flags().StringVar(&order, "pcv3-keyfile-order", "", "PCV3 keyfile order: ordered or unordered")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")
	cmd.RunE = func(cmd *cobra.Command, args []string) (retErr error) {
		defer func() { password = ""; clear(keyfiles); keyfiles = nil }()
		if !deniability {
			return errors.New("verify requires explicit --deniability for PCV3 D1")
		}
		if args[0] == "-" {
			return errors.New("D1 verification requires a regular file path")
		}
		if passwordFD != -1 && passwordFD < 3 {
			return errors.New("--password-fd requires an inherited descriptor of 3 or higher")
		}
		passwordSources := 0
		for _, selected := range []bool{cmd.Flags().Changed("password"), passwordStdin, passwordFD >= 3} {
			if selected {
				passwordSources++
			}
		}
		if passwordSources > 1 {
			return errors.New("choose only one password source")
		}
		mode, keyMode, policy, err := pcv3CLIFactorPolicy(policyName, order, len(password) != 0, len(keyfiles))
		if err != nil {
			return err
		}
		if mode == pcv3operation.CredentialModeKeyfilesOnly && (passwordStdin || passwordFD >= 3) {
			return errors.New("keyfiles-only PCV3 policy cannot read a password")
		}
		passwordBytes := []byte(password)
		password = ""
		defer func() { secret.SecureZero(passwordBytes) }()
		switch {
		case passwordFD >= 3:
			passwordBytes, err = ReadPasswordFromFD(passwordFD)
		case passwordStdin:
			passwordBytes, err = ReadPasswordFromStdin()
		case mode != pcv3operation.CredentialModeKeyfilesOnly && len(passwordBytes) == 0:
			passwordBytes, err = ReadPasswordInteractive(false, false)
		}
		if err != nil {
			return err
		}
		request := &pcv3operation.D1VerifyRequest{Factors: &pcv3operation.FactorRequest{Mode: mode, KeyfileMode: keyMode, ExpectedPolicy: policy, Password: passwordBytes}}
		passwordBytes = nil
		defer func() {
			cleanupFailed := false
			if request.Factors != nil {
				cleanupFailed = request.Factors.Close() != nil || request.Factors.CleanupIncomplete()
			}
			if request.Source != nil {
				cleanupFailed = request.Source.Close() != nil || cleanupFailed
			}
			if cleanupFailed {
				retErr = errors.New("D1 verification cleanup could not be confirmed")
			}
		}()
		request.Source, err = fileops.OpenRegularReadNoSymlink(args[0])
		if err != nil {
			return errors.New("D1 source could not be opened safely")
		}
		for _, path := range keyfiles {
			file, err := fileops.OpenRegularReadNoSymlink(path)
			if err != nil {
				return errors.New("PCV3 keyfile could not be opened safely")
			}
			request.Factors.Keyfiles = append(request.Factors.Keyfiles, pcv3operation.OwnKeyfileReader(file))
		}
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()
		reporter := NewReporter(quiet)
		reporter.setCancel(cancel)
		defer reporter.setCancel(nil)
		globalReporter.Store(reporter)
		defer globalReporter.CompareAndSwap(reporter, nil)
		request.Reporter = reporter.PrintPCV3Status
		report := pcv3operation.VerifyD1(ctx, request)
		fmt.Fprintf(cmd.ErrOrStderr(), "D1 verification: front=%s tail=%s pair=%s payload=%s\n", d1CheckText(report.Front()), d1CheckText(report.Tail()), d1CheckText(report.Pair()), d1CheckText(report.Payload()))
		if report.CleanupIncomplete() {
			return errors.New("D1 verification cleanup could not be confirmed")
		}
		if report.Verified() {
			fmt.Fprintln(cmd.ErrOrStderr(), "D1 fully verified; no output created.")
			return nil
		}
		if report.Outcome() == pcv3operation.OutcomeOperationFailed {
			switch report.Diagnostic() {
			case pcv3operation.DiagnosticCancellation:
				return errors.New("D1 verification cancelled")
			case pcv3operation.DiagnosticResourceInsufficient, pcv3operation.DiagnosticResourceUnknown, pcv3operation.DiagnosticResourceBusy:
				return errors.New("D1 verification could not obtain the required KDF resources")
			default:
				return fmt.Errorf("D1 verification operational failure at %s", report.Stage())
			}
		}
		return errors.New("D1 could not be fully verified; credentials or volume damage may prevent authentication")
	}
	return cmd
}

func d1CheckText(state pcv3operation.D1CheckState) string {
	switch state {
	case pcv3operation.D1CheckPassed:
		return "passed"
	case pcv3operation.D1CheckFailed:
		return "not authenticated"
	default:
		return "unchecked"
	}
}
