package ui

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

//go:embed translation/*.json
var translationFS embed.FS

var localizationState = newLocalizationState()

type localizationRuntime struct {
	mu      sync.RWMutex
	once    sync.Once
	loadErr error

	bundle    *i18n.Bundle
	localizer *i18n.Localizer
	active    LanguageCode
	loaded    map[LanguageCode]bool
	tags      map[LanguageCode]string
}

func newLocalizationState() *localizationRuntime {
	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("json", json.Unmarshal)
	return &localizationRuntime{
		bundle:    bundle,
		localizer: i18n.NewLocalizer(bundle, "en"),
		active:    "en",
		loaded:    map[LanguageCode]bool{},
		tags:      map[LanguageCode]string{},
	}
}

func loadTranslations() error {
	localizationState.once.Do(func() {
		localizationState.loadErr = loadTranslationsFromFS(translationFS)
	})
	return localizationState.loadErr
}

func loadTranslationsFromFS(files fs.FS) error {
	const dir = "translation"

	entries, err := fs.ReadDir(files, dir)
	if err != nil {
		return err
	}

	localizationState.mu.Lock()
	defer localizationState.mu.Unlock()

	var firstErr error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.ToSlash(filepath.Join(dir, entry.Name()))
		data, readErr := fs.ReadFile(files, path)
		if readErr != nil {
			if firstErr == nil {
				firstErr = readErr
			}
			continue
		}
		messageFile, parseErr := localizationState.bundle.ParseMessageFileBytes(data, entry.Name())
		if parseErr != nil {
			if firstErr == nil {
				firstErr = parseErr
			}
			continue
		}
		code := LanguageCode(strings.TrimSuffix(entry.Name(), ".json"))
		localizationState.loaded[code] = true
		localizationState.tags[code] = messageFile.Tag.String()
	}
	if !localizationState.loaded["en"] {
		return errors.New("translation/en.json is required")
	}
	localizationState.active = "en"
	localizationState.localizer = i18n.NewLocalizer(localizationState.bundle, "en")
	return firstErr
}

func setActiveLanguage(code LanguageCode) error {
	localizationState.mu.Lock()
	defer localizationState.mu.Unlock()

	if code == "" {
		code = "en"
	}
	if !localizationState.loaded[code] {
		return fmt.Errorf("language %q is not bundled", code)
	}
	localizationState.active = code
	tag := localizationState.tags[code]
	if tag == "" {
		tag = string(code)
	}
	localizationState.localizer = i18n.NewLocalizer(localizationState.bundle, tag, "en")
	return nil
}

func activeLanguage() LanguageCode {
	localizationState.mu.RLock()
	defer localizationState.mu.RUnlock()
	return localizationState.active
}

func (l *localizationRuntime) loadedCodes() map[LanguageCode]bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make(map[LanguageCode]bool, len(l.loaded))
	for code, loaded := range l.loaded {
		out[code] = loaded
	}
	return out
}

func tr(key, fallback string, data ...any) string {
	return localize(key, fallback, 0, false, data...)
}

func trn(key, fallback string, count int, data ...any) string {
	return localize(key, fallback, count, true, data...)
}

func localize(key, fallback string, count int, plural bool, data ...any) string {
	localizationState.mu.RLock()
	localizer := localizationState.localizer
	localizationState.mu.RUnlock()

	var d0 any
	if len(data) > 0 {
		d0 = data[0]
	}
	config := &i18n.LocalizeConfig{
		MessageID: key,
		DefaultMessage: &i18n.Message{
			ID:    key,
			Other: fallback,
		},
		TemplateData: d0,
	}
	if plural {
		config.PluralCount = count
	}
	text, err := localizer.Localize(config)
	if err != nil {
		return fallbackWithData(key, fallback, d0)
	}
	return text
}

func fallbackWithData(key, fallback string, data any) string {
	t, err := template.New(key).Parse(fallback)
	if err != nil {
		return fallback
	}
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return fallback
	}
	return b.String()
}

// pcv3LocalizedCopy is an authority-free render value. Empty fields mean that
// the closed state grants no corresponding text or action.
type pcv3LocalizedCopy struct {
	Title  string
	Body   string
	Action string
}

func pcv3ProgressText(code pcv3operation.StatusCode) string {
	switch code {
	case pcv3operation.StatusCheckingRequest:
		return tr("pcv3.progress.checking_request", "Checking operation…")
	case pcv3operation.StatusCheckingFactors:
		return tr("pcv3.progress.checking_factors", "Checking credential policy…")
	case pcv3operation.StatusCheckingResources:
		return tr("pcv3.progress.checking_resources", "Checking device resources…")
	case pcv3operation.StatusDerivingKey:
		return tr("pcv3.progress.deriving_key", "Deriving key…")
	case pcv3operation.StatusEncrypting:
		return tr("pcv3.progress.encrypting", "Encrypting volume…")
	case pcv3operation.StatusSplitting:
		return tr("pcv3.progress.splitting", "Splitting encrypted output…")
	case pcv3operation.StatusAuthenticating:
		return tr("pcv3.progress.authenticating", "Authenticating volume…")
	case pcv3operation.StatusRecovering:
		return tr("pcv3.progress.recovering", "Recovering available ranges…")
	case pcv3operation.StatusPreparingArtifact:
		return tr("pcv3.progress.preparing_artifact", "Preparing recovery artifact…")
	case pcv3operation.StatusPublishing:
		return tr("pcv3.progress.publishing", "Publishing output…")
	case pcv3operation.StatusConfirmingDurability:
		return tr("pcv3.progress.confirming_durability", "Confirming output durability…")
	default:
		// Unknown codes stay neutral. No caller-provided data participates in
		// this fallback.
		return tr("pcv3.progress.working", "Working…")
	}
}

func pcv3PhysicalRoleText(role pcv3operation.PhysicalRole) string {
	switch role {
	case pcv3operation.RolePrimary:
		return tr("pcv3.consent.role.primary", "Primary capsule")
	case pcv3operation.RoleBackup:
		return tr("pcv3.consent.role.backup", "Backup capsule")
	case pcv3operation.RoleD1Front:
		return tr("pcv3.consent.role.d1_front", "Front bootstrap")
	case pcv3operation.RoleD1Tail:
		return tr("pcv3.consent.role.d1_tail", "Tail bootstrap")
	default:
		// An invalid or absent role must be refused before rendering a partial
		// consent surface.
		return ""
	}
}

func pcv3OutcomeCopy(presentation pcv3operation.Presentation) pcv3LocalizedCopy {
	switch presentation.Diagnostic() {
	case pcv3operation.DiagnosticResourceLimit:
		return resourceLimitCopy()
	case pcv3operation.DiagnosticResourceBusy:
		return pcv3LocalizedCopy{
			Title:  tr("pcv3.resource.busy.title", "Another secure operation is running"),
			Body:   tr("pcv3.resource.busy.body", "Wait for it to finish. This operation did not start, and no output was created."),
			Action: tr("pcv3.resource.close", "Close resource notice"),
		}
	case pcv3operation.DiagnosticResourceInsufficient:
		return pcv3LocalizedCopy{
			Title:  tr("pcv3.resource.insufficient.title", "Required resources are unavailable"),
			Body:   tr("pcv3.resource.insufficient.body", "This device cannot safely run the fixed security profile right now. Security settings were not reduced, and no output was created."),
			Action: tr("pcv3.resource.close", "Close resource notice"),
		}
	case pcv3operation.DiagnosticResourceUnknown:
		return pcv3LocalizedCopy{
			Title:  tr("pcv3.resource.unknown.title", "Device resources could not be verified"),
			Body:   tr("pcv3.resource.unknown.body", "The operation stopped before key derivation. No output was created."),
			Action: tr("pcv3.resource.close", "Close resource notice"),
		}
	}

	if presentation.ArchivePending() {
		return pcv3LocalizedCopy{
			Title: tr("pcv3.outcome.archive_pending.title", "Authenticated archive ready to extract"),
			Body:  tr("pcv3.outcome.archive_pending.body", "The archive payload is fully authenticated. Choose a new extraction folder. The encrypted source is kept."),
		}
	}

	switch presentation.Outcome() {
	case pcv3operation.OutcomeSuccess:
		return pcv3LocalizedCopy{
			Title: tr("pcv3.outcome.success.title", "Operation complete"),
			Body:  tr("pcv3.outcome.success.body", "The output is fully authenticated."),
		}
	case pcv3operation.OutcomeAuthenticatedDegraded:
		return pcv3LocalizedCopy{
			Title: tr("pcv3.outcome.degraded.title", "Authenticated output recovered with damage"),
			Body:  tr("pcv3.outcome.degraded.body", "The output is authenticated, but recovery redundancy is damaged. Keep the original volume."),
		}
	case pcv3operation.OutcomeForcePartial:
		return pcv3LocalizedCopy{
			Title: tr("pcv3.outcome.force_partial.title", "Partial recovery artifact created"),
			Body:  tr("pcv3.outcome.force_partial.body", "Some ranges are verified and some are missing. This .pcv3-recovery file is not a complete plaintext file."),
		}
	case pcv3operation.OutcomeForceUnverified:
		return pcv3LocalizedCopy{
			Title: tr("pcv3.outcome.force_unverified.title", "Unverified recovery artifact created"),
			Body:  tr("pcv3.outcome.force_unverified.body", "Some recovered bytes are not authenticated and may be corrupted or unsafe. Do not open or extract this artifact as trusted content."),
		}
	case pcv3operation.OutcomeCredentialsOrDamage:
		return pcv3LocalizedCopy{
			Title: tr("pcv3.outcome.credentials_or_damage.title", "Credentials or recovery data could not be verified"),
			Body:  tr("pcv3.outcome.credentials_or_damage.body", "Check the selected credential policy, keyfiles, and keyfile order. No output was published."),
		}
	case pcv3operation.OutcomeAuthenticationFailed:
		return pcv3LocalizedCopy{
			Title: tr("pcv3.outcome.authentication_failed.title", "Authentication failed"),
			Body:  tr("pcv3.outcome.authentication_failed.body", "No output was published. Recovery was not started automatically."),
		}
	case pcv3operation.OutcomeAmbiguousVolume:
		return pcv3LocalizedCopy{
			Title: tr("pcv3.outcome.ambiguous.title", "Conflicting authenticated recovery data"),
			Body:  tr("pcv3.outcome.ambiguous.body", "No output was published. Keep the original volume and do not choose a candidate in the frontend."),
		}
	case pcv3operation.OutcomeUnsupportedRoutingPreKDF:
		return pcv3LocalizedCopy{
			Title: tr("pcv3.outcome.unsupported.title", "Unsupported PCV3 format"),
			Body:  tr("pcv3.outcome.unsupported.body", "No output was created, and the file was not tried as a legacy volume."),
		}
	case pcv3operation.OutcomeInvalidStructurePreKDF:
		return pcv3LocalizedCopy{
			Title: tr("pcv3.outcome.invalid_structure.title", "Invalid or damaged PCV3 structure"),
			Body:  tr("pcv3.outcome.invalid_structure.body", "The operation stopped before credential processing and output creation."),
		}
	case pcv3operation.OutcomeOperationFailed:
		switch presentation.Diagnostic() {
		case pcv3operation.DiagnosticCredentialPolicy:
			return pcv3LocalizedCopy{
				Title: tr("pcv3.outcome.credential_mismatch.title", "Credential policy does not match"),
				Body:  tr("pcv3.outcome.credential_mismatch.body", "Check password/keyfile mode, keyfile count, and keyfile order. No key derivation or output started."),
			}
		case pcv3operation.DiagnosticCancellation:
			return pcv3LocalizedCopy{
				Title: tr("pcv3.outcome.cancelled.title", "Operation cancelled"),
				Body:  tr("pcv3.outcome.cancelled.body", "No completed output was reported. Source files were kept."),
			}
		}
	}
	return pcv3LocalizedCopy{
		Title: tr("pcv3.outcome.generic.title", "Operation failed"),
		Body:  tr("pcv3.outcome.generic.body", "The operation failed safely. No output was published. Keep the source and review the reported state."),
	}
}

func resourceLimitCopy() pcv3LocalizedCopy {
	return pcv3LocalizedCopy{
		Title:  tr("pcv3.resource.limit.title", "Resource limit reached"),
		Body:   tr("pcv3.resource.limit.body", "The operation stopped because a processing resource limit was reached."),
		Action: tr("pcv3.resource.close", "Close resource notice"),
	}
}

func pcv3PublicationCopy(presentation pcv3operation.Presentation) pcv3LocalizedCopy {
	if !presentation.PublicationAttempted() {
		if presentation.ArchivePending() {
			return pcv3LocalizedCopy{}
		}
		if presentation.Outcome() == pcv3operation.OutcomeOperationFailed &&
			presentation.Stage() == pcv3operation.StageOutputPublication &&
			presentation.Diagnostic() == pcv3operation.DiagnosticNone {
			return pcv3LocalizedCopy{
				Title:  tr("pcv3.publication.not_requested.title", "No output was requested"),
				Body:   tr("pcv3.publication.not_requested.body", "The authenticated archive was closed without extraction. The encrypted source was kept."),
				Action: tr("pcv3.publication.close", "Close"),
			}
		}
		return pcv3LocalizedCopy{}
	}

	switch presentation.PublicationState() {
	case pcv3publication.StateNotPublished:
		return pcv3LocalizedCopy{
			Title:  tr("pcv3.publication.not_published.title", "No output was published"),
			Body:   tr("pcv3.publication.not_published.body", "Source files were kept."),
			Action: tr("pcv3.publication.close", "Close"),
		}
	case pcv3publication.StatePublishedDurable:
		return pcv3LocalizedCopy{
			Title:  pcv3OutcomeCopy(presentation).Title,
			Body:   tr("pcv3.publication.durable.body", "File saved."),
			Action: tr("pcv3.publication.close", "Close"),
		}
	case pcv3publication.StatePublishedDurabilityUncertain:
		return pcv3LocalizedCopy{
			Title:  tr("pcv3.publication.uncertain.title", "Output durability not confirmed"),
			Body:   tr("pcv3.publication.uncertain.body", "The destination may contain the output, but filesystem durability could not be confirmed. Keep every source and the destination. Do not retry, replace, delete, or clean up this operation."),
			Action: tr("pcv3.publication.uncertain.close", "Close durability warning"),
		}
	case pcv3publication.StatePublicationIndeterminate:
		return pcv3LocalizedCopy{
			Title:  tr("pcv3.publication.indeterminate.title", "Output state is unknown"),
			Body:   tr("pcv3.publication.indeterminate.body", "The application cannot determine whether publication committed. Keep every source and the destination exactly as they are. Do not retry or clean up this operation."),
			Action: tr("pcv3.publication.indeterminate.close", "Close publication warning"),
		}
	default:
		return pcv3LocalizedCopy{}
	}
}

func pcv3WarningText(warning pcv3operation.Warning) string {
	switch warning {
	case pcv3operation.WarningAuthenticatedDegraded:
		return tr("pcv3.warning.degraded", "The output is authenticated, but recovery redundancy is damaged. Keep the original volume.")
	case pcv3operation.WarningForcePartial:
		return tr("pcv3.warning.force_partial", "Some ranges are verified and some are missing. This .pcv3-recovery file is not a complete plaintext file.")
	case pcv3operation.WarningForceUnverified:
		return tr("pcv3.warning.force_unverified", "Some recovered bytes are not authenticated and may be corrupted or unsafe. Do not open or extract this artifact as trusted content.")
	case pcv3operation.WarningDurabilityUncertain:
		return tr("pcv3.warning.durability_uncertain", "Output durability was not confirmed. Keep every source and the destination.")
	case pcv3operation.WarningPublicationIndeterminate:
		return tr("pcv3.warning.publication_indeterminate", "Output publication state is unknown. Keep every source and the destination exactly as they are.")
	case pcv3operation.WarningCleanupIncomplete:
		return tr("pcv3.warning.cleanup_incomplete", "The application could not confirm removal of all temporary files created by this operation. Keep the source files and do not delete files based on this result.")
	case pcv3operation.WarningCallbackFailure:
		return tr("pcv3.warning.callback_failure", "A user-interface callback failed. No additional action was authorized.")
	default:
		return tr("pcv3.warning.unknown", "The operation reported a warning.")
	}
}

func pcv3ArtifactKindText(kind pcv3operation.ArtifactState) string {
	switch kind {
	case pcv3operation.ArtifactStatePartial:
		return tr("pcv3.artifact.kind.partial", "Partial recovery")
	case pcv3operation.ArtifactStateUnverifiedForensic:
		return tr("pcv3.artifact.kind.unverified", "Unverified forensic recovery")
	default:
		return tr("pcv3.artifact.kind.unknown", "Unknown recovery artifact")
	}
}

func pcv3ArtifactRoleText(role pcv3operation.ArtifactRole) string {
	switch role {
	case pcv3operation.ArtifactRolePrimary:
		return tr("pcv3.artifact.role.primary", "Primary capsule")
	case pcv3operation.ArtifactRoleBackup:
		return tr("pcv3.artifact.role.backup", "Backup capsule")
	case pcv3operation.ArtifactRoleD1Front:
		return tr("pcv3.artifact.role.d1_front", "Front bootstrap")
	case pcv3operation.ArtifactRoleD1Tail:
		return tr("pcv3.artifact.role.d1_tail", "Tail bootstrap")
	default:
		return ""
	}
}

func pcv3ArtifactFinalText(status pcv3operation.ArtifactFinalStatus) string {
	switch status {
	case pcv3operation.ArtifactFinalVerified:
		return tr("pcv3.artifact.final.verified", "Verified")
	case pcv3operation.ArtifactFinalUnverified:
		return tr("pcv3.artifact.final.unverified", "Unverified")
	case pcv3operation.ArtifactFinalMissing:
		return tr("pcv3.artifact.final.missing", "Missing")
	default:
		return tr("pcv3.artifact.final.unknown", "Unknown")
	}
}

func pcv3ArtifactRangeStateText(status pcv3operation.ArtifactRangeStatus) string {
	switch status {
	case pcv3operation.ArtifactRangeVerified:
		return tr("pcv3.artifact.range.verified", "verified")
	case pcv3operation.ArtifactRangeUnverified:
		return tr("pcv3.artifact.range.unverified", "unverified")
	case pcv3operation.ArtifactRangeMissing:
		return tr("pcv3.artifact.range.missing", "missing")
	default:
		return tr("pcv3.artifact.range.unknown", "unknown status")
	}
}

func pcv3RecoveryRangeCount(count uint64) string {
	if count == 0 {
		return tr("pcv3.recovery.no_ranges", "No recoverable ranges were recorded.")
	}

	// go-i18n accepts only signed integers or signed decimal strings. Preserve
	// the full displayed uint64 while selecting a safe plural operand. Bundled
	// locales carry dedicated PCV3 copy; any locale without it falls back
	// to the English catalog.
	pluralCount := count
	maxInt := uint64(^uint(0) >> 1)
	if pluralCount > maxInt {
		if activeLanguage() == "ru" {
			pluralCount %= 100
		} else {
			pluralCount = 2
		}
	}
	return localize(
		"pcv3.recovery.range_count",
		"{{.Count}} recovery ranges",
		int(pluralCount),
		true,
		map[string]any{"Count": strconv.FormatUint(count, 10)},
	)
}

func pcv3RecoveryRangeRow(
	index uint64,
	start uint64,
	end uint64,
	status pcv3operation.ArtifactRangeStatus,
) string {
	return tr("pcv3.recovery.range_row", "Record {{.Index}}: bytes {{.Start}}–{{.End}} — {{.Status}}", map[string]any{
		"Index":  strconv.FormatUint(index, 10),
		"Start":  strconv.FormatUint(start, 10),
		"End":    strconv.FormatUint(end, 10),
		"Status": pcv3ArtifactRangeStateText(status),
	})
}
