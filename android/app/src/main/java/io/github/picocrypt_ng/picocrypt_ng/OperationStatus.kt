package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import androidx.annotation.StringRes

data class OperationStatusData(
    val code: String,
    val speedMiBPerSecond: Double = 0.0,
    val eta: String = "",
)

data class OperationProgressDetail(
    val code: String,
    val current: Long = 0,
    val total: Long = 0,
)

data class OperationDisplayText(
    val status: String,
    val detail: String? = null,
)

/** Resource-only PCV3 progress projection; numeric progress requires one valid closed tuple. */
data class Pcv3ProgressDisplay(
    @StringRes val statusResId: Int,
    val fraction: Float? = null,
)

/** One localized title/body pair selected from closed PCV3 snapshot values. */
data class Pcv3CopyResources(
    @StringRes val titleResId: Int,
    @StringRes val bodyResId: Int,
)

enum class Pcv3ResultTone { NEUTRAL, WARNING, ERROR }

/**
 * Complete authority-free terminal copy. Outcome and publication stay separate so a durable
 * publication can never erase degraded authentication, and semantic success can never imply
 * durability.
 */
data class Pcv3ResultDisplay(
    val outcome: Pcv3CopyResources,
    val supportingOutcome: Pcv3CopyResources? = null,
    val publication: Pcv3CopyResources? = null,
    val warnings: List<Pcv3CopyResources> = emptyList(),
    val tone: Pcv3ResultTone,
    @StringRes val closeActionResId: Int,
    val authenticatedComment: String? = null,
)

/** The only PCV3 terminal actions Android may render for a typed presentation. */
enum class Pcv3ResultAction {
    EXPORT_ARCHIVE,
    SAVE_DECRYPTED_OUTPUT,
    SAVE_CREATED_VOLUME,
    SAVE_RECOVERY_ARTIFACT,
    INSPECT_RECOVERY_ARTIFACT,
    DISCARD_RECOVERY_ARTIFACT,
    CLOSE_RESULT,
    CLOSE_ARCHIVE,
}

/** Closed, authority-preserving projection for PCV3 result controls. */
data class Pcv3ResultActionProjection(
    val actions: Set<Pcv3ResultAction>,
    @StringRes val closeActionResId: Int? = null,
)

/** The only scalar output targets that may refine an already-live native capability. */
internal enum class Pcv3OutputActionTarget { DECRYPTED_OUTPUT, CREATED_VOLUME, RECOVERY_ARTIFACT }

/** Validated offsets for one bounded artifact page. */
data class Pcv3ArtifactPageNavigation(
    val previousOffsetDecimal: String?,
    val nextOffsetDecimal: String?,
)

/** Bounded localized labels for core-vetted artifact metadata. */
data class Pcv3ArtifactMetadataDisplay(
    @StringRes val kindResId: Int,
    @StringRes val roleResId: Int,
    @StringRes val finalStatusResId: Int,
)

object OperationStatus {
    const val STARTING = "STARTING"
    const val COMPLETED = "COMPLETED"
    const val CANCELLED = "CANCELLED"
    const val ERROR = "ERROR"
    const val COMPRESSING_FILES = "COMPRESSING_FILES"
    const val GENERATING_VALUES = "GENERATING_VALUES"
    const val DERIVING_KEY = "DERIVING_KEY"
    const val READING_KEYFILES = "READING_KEYFILES"
    const val CALCULATING_VALUES = "CALCULATING_VALUES"
    const val WRITING_VALUES = "WRITING_VALUES"
    const val SPLITTING = "SPLITTING"
    const val RECOMBINING_CHUNKS = "RECOMBINING_CHUNKS"
    const val READING_VALUES = "READING_VALUES"
    const val DUPLICATE_KEYFILES_WARNING = "DUPLICATE_KEYFILES_WARNING"
    const val VERIFYING_INTEGRITY = "VERIFYING_INTEGRITY"
    const val MAC_VERIFICATION_FAILED_CONTINUING = "MAC_VERIFICATION_FAILED_CONTINUING"
    const val REPAIRING_VERIFYING = "REPAIRING_VERIFYING"
    const val INTEGRITY_VERIFIED_DECRYPTING = "INTEGRITY_VERIFIED_DECRYPTING"
    const val COMPARING_VALUES = "COMPARING_VALUES"
    const val UNZIPPING = "UNZIPPING"
    const val ADDING_PLAUSIBLE_DENIABILITY = "ADDING_PLAUSIBLE_DENIABILITY"
    const val REMOVING_DENIABILITY_PROTECTION = "REMOVING_DENIABILITY_PROTECTION"
    const val COMPRESSING_RATE = "COMPRESSING_RATE"
    const val ENCRYPTING_RATE = "ENCRYPTING_RATE"
    const val SPLITTING_RATE = "SPLITTING_RATE"
    const val RECOMBINING_RATE = "RECOMBINING_RATE"
    const val VERIFYING_RATE = "VERIFYING_RATE"
    const val DECRYPTING_RATE = "DECRYPTING_RATE"
    const val REPAIRING_RATE = "REPAIRING_RATE"
    const val UNPACKING_RATE = "UNPACKING_RATE"
    const val ADDING_DENIABILITY_RATE = "ADDING_DENIABILITY_RATE"
    const val REMOVING_DENIABILITY_RATE = "REMOVING_DENIABILITY_RATE"
    const val UNKNOWN = "UNKNOWN"
    const val WORKING = UNKNOWN
}

object OperationProgress {
    const val NONE = "NONE"
    const val PERCENT = "PERCENT"
    const val ITEM_COUNT = "ITEM_COUNT"
    const val UNKNOWN = "UNKNOWN"
}

object Pcv3ProgressStatus {
    const val CHECKING_REQUEST = "checking-request"
    const val CHECKING_FACTORS = "checking-factors"
    const val CHECKING_RESOURCES = "checking-resources"
    const val DERIVING_KEY = "deriving-key"
    const val AUTHENTICATING = "authenticating"
    const val RECOVERING = "recovering"
    const val PREPARING_ARTIFACT = "preparing-artifact"
    const val PUBLISHING = "publishing"
    const val CONFIRMING_DURABILITY = "confirming-durability"
}

/**
 * Maps only Go's closed progress vocabulary. Numeric arguments are interpreted only for the
 * specified recovering current/total tuple; every other argument shape fails neutral.
 */
fun pcv3ProgressDisplay(snapshot: Pcv3SnapshotView): Pcv3ProgressDisplay {
    val statusResId = when (snapshot.statusCode) {
        Pcv3ProgressStatus.CHECKING_REQUEST -> R.string.pcv3_progress_checking_request
        Pcv3ProgressStatus.CHECKING_FACTORS -> R.string.pcv3_progress_checking_factors
        Pcv3ProgressStatus.CHECKING_RESOURCES -> R.string.pcv3_progress_checking_resources
        Pcv3ProgressStatus.DERIVING_KEY -> R.string.pcv3_progress_deriving_key
        Pcv3ProgressStatus.AUTHENTICATING -> R.string.pcv3_progress_authenticating
        Pcv3ProgressStatus.RECOVERING -> R.string.pcv3_progress_recovering
        Pcv3ProgressStatus.PREPARING_ARTIFACT -> R.string.pcv3_progress_preparing_artifact
        Pcv3ProgressStatus.PUBLISHING -> R.string.pcv3_progress_publishing
        Pcv3ProgressStatus.CONFIRMING_DURABILITY ->
            R.string.pcv3_progress_confirming_durability
        else -> return Pcv3ProgressDisplay(R.string.pcv3_progress_working)
    }

    if (snapshot.statusArgs.isEmpty()) {
        return Pcv3ProgressDisplay(statusResId)
    }
    if (snapshot.statusCode != Pcv3ProgressStatus.RECOVERING || snapshot.statusArgs.size != 2) {
        return Pcv3ProgressDisplay(R.string.pcv3_progress_working)
    }

    val current = snapshot.statusArgs[0].toULongOrNull()
    val total = snapshot.statusArgs[1].toULongOrNull()
    if (current == null || total == null || total == 0uL || current > total) {
        return Pcv3ProgressDisplay(R.string.pcv3_progress_working)
    }
    val fraction = (current.toDouble() / total.toDouble()).toFloat()
    return if (fraction.isFinite() && fraction in 0f..1f) {
        Pcv3ProgressDisplay(statusResId, fraction)
    } else {
        Pcv3ProgressDisplay(R.string.pcv3_progress_working)
    }
}

@StringRes
fun pcv3ConsentRoleResource(role: String): Int? = when (role) {
    "primary" -> R.string.pcv3_consent_role_primary
    "backup" -> R.string.pcv3_consent_role_backup
    "d1-front" -> R.string.pcv3_consent_role_d1_front
    "d1-tail" -> R.string.pcv3_consent_role_d1_tail
    else -> null
}

/** Selects bounded copy from the complete Go projection without rendering raw snapshot values. */
fun pcv3ResultDisplay(snapshot: Pcv3SnapshotView): Pcv3ResultDisplay {
    val authenticatedComment = snapshot.authenticatedComment.takeIf { it.isNotEmpty() }
    val resourceNotice = resourceNotice(snapshot.diagnostic)
    if (resourceNotice != null) {
        return Pcv3ResultDisplay(
            outcome = resourceNotice,
            tone = Pcv3ResultTone.WARNING,
            closeActionResId = R.string.pcv3_resource_close,
            authenticatedComment = authenticatedComment,
        )
    }

    val archiveClosedWithoutExtraction = !snapshot.publication.attempted &&
        snapshot.semantic.outcome == "operation-failed" &&
        snapshot.semantic.stage == "output-publication" &&
        snapshot.diagnostic == "none"
    val outcome = when {
        snapshot.archivePending -> copy(
            R.string.pcv3_outcome_archive_pending_title,
            R.string.pcv3_outcome_archive_pending_body,
        )
        archiveClosedWithoutExtraction -> copy(
            R.string.pcv3_publication_not_requested_title,
            R.string.pcv3_publication_not_requested_body,
        )
        snapshot.semantic.outcome == "success" -> copy(
            R.string.pcv3_outcome_success_title,
            R.string.pcv3_outcome_success_body,
        )
        snapshot.semantic.outcome == "authenticated-degraded" -> copy(
            R.string.pcv3_outcome_degraded_title,
            R.string.pcv3_outcome_degraded_body,
        )
        snapshot.semantic.outcome == "force-partial" -> copy(
            R.string.pcv3_outcome_force_partial_title,
            R.string.pcv3_outcome_force_partial_body,
        )
        snapshot.semantic.outcome == "force-unverified" -> copy(
            R.string.pcv3_outcome_force_unverified_title,
            R.string.pcv3_outcome_force_unverified_body,
        )
        snapshot.semantic.outcome == "credentials-or-damage" -> copy(
            R.string.pcv3_outcome_credentials_or_damage_title,
            R.string.pcv3_outcome_credentials_or_damage_body,
        )
        snapshot.semantic.outcome == "authentication-failed" -> copy(
            R.string.pcv3_outcome_authentication_failed_title,
            R.string.pcv3_outcome_authentication_failed_body,
        )
        snapshot.semantic.outcome == "ambiguous-volume" -> copy(
            R.string.pcv3_outcome_ambiguous_title,
            R.string.pcv3_outcome_ambiguous_body,
        )
        snapshot.semantic.outcome == "unsupported-routing-pre-kdf" -> copy(
            R.string.pcv3_outcome_unsupported_title,
            R.string.pcv3_outcome_unsupported_body,
        )
        snapshot.semantic.outcome == "invalid-structure-pre-kdf" -> copy(
            R.string.pcv3_outcome_invalid_structure_title,
            R.string.pcv3_outcome_invalid_structure_body,
        )
        snapshot.semantic.outcome == "operation-failed" &&
            snapshot.diagnostic == "credential-policy" -> copy(
                R.string.pcv3_outcome_credential_mismatch_title,
                R.string.pcv3_outcome_credential_mismatch_body,
            )
        snapshot.semantic.outcome == "operation-failed" &&
            snapshot.diagnostic == "cancellation" -> copy(
                R.string.pcv3_outcome_cancelled_title,
                R.string.pcv3_outcome_cancelled_body,
            )
        else -> copy(
            R.string.pcv3_outcome_generic_title,
            R.string.pcv3_outcome_generic_body,
        )
    }

    val publication = when {
        !snapshot.publication.attempted -> null
        snapshot.publication.state == "not-published" -> copy(
            R.string.pcv3_publication_not_published_title,
            R.string.pcv3_publication_not_published_body,
        )
        snapshot.publication.state == "published-durable" -> copy(
            outcome.titleResId,
            R.string.pcv3_publication_durable_body,
        )
        snapshot.publication.state == "published-durability-uncertain" -> copy(
            R.string.pcv3_publication_uncertain_title,
            R.string.pcv3_publication_uncertain_body,
        )
        snapshot.publication.state == "publication-indeterminate" -> copy(
            R.string.pcv3_publication_indeterminate_title,
            R.string.pcv3_publication_indeterminate_body,
        )
        else -> null
    }

    val cleanupWarning = "cleanup-incomplete" in snapshot.warnings
    val warnings = buildList {
        if (cleanupWarning) {
            add(copy(R.string.pcv3_warning_cleanup_title, R.string.pcv3_warning_cleanup_body))
        }
        if ("callback-failure" in snapshot.warnings) {
            add(copy(R.string.pcv3_warning_callback_title, R.string.pcv3_warning_callback_body))
        }
        if (snapshot.warnings.any { !it.isRepresentedBy(snapshot) }) {
            add(copy(R.string.pcv3_warning_unknown_title, R.string.pcv3_warning_unknown_body))
        }
    }
    val closeAction = when {
        snapshot.publication.state == "published-durability-uncertain" ->
            R.string.pcv3_publication_uncertain_close
        snapshot.publication.state == "publication-indeterminate" ->
            R.string.pcv3_publication_indeterminate_close
        cleanupWarning -> R.string.pcv3_warning_cleanup_close
        snapshot.semantic.outcome == "force-partial" ||
            snapshot.semantic.outcome == "force-unverified" ->
            R.string.pcv3_recovery_result_close
        else -> R.string.pcv3_publication_close
    }
    val outcomeTone = when {
        snapshot.archivePending || archiveClosedWithoutExtraction ||
            snapshot.semantic.outcome == "success" ||
            (snapshot.semantic.outcome == "operation-failed" &&
                snapshot.diagnostic == "cancellation") -> Pcv3ResultTone.NEUTRAL
        snapshot.semantic.outcome == "authenticated-degraded" ||
            snapshot.semantic.outcome == "force-partial" -> Pcv3ResultTone.WARNING
        else -> Pcv3ResultTone.ERROR
    }
    val tone = when {
        snapshot.publication.state == "publication-indeterminate" -> Pcv3ResultTone.ERROR
        snapshot.publication.state == "published-durability-uncertain" -> Pcv3ResultTone.WARNING
        snapshot.publication.state == "not-published" -> Pcv3ResultTone.ERROR
        outcomeTone == Pcv3ResultTone.ERROR -> Pcv3ResultTone.ERROR
        cleanupWarning || warnings.isNotEmpty() || outcomeTone == Pcv3ResultTone.WARNING ->
            Pcv3ResultTone.WARNING
        else -> Pcv3ResultTone.NEUTRAL
    }
    return Pcv3ResultDisplay(
        outcome = outcome,
        publication = publication,
        warnings = warnings,
        tone = tone,
        closeActionResId = closeAction,
        authenticatedComment = authenticatedComment,
    )
}

/**
 * Projects terminal copy from the complete typed presentation. A settled output action replaces
 * pre-action publication copy so a failed/expired/unknown Save or Discard cannot look durable.
 */
fun pcv3ResultDisplay(presentation: Pcv3Presentation): Pcv3ResultDisplay {
    val snapshotDisplay = pcv3ResultDisplay(presentation.snapshot)
    val outputAction = (presentation as? Pcv3Presentation.Final)?.outputAction
    // A creation that has not yet settled an output action shows creation copy, never
    // decryption copy; publication durability of the private staging file is not the
    // user-visible save.
    if (presentation.isCreation && outputAction == null &&
        presentation.snapshot.semantic.outcome == "success" &&
        presentation.snapshot.diagnostic == "none"
    ) {
        return snapshotDisplay.copy(
            outcome = copy(
                R.string.pcv3_create_outcome_title,
                R.string.pcv3_create_outcome_body,
            ),
            publication = null,
        )
    }
    if (outputAction == null) return snapshotDisplay
    val result = outputAction.closedDisplay(
        target = pcv3OutputActionTarget(
            presentation.snapshot,
            presentation.artifactMetadata,
            presentation.isCreation,
        ),
    )
    val cleanupUncertain = outputAction.cleanupIncomplete ||
        outputAction.code.endsWith("-cleanup-incomplete")
    val warnings = buildList {
        addAll(snapshotDisplay.warnings)
        if (cleanupUncertain && none { it.titleResId == R.string.pcv3_warning_cleanup_title }) {
            add(copy(R.string.pcv3_warning_cleanup_title, R.string.pcv3_warning_cleanup_body))
        }
    }
    val tone = when {
        result.tone == Pcv3ResultTone.ERROR || snapshotDisplay.tone == Pcv3ResultTone.ERROR &&
            result.keepUnderlyingOutcome -> Pcv3ResultTone.ERROR
        cleanupUncertain || warnings.isNotEmpty() || result.tone == Pcv3ResultTone.WARNING ->
            Pcv3ResultTone.WARNING
        else -> Pcv3ResultTone.NEUTRAL
    }
    val stateSpecificCloseTakesPrecedence =
        presentation.snapshot.publication.state == "published-durability-uncertain" ||
            presentation.snapshot.publication.state == "publication-indeterminate" ||
            presentation.snapshot.restoredReceipt.isNotEmpty()
    if (stateSpecificCloseTakesPrecedence) {
        return snapshotDisplay.copy(
            supportingOutcome = result.copy,
            warnings = warnings,
            tone = if (snapshotDisplay.tone == Pcv3ResultTone.ERROR ||
                result.tone == Pcv3ResultTone.ERROR
            ) {
                Pcv3ResultTone.ERROR
            } else {
                Pcv3ResultTone.WARNING
            },
        )
    }
    return Pcv3ResultDisplay(
        outcome = result.copy,
        supportingOutcome = snapshotDisplay.outcome.takeIf { result.keepUnderlyingOutcome },
        publication = null,
        warnings = warnings,
        tone = tone,
        closeActionResId = if (cleanupUncertain) {
            R.string.pcv3_warning_cleanup_close
        } else {
            result.closeActionResId
        },
        authenticatedComment = snapshotDisplay.authenticatedComment,
    )
}

/**
 * Derives visible controls from an exact presentation and its native capabilities.
 * Snapshot values can only deny actions; they never create output authority.
 */
fun pcv3ResultActions(presentation: Pcv3Presentation): Pcv3ResultActionProjection {
    val snapshot = presentation.snapshot
    val display = pcv3ResultDisplay(presentation)
    val denyOnly = snapshot.publication.state == "published-durability-uncertain" ||
        snapshot.publication.state == "publication-indeterminate" ||
        snapshot.restoredReceipt.isNotEmpty()

    if (presentation is Pcv3Presentation.Restored || denyOnly) {
        return closeProjection(presentation, display)
    }

    if (snapshot.archivePending) {
        val live = presentation as? Pcv3Presentation.Live
        return if (live?.archiveHandle != null) {
            Pcv3ResultActionProjection(
                setOf(Pcv3ResultAction.EXPORT_ARCHIVE, Pcv3ResultAction.CLOSE_ARCHIVE),
                R.string.pcv3_archive_close,
            )
        } else {
            Pcv3ResultActionProjection(emptySet())
        }
    }

    val outputTarget = pcv3OutputActionTarget(
        snapshot,
        presentation.artifactMetadata,
        presentation.isCreation,
    )
    if (presentation is Pcv3Presentation.Live) {
        if (presentation.outputHandle == null || !presentation.outputPending ||
            presentation.outputActionInFlight
        ) {
            return Pcv3ResultActionProjection(emptySet())
        }
        return when (outputTarget) {
            Pcv3OutputActionTarget.RECOVERY_ARTIFACT -> Pcv3ResultActionProjection(
                setOf(
                    Pcv3ResultAction.SAVE_RECOVERY_ARTIFACT,
                    Pcv3ResultAction.INSPECT_RECOVERY_ARTIFACT,
                    Pcv3ResultAction.DISCARD_RECOVERY_ARTIFACT,
                ),
            )
            Pcv3OutputActionTarget.DECRYPTED_OUTPUT ->
                Pcv3ResultActionProjection(setOf(Pcv3ResultAction.SAVE_DECRYPTED_OUTPUT))
            Pcv3OutputActionTarget.CREATED_VOLUME ->
                Pcv3ResultActionProjection(setOf(Pcv3ResultAction.SAVE_CREATED_VOLUME))
            null -> Pcv3ResultActionProjection(emptySet())
        }
    }

    // A D1 creation has no retained output capability: the native writer published the
    // staging file directly and the host must copy it out. Until it is saved, closing
    // would abandon the only copy, so Save is the only rendered action.
    if (presentation is Pcv3Presentation.Final && presentation.isCreation &&
        presentation.outputAction == null && outputTarget == Pcv3OutputActionTarget.CREATED_VOLUME
    ) {
        return Pcv3ResultActionProjection(setOf(Pcv3ResultAction.SAVE_CREATED_VOLUME))
    }

    if (presentation is Pcv3Presentation.Final &&
        outputTarget == Pcv3OutputActionTarget.RECOVERY_ARTIFACT
    ) {
        return Pcv3ResultActionProjection(
            setOf(Pcv3ResultAction.INSPECT_RECOVERY_ARTIFACT, Pcv3ResultAction.CLOSE_RESULT),
            display.closeActionResId,
        )
    }
    return closeProjection(presentation, display)
}

/** Returns navigation only for a contiguous, closed, bounded page. */
fun pcv3ArtifactPageNavigation(
    metadata: Pcv3ArtifactMetadataView,
    page: Pcv3ArtifactPageView,
): Pcv3ArtifactPageNavigation? {
    val total = metadata.rangeCount.toCanonicalPcv3ULong() ?: return null
    val offset = page.offsetDecimal.toCanonicalPcv3ULong() ?: return null
    if (page.ranges.isEmpty()) {
        return if (total == 0uL && offset == 0uL) {
            Pcv3ArtifactPageNavigation(null, null)
        } else {
            null
        }
    }
    if (page.ranges.size !in 1..128 || offset >= total) return null
    val size = page.ranges.size.toULong()
    if (offset > ULong.MAX_VALUE - size) return null
    val endExclusive = offset + size
    if (endExclusive > total || page.ranges.anyIndexed { index, row ->
            row.recordIndex.toCanonicalPcv3ULong() != offset + index.toULong() ||
                row.start.toCanonicalPcv3ULong() == null ||
                row.end.toCanonicalPcv3ULong() == null ||
                row.start.toCanonicalPcv3ULong()!! > row.end.toCanonicalPcv3ULong()!! ||
                row.status !in PCV3_ARTIFACT_RANGE_STATUSES
        }
    ) {
        return null
    }
    val previous = if (offset == 0uL) null else (offset - minOf(offset, 128uL)).toString()
    val next = endExclusive.takeIf { it < total }?.toString()
    return Pcv3ArtifactPageNavigation(previous, next)
}

/** Rejects malformed metadata instead of interpolating provider-controlled values. */
fun pcv3ArtifactMetadataDisplay(metadata: Pcv3ArtifactMetadataView): Pcv3ArtifactMetadataDisplay? {
    metadata.plaintextLength.toCanonicalPcv3ULong() ?: return null
    val rangeCount = metadata.rangeCount.toCanonicalPcv3ULong() ?: return null
    val verifiedCount = metadata.verifiedCount.toCanonicalPcv3ULong() ?: return null
    val unverifiedCount = metadata.unverifiedCount.toCanonicalPcv3ULong() ?: return null
    val missingCount = metadata.missingCount.toCanonicalPcv3ULong() ?: return null
    if (exactPcv3Sum(verifiedCount, unverifiedCount, missingCount) != rangeCount) return null
    val kind = when (metadata.kind) {
        "partial" -> R.string.pcv3_artifact_kind_partial
        "unverified-forensic" -> R.string.pcv3_artifact_kind_unverified_forensic
        else -> return null
    }
    val role = when (metadata.role) {
        "none" -> R.string.pcv3_artifact_role_none
        "primary" -> R.string.pcv3_consent_role_primary
        "backup" -> R.string.pcv3_consent_role_backup
        "d1-front" -> R.string.pcv3_consent_role_d1_front
        "d1-tail" -> R.string.pcv3_consent_role_d1_tail
        else -> return null
    }
    val finalStatus = pcv3ArtifactStatusResource(metadata.finalStatus) ?: return null
    return Pcv3ArtifactMetadataDisplay(kind, role, finalStatus)
}

@StringRes
fun pcv3ArtifactStatusResource(status: String): Int? = when (status) {
    "verified" -> R.string.pcv3_artifact_status_verified
    "unverified" -> R.string.pcv3_artifact_status_unverified
    "missing" -> R.string.pcv3_artifact_status_missing
    else -> null
}

private fun closeProjection(
    presentation: Pcv3Presentation,
    display: Pcv3ResultDisplay,
): Pcv3ResultActionProjection = when (presentation) {
    is Pcv3Presentation.Final, is Pcv3Presentation.Restored ->
        Pcv3ResultActionProjection(setOf(Pcv3ResultAction.CLOSE_RESULT), display.closeActionResId)
    is Pcv3Presentation.Live -> Pcv3ResultActionProjection(emptySet())
}

/**
 * The single scalar validator for an output action. It can only restrict separately-held native
 * authority; callers must additionally require the exact live capability/ticket and idle state.
 */
internal fun pcv3OutputActionTarget(
    snapshot: Pcv3SnapshotView,
    artifactMetadata: Pcv3ArtifactMetadataView?,
    isCreation: Boolean = false,
): Pcv3OutputActionTarget? {
    if (snapshot.diagnostic != "none" || !snapshot.publication.attempted ||
        snapshot.publication.state != "published-durable" ||
        snapshot.publication.stage != "none" ||
        snapshot.publication.code != "PCV3_PUBLICATION_PUBLISHED_DURABLE" ||
        snapshot.archivePending || snapshot.restoredReceipt.isNotEmpty()
    ) {
        return null
    }
    // A created volume is never a decrypted output or a recovery artifact; only the
    // exact clean durable creation success may offer saving the created volume.
    if (isCreation) {
        return if (artifactMetadata == null &&
            snapshot.semantic.outcome == "success" &&
            snapshot.semantic.stage == "none" &&
            snapshot.semantic.code == "PCV3_SUCCESS" &&
            snapshot.completionClass in setOf("clean", "warning") &&
            snapshot.forceProvenance == "none"
        ) {
            Pcv3OutputActionTarget.CREATED_VOLUME
        } else {
            null
        }
    }
    val vettedArtifactKind = artifactMetadata
        ?.takeIf { pcv3ArtifactMetadataDisplay(it) != null }
        ?.kind
    return when {
        artifactMetadata == null &&
            snapshot.semantic.outcome == "success" &&
            snapshot.semantic.stage == "none" &&
            snapshot.semantic.code == "PCV3_SUCCESS" &&
            snapshot.completionClass in setOf("clean", "warning") &&
            snapshot.forceProvenance == "none" ->
            Pcv3OutputActionTarget.DECRYPTED_OUTPUT
        artifactMetadata == null &&
            snapshot.semantic.outcome == "authenticated-degraded" &&
            snapshot.semantic.stage in PCV3_DEGRADED_DAMAGE_STAGES &&
            snapshot.semantic.code == "PCV3_AUTHENTICATED_DEGRADED" &&
            snapshot.completionClass == "warning" &&
            snapshot.forceProvenance in setOf("none", "verified") ->
            Pcv3OutputActionTarget.DECRYPTED_OUTPUT
        vettedArtifactKind == "partial" &&
            snapshot.semantic.outcome == "force-partial" &&
            snapshot.semantic.stage in PCV3_FORCE_DAMAGE_STAGES &&
            snapshot.semantic.code == "PCV3_FORCE_PARTIAL" &&
            snapshot.completionClass == "warning" &&
            snapshot.forceProvenance == "partial" ->
            Pcv3OutputActionTarget.RECOVERY_ARTIFACT
        vettedArtifactKind == "unverified-forensic" &&
            snapshot.semantic.outcome == "force-unverified" &&
            snapshot.semantic.stage in PCV3_FORCE_DAMAGE_STAGES &&
            snapshot.semantic.code == "PCV3_FORCE_UNVERIFIED" &&
            snapshot.completionClass == "warning" &&
            snapshot.forceProvenance == "unverified" ->
            Pcv3OutputActionTarget.RECOVERY_ARTIFACT
        else -> null
    }
}

private fun String.toCanonicalPcv3ULong(): ULong? =
    toULongOrNull()?.takeIf { it.toString() == this }

private fun exactPcv3Sum(first: ULong, second: ULong, third: ULong): ULong? {
    if (first > ULong.MAX_VALUE - second) return null
    val partial = first + second
    if (partial > ULong.MAX_VALUE - third) return null
    return partial + third
}

private inline fun <T> Iterable<T>.anyIndexed(predicate: (Int, T) -> Boolean): Boolean {
    forEachIndexed { index, value -> if (predicate(index, value)) return true }
    return false
}

private val PCV3_ARTIFACT_RANGE_STATUSES = setOf("verified", "unverified", "missing")

/** Matches the core stages that can produce an authenticated-degraded result. */
private val PCV3_DEGRADED_DAMAGE_STAGES = setOf(
    "preamble",
    "capsule-rs",
    "capsule-structure",
    "tail-geometry",
    "wrap-auth",
    "replica-auth",
    "metadata",
)

/** Extends authenticated damage with the record stages that Force can recover from. */
private val PCV3_FORCE_DAMAGE_STAGES = PCV3_DEGRADED_DAMAGE_STAGES + setOf(
    "descriptor",
    "record-body-rs",
    "record-auth",
    "final-record",
)

private fun String.isRepresentedBy(snapshot: Pcv3SnapshotView): Boolean = when (this) {
    "authenticated-degraded" -> snapshot.semantic.outcome == "authenticated-degraded"
    "force-partial" -> snapshot.semantic.outcome == "force-partial"
    "force-unverified" -> snapshot.semantic.outcome == "force-unverified"
    "durability-uncertain" ->
        snapshot.publication.state == "published-durability-uncertain"
    "publication-indeterminate" -> snapshot.publication.state == "publication-indeterminate"
    "cleanup-incomplete", "callback-failure" -> true
    else -> false
}

private fun resourceNotice(diagnostic: String): Pcv3CopyResources? = when (diagnostic) {
    "resource-busy" -> copy(
        R.string.pcv3_resource_busy_title,
        R.string.pcv3_resource_busy_body,
    )
    "resource-insufficient" -> copy(
        R.string.pcv3_resource_insufficient_title,
        R.string.pcv3_resource_insufficient_body,
    )
    "resource-unknown" -> copy(
        R.string.pcv3_resource_unknown_title,
        R.string.pcv3_resource_unknown_body,
    )
    else -> null
}

private data class Pcv3ClosedOutputDisplay(
    val copy: Pcv3CopyResources,
    val tone: Pcv3ResultTone,
    @StringRes val closeActionResId: Int,
    val keepUnderlyingOutcome: Boolean = false,
)

/** Mirrors the bridge's closed code/cleanup pairs and collapses every other pair safely. */
private fun Pcv3OutputResultView.closedDisplay(
    target: Pcv3OutputActionTarget?,
): Pcv3ClosedOutputDisplay = when {
    target == null -> Pcv3ClosedOutputDisplay(
        copy(R.string.pcv3_output_unknown_title, R.string.pcv3_output_unknown_body),
        Pcv3ResultTone.ERROR,
        R.string.pcv3_output_unknown_close,
    )
    code == "saved" && !cleanupIncomplete -> Pcv3ClosedOutputDisplay(
        copy(R.string.pcv3_output_saved_title, R.string.pcv3_output_saved_body),
        Pcv3ResultTone.NEUTRAL,
        R.string.pcv3_output_saved_close,
        keepUnderlyingOutcome = true,
    )
    code == "saved-cleanup-incomplete" && cleanupIncomplete -> Pcv3ClosedOutputDisplay(
        copy(
            R.string.pcv3_output_saved_cleanup_title,
            R.string.pcv3_output_saved_cleanup_body,
        ),
        Pcv3ResultTone.WARNING,
        R.string.pcv3_warning_cleanup_close,
        keepUnderlyingOutcome = true,
    )
    code == "save-failed" && !cleanupIncomplete -> Pcv3ClosedOutputDisplay(
        copy(R.string.pcv3_output_save_failed_title, R.string.pcv3_output_save_failed_body),
        Pcv3ResultTone.ERROR,
        R.string.pcv3_output_save_failed_close,
    )
    code == "save-failed-cleanup-incomplete" && cleanupIncomplete ->
        Pcv3ClosedOutputDisplay(
            copy(
                R.string.pcv3_output_save_failed_cleanup_title,
                R.string.pcv3_output_save_failed_cleanup_body,
            ),
            Pcv3ResultTone.ERROR,
            R.string.pcv3_warning_cleanup_close,
        )
    target == Pcv3OutputActionTarget.RECOVERY_ARTIFACT &&
        code == "discarded" && !cleanupIncomplete -> Pcv3ClosedOutputDisplay(
        copy(R.string.pcv3_output_discarded_title, R.string.pcv3_output_discarded_body),
        Pcv3ResultTone.NEUTRAL,
        R.string.pcv3_output_discarded_close,
    )
    target == Pcv3OutputActionTarget.RECOVERY_ARTIFACT &&
        code == "discard-cleanup-incomplete" && cleanupIncomplete ->
        Pcv3ClosedOutputDisplay(
            copy(
                R.string.pcv3_output_discard_cleanup_title,
                R.string.pcv3_output_discard_cleanup_body,
            ),
            Pcv3ResultTone.WARNING,
            R.string.pcv3_warning_cleanup_close,
        )
    code == "expired" && !cleanupIncomplete -> Pcv3ClosedOutputDisplay(
        copy(R.string.pcv3_output_expired_title, R.string.pcv3_output_expired_body),
        Pcv3ResultTone.ERROR,
        R.string.pcv3_output_expired_close,
    )
    else -> Pcv3ClosedOutputDisplay(
        copy(R.string.pcv3_output_unknown_title, R.string.pcv3_output_unknown_body),
        Pcv3ResultTone.ERROR,
        R.string.pcv3_output_unknown_close,
    )
}

private fun copy(@StringRes title: Int, @StringRes body: Int) =
    Pcv3CopyResources(titleResId = title, bodyResId = body)

fun renderOperationStatus(
    context: Context,
    status: OperationStatusData,
    detail: OperationProgressDetail,
    progress: Float,
): OperationDisplayText {
    val statusText = staticStatusResource(status.code)?.let(context::getString)
        ?: rateStatusResource(status.code)?.let { resourceId ->
            if (status.speedMiBPerSecond.isFinite() &&
                status.speedMiBPerSecond >= 0.0 &&
                validEta.matches(status.eta)
            ) {
                context.getString(resourceId, status.speedMiBPerSecond, status.eta)
            } else {
                null
            }
        }
        ?: context.getString(R.string.fgs_working)

    val detailText = when (detail.code) {
        OperationProgress.PERCENT -> {
            if (progress.isFinite() && progress in 0f..1f) {
                context.getString(R.string.progress_percent, progress.toDouble() * 100.0)
            } else {
                null
            }
        }
        OperationProgress.ITEM_COUNT -> {
            if (detail.current >= 0 &&
                detail.total > 0 &&
                detail.current <= detail.total &&
                detail.total <= Int.MAX_VALUE
            ) {
                context.resources.getQuantityString(
                    R.plurals.progress_item_count,
                    detail.total.toInt(),
                    detail.current,
                    detail.total,
                )
            } else {
                null
            }
        }
        else -> null
    }

    return OperationDisplayText(statusText, detailText)
}

@StringRes
private fun staticStatusResource(code: String): Int? = when (code) {
    OperationStatus.STARTING -> R.string.status_starting
    OperationStatus.COMPLETED -> R.string.status_completed
    OperationStatus.CANCELLED -> R.string.status_cancelled
    OperationStatus.ERROR -> R.string.status_error
    OperationStatus.COMPRESSING_FILES -> R.string.status_compressing_files
    OperationStatus.GENERATING_VALUES -> R.string.status_generating_values
    OperationStatus.DERIVING_KEY -> R.string.status_deriving_key
    OperationStatus.READING_KEYFILES -> R.string.status_reading_keyfiles
    OperationStatus.CALCULATING_VALUES -> R.string.status_calculating_values
    OperationStatus.WRITING_VALUES -> R.string.status_writing_values
    OperationStatus.SPLITTING -> R.string.status_splitting
    OperationStatus.RECOMBINING_CHUNKS -> R.string.status_recombining_chunks
    OperationStatus.READING_VALUES -> R.string.status_reading_values
    OperationStatus.DUPLICATE_KEYFILES_WARNING -> R.string.status_duplicate_keyfiles_warning
    OperationStatus.VERIFYING_INTEGRITY -> R.string.status_verifying_integrity
    OperationStatus.MAC_VERIFICATION_FAILED_CONTINUING ->
        R.string.status_mac_verification_failed_continuing
    OperationStatus.REPAIRING_VERIFYING -> R.string.status_repairing_verifying
    OperationStatus.INTEGRITY_VERIFIED_DECRYPTING ->
        R.string.status_integrity_verified_decrypting
    OperationStatus.COMPARING_VALUES -> R.string.status_comparing_values
    OperationStatus.UNZIPPING -> R.string.status_unzipping
    OperationStatus.ADDING_PLAUSIBLE_DENIABILITY -> R.string.status_adding_plausible_deniability
    OperationStatus.REMOVING_DENIABILITY_PROTECTION ->
        R.string.status_removing_deniability_protection
    else -> null
}

@StringRes
private fun rateStatusResource(code: String): Int? = when (code) {
    OperationStatus.COMPRESSING_RATE -> R.string.status_compressing_rate
    OperationStatus.ENCRYPTING_RATE -> R.string.status_encrypting_rate
    OperationStatus.SPLITTING_RATE -> R.string.status_splitting_rate
    OperationStatus.RECOMBINING_RATE -> R.string.status_recombining_rate
    OperationStatus.VERIFYING_RATE -> R.string.status_verifying_rate
    OperationStatus.DECRYPTING_RATE -> R.string.status_decrypting_rate
    OperationStatus.REPAIRING_RATE -> R.string.status_repairing_rate
    OperationStatus.UNPACKING_RATE -> R.string.status_unpacking_rate
    OperationStatus.ADDING_DENIABILITY_RATE -> R.string.status_adding_deniability_rate
    OperationStatus.REMOVING_DENIABILITY_RATE -> R.string.status_removing_deniability_rate
    else -> null
}

private val validEta = Regex("^[0-9]{2,}:[0-5][0-9]:[0-5][0-9]$")
