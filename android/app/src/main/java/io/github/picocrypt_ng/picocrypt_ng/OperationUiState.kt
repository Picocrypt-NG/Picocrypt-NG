package io.github.picocrypt_ng.picocrypt_ng


/** Exhaustive UI state for an encrypt/decrypt operation. */
sealed interface OperationUiState {
    data object Idle : OperationUiState
    data class Running(
        val type: OperationType,
        val progress: Float,
        val status: OperationStatusData,
        val detail: OperationProgressDetail,
    ) : OperationUiState
    data class Cancelled(val type: OperationType) : OperationUiState
    data class Success(val type: OperationType) : OperationUiState
    data class Failed(val type: OperationType, val error: AppError) : OperationUiState
}

/** The complete scalar portion of one immutable Go PCV3 snapshot. */
data class Pcv3SnapshotView(
    val statusCode: String,
    val statusArgs: List<String>,
    val semantic: Pcv3Semantic,
    val publication: Pcv3Publication,
    val forceProvenance: String,
    val d1BootstrapProvenance: String,
    val detailStage: String,
    val diagnostic: String,
    val completionClass: String,
    val resultArgs: List<String>,
    val warnings: List<String>,
    val archivePending: Boolean,
    val restoredReceipt: String,
    val authenticatedComment: String = "",
)

data class Pcv3Semantic(val outcome: String, val stage: String, val code: String)

data class Pcv3Publication(
    val attempted: Boolean,
    val state: String,
    val stage: String,
    val code: String,
)

/** Consent data is scalar display state; the handle stays Go-owned in [Pcv3Presentation.Live]. */
data class Pcv3ConsentView(
    val mode: String,
    val allowedRoles: List<String>,
    val selectedRole: String? = null,
)

/** Authority-free terminal truth from one consumed retained-output action. */
data class Pcv3OutputResultView(
    val code: String,
    val cleanupIncomplete: Boolean,
)

/** Immutable, path-free recovery artifact summary suitable for rendering. */
data class Pcv3ArtifactMetadataView(
    val kind: String,
    val role: String,
    val plaintextLength: String,
    val finalStatus: String,
    val rangeCount: String,
    val verifiedCount: String,
    val unverifiedCount: String,
    val missingCount: String,
)

data class Pcv3ArtifactRangeView(
    val recordIndex: String,
    val start: String,
    val end: String,
    val status: String,
)

data class Pcv3ArtifactPageView(
    val offsetDecimal: String,
    val ranges: List<Pcv3ArtifactRangeView>,
)

/** Closed detail-loading state; no variant carries a native handle or action. */
sealed interface Pcv3ArtifactDetailsUiState {
    data object Closed : Pcv3ArtifactDetailsUiState
    data object Loading : Pcv3ArtifactDetailsUiState
    data class Ready(
        val metadata: Pcv3ArtifactMetadataView,
        val page: Pcv3ArtifactPageView,
    ) : Pcv3ArtifactDetailsUiState
    data class Failed(val code: String) : Pcv3ArtifactDetailsUiState
}

internal fun Pcv3ArtifactMetadataData.toView(): Pcv3ArtifactMetadataView =
    Pcv3ArtifactMetadataView(
        kind = kind,
        role = role,
        plaintextLength = plaintextLength,
        finalStatus = finalStatus,
        rangeCount = rangeCount,
        verifiedCount = verifiedCount,
        unverifiedCount = unverifiedCount,
        missingCount = missingCount,
    )

internal fun Pcv3ArtifactPageData.toView(): Pcv3ArtifactPageView =
    Pcv3ArtifactPageView(
        offsetDecimal = offsetDecimal,
        ranges = ranges.map {
            Pcv3ArtifactRangeView(it.recordIndex, it.start, it.end, it.status)
        },
    )

/**
 * Sole Android PCV3 projection.  It carries every scalar result axis together
 * with only live Go capabilities; legacy OperationUiState never represents it.
 */
sealed interface Pcv3Presentation {
    val snapshot: Pcv3SnapshotView
    val operationId: String
    val generation: Long
    val artifactMetadata: Pcv3ArtifactMetadataView? get() = null

    /** True when this presentation projects a PCV3 creation (write) operation. */
    val isCreation: Boolean get() = false

    data class Live(
        override val snapshot: Pcv3SnapshotView,
        override val operationId: String,
        override val generation: Long,
        internal val operationHandle: Pcv3OperationCapability,
        internal val consentHandle: Pcv3ConsentCapability?,
        internal val archiveHandle: Pcv3ArchiveCapability?,
        val consent: Pcv3ConsentView?,
        internal val outputHandle: Pcv3OutputCapability? = null,
        val outputPending: Boolean = false,
        val outputActionInFlight: Boolean = false,
        override val artifactMetadata: Pcv3ArtifactMetadataView? = null,
        override val isCreation: Boolean = false,
    ) : Pcv3Presentation

    data class Restored(
        override val snapshot: Pcv3SnapshotView,
        override val operationId: String,
        override val generation: Long,
        val receiptId: String,
    ) : Pcv3Presentation

    /** A Go-released terminal display record; no operation or action handle remains. */
    data class Final(
        override val snapshot: Pcv3SnapshotView,
        override val operationId: String,
        override val generation: Long,
        val outputAction: Pcv3OutputResultView? = null,
        override val artifactMetadata: Pcv3ArtifactMetadataView? = null,
        override val isCreation: Boolean = false,
    ) : Pcv3Presentation
}

/** Reads every bounded native snapshot field once; capability lookup stays in [Pcv3Lifecycle]. */
internal fun projectPcv3Snapshot(
    snapshot: Pcv3SnapshotData,
) : Pcv3SnapshotView = Pcv3SnapshotView(
        statusCode = snapshot.statusCode,
        statusArgs = snapshot.statusArgs,
        semantic = Pcv3Semantic(snapshot.outcome, snapshot.stage, snapshot.code),
        publication = Pcv3Publication(
            attempted = snapshot.publicationAttempted, state = snapshot.publicationState, stage = snapshot.publicationStage, code = snapshot.publicationCode,
        ),
        forceProvenance = snapshot.forceProvenance, d1BootstrapProvenance = snapshot.d1BootstrapProvenance, detailStage = snapshot.detailStage,
        diagnostic = snapshot.diagnostic,
        completionClass = snapshot.completionClass,
        resultArgs = snapshot.args,
        warnings = snapshot.warnings,
        archivePending = snapshot.archivePending,
        restoredReceipt = snapshot.restoredReceipt,
        authenticatedComment = snapshot.authenticatedComment,
    )

/** Accepts only Go's two exact closed role tuples, in their canonical order. */
internal fun Pcv3ConsentCapability.toViewOrNull(): Pcv3ConsentView? {
    val roles = roles()
    val mode = mode()
    val expectedRoles = when (mode) {
        "force-unverified-normal" -> listOf("primary", "backup")
        "force-unverified-d1" -> listOf("d1-front", "d1-tail")
        else -> return null
    }
    if (roles != expectedRoles) {
        return null
    }
    return Pcv3ConsentView(mode = mode, allowedRoles = roles)
}

/**
 * Projects the polled [OperationState] (source of truth from the Go bridge) into the exhaustive
 * [OperationUiState] consumed by the UI. This replaces the prior done/error/magic-status boolean
 * machine.
 *
 * Behaviour is preserved from the old ProgressCard branches except that cancelled terminal states
 * now remain distinct from successful output-producing completion:
 *  - null            -> Idle    (no operation)
 *  - !done           -> Running (operation in progress; cancel affordance)
 *  - done && error   -> Failed  (carries the full AppError so ProgressCard can gate the
 *                                force-decrypt (DataCorruption) and password-retry (PasswordAuth)
 *                                buttons via allowsForceDecrypt()/allowsPasswordRetry())
 *  - done && status=OperationStatus.CANCELLED
 *                    -> Cancelled (terminal, but no successful output to save)
 *  - done && !error  -> Success (the "Completed" save dialog)
 */
fun OperationState?.toUiState(): OperationUiState = when {
    this == null -> OperationUiState.Idle
    !done -> OperationUiState.Running(type, progress, status, detail)
    error != null -> OperationUiState.Failed(type, error)
    status.code == OperationStatus.CANCELLED -> OperationUiState.Cancelled(type)
    else -> OperationUiState.Success(type)
}
