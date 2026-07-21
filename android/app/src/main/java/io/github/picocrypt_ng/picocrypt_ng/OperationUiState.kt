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
