package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import io.github.picocrypt_ng.picocrypt_ng.FileCopyService

/**
 * Manages encryption/decryption operations and their progress.
 */
object OperationManager {
    private val _currentOperation = MutableStateFlow<OperationState?>(null)
    val currentOperation: StateFlow<OperationState?> = _currentOperation.asStateFlow()

    private fun progressError(progressState: ProgressState, type: OperationType): AppError? =
        if (progressState.done && progressState.status.code == OperationStatus.ERROR) {
            AppError.fromGoError(
                progressState.technicalError,
                type,
                progressState.errorCode,
            )
        } else {
            null
        }
    
    /**
     * Starts an encryption operation.
     */
    suspend fun startEncrypt(
        context: Context,
        formData: FormData
    ): Result<String> = withContext(Dispatchers.IO) {
        // A folder/multi-file selection encrypts the staged tree (inputFiles), not a
        // single copiedFilePath. Validate the right source per selection kind.
        val isMulti = formData.selectionKind != SelectionKind.SINGLE_FILE
        if (!isMulti && formData.copiedFilePath.isEmpty()) {
            return@withContext Result.failure(AppError.ValidationError.NoFileSelected)
        }
        if (isMulti && formData.inputFiles.isEmpty()) {
            return@withContext Result.failure(AppError.ValidationError.NoFileSelected)
        }

        // A numbered split-volume chunk (secret.pcv.0) does not end in .pcv, so it lands
        // on the encrypt path and would be DOUBLE-ENCRYPTED. Android cannot recombine
        // (single-file picker), so reject it loudly before any work. Only meaningful for
        // a single-file selection (isSplitVolumeChunk is already SINGLE_FILE-gated).
        if (!isMulti && formData.isSplitVolumeChunk) {
            return@withContext Result.failure(AppError.ValidationError.SplitVolumeNotSupported)
        }

        if (!formData.isPasswordValid) {
            val error = if (formData.isEncrypt && !formData.isPasswordsMatch) {
                AppError.ValidationError.PasswordsMismatch
            } else {
                AppError.ValidationError.InvalidPassword
            }
            return@withContext Result.failure(error)
        }

        // Clean up old files before starting new operation to prevent contamination
        if (!FileCopyService.cleanupOperationFilesBeforeStart(context)) {
            return@withContext Result.failure(AppError.FileError.DeleteFailed())
        }

        // Generate output file path using FileCopyService. For encrypt this is a fixed
        // output_file.pcv regardless of the input path, so an empty copiedFilePath (multi
        // selection) is fine.
        val outputFilePath = FileCopyService.getOutputFilePath(context, formData.copiedFilePath, isEncrypt = true)

        // Start operation
        val operationID = GoBridge.startOperation().getOrElse { return@withContext Result.failure(it) }

        val options = EncryptOptions(
            comments = formData.comments,
            paranoid = formData.paranoid,
            reedSolomon = formData.reedSolomon,
            deniability = formData.deniability,
            compress = formData.compress,
            keyfiles = formData.keyfileFilenames.map { it.internalPath },
            keyfileOrdered = formData.keyfileOrdered
        )

        // Encode the password to UTF-8 bytes without a String; GoBridge zeroes them.
        // For a multi selection the single inputFile is empty and the staged arrays carry
        // the inputs; for a single file the arrays are empty (the degenerate case).
        val result = GoBridge.startEncrypt(
            operationID,
            if (isMulti) "" else formData.copiedFilePath,
            outputFilePath,
            formData.passwordInput.toUtf8BytesSecure(),
            options,
            inputFiles = formData.inputFiles,
            onlyFolders = formData.onlyFolders,
            onlyFiles = formData.onlyFiles
        )
        
        result.onSuccess {
            _currentOperation.value = OperationState(
                id = operationID,
                type = OperationType.ENCRYPT,
                inputFile = formData.copiedFilePath,
                outputFile = outputFilePath,
                status = OperationStatusData(OperationStatus.STARTING),
                detail = OperationProgressDetail(OperationProgress.NONE),
                progress = 0f,
                formData = formData
            )
        }
        
        result.map { operationID }
    }
    
    /**
     * Starts a decryption operation.
     */
    suspend fun startDecrypt(
        context: Context,
        formData: FormData
    ): Result<String> = withContext(Dispatchers.IO) {
        if (formData.copiedFilePath.isEmpty()) {
            return@withContext Result.failure(AppError.ValidationError.NoFileSelected)
        }

        // A desktop split volume (secret.pcv.0) cannot be decrypted on Android without
        // recombining its sibling chunks, which the single-file picker cannot supply.
        // Fail loud instead of running the Go op on one chunk (a confusing corrupt error).
        if (formData.isSplitVolumeChunk) {
            return@withContext Result.failure(AppError.ValidationError.SplitVolumeNotSupported)
        }

        if (!formData.isPasswordValid) {
            return@withContext Result.failure(AppError.ValidationError.InvalidPassword)
        }

        // Clean up old files before starting new operation to prevent contamination
        if (!FileCopyService.cleanupOperationFilesBeforeStart(context)) {
            return@withContext Result.failure(AppError.FileError.DeleteFailed())
        }

        // Generate output file path using FileCopyService
        val outputFilePath = FileCopyService.getOutputFilePath(context, formData.copiedFilePath, isEncrypt = false)

        // Start operation
        val operationID = GoBridge.startOperation().getOrElse { return@withContext Result.failure(it) }

        val options = DecryptOptions(
            keyfiles = formData.keyfileFilenames.map { it.internalPath },
            forceDecrypt = false,
            verifyFirst = formData.verifyFirst,
            // INTEROP: Go auto-unzip extracts to a subdirectory and DELETES the zip
            // (decrypt.go:816,847). Android exports a single fixed output path, so an
            // unzipped output orphans the export -> SaveFailed. Keep OFF until a SAF
            // tree-export exists; the intact .zip stays exportable. Matches the CLI
            // --auto-unzip default (decrypt.go:94).
            autoUnzip = false,
            sameLevel = false,
            recombine = false, // Split volumes are not supported in the Android app
            deniability = formData.decryptionInfo?.deniability ?: false
        )
        
        // Encode the password to UTF-8 bytes without a String; GoBridge zeroes them.
        val result = GoBridge.startDecrypt(
            operationID,
            formData.copiedFilePath,
            outputFilePath,
            formData.passwordInput.toUtf8BytesSecure(),
            options
        )
        
        result.onSuccess {
            _currentOperation.value = OperationState(
                id = operationID,
                type = OperationType.DECRYPT,
                inputFile = formData.copiedFilePath,
                outputFile = outputFilePath,
                status = OperationStatusData(OperationStatus.STARTING),
                detail = OperationProgressDetail(OperationProgress.NONE),
                progress = 0f,
                formData = formData
            )
        }
        
        result.map { operationID }
    }
    
    /**
     * Surfaces a start failure as a terminal error OperationState so the UI can show it
     * (e.g. via OperationUiState.Failed) instead of silently swallowing the Result.failure.
     * Only writes if _currentOperation is null (i.e. the start truly failed before
     * establishing a state); does not clobber an already-running operation.
     */
    fun surfaceStartFailure(type: OperationType, error: Throwable) {
        val appError = if (error is AppError) error
                       else AppError.OperationError.GenericOperation(
                           error.message ?: "Operation failed to start",
                           error.message,
                           R.string.error_operation_start_failed,
                       )
        _currentOperation.update { current ->
            if (current != null) current  // Don't clobber an already-running op.
            else OperationState(
                id = "",
                type = type,
                inputFile = "",
                outputFile = "",
                status = OperationStatusData(OperationStatus.ERROR),
                detail = OperationProgressDetail(OperationProgress.NONE),
                progress = 0f,
                done = true,
                error = appError
            )
        }
    }

    /**
     * Polls progress for the current operation.
     */
    suspend fun pollProgress(): OperationState? = withContext(Dispatchers.IO) {
        val operation = _currentOperation.value ?: return@withContext null
        // Once terminal, do not let a slow/concurrent poll (UI 500ms + FGS 1000ms run
        // simultaneously) overwrite the freshly-final state with stale progress.
        if (operation.done) return@withContext operation

        val result = GoBridge.getProgress(operation.id)
        result.getOrNull()?.let { progressState ->
            // Classify by the stable Go error code (not fragile substring matching).
            val error = progressError(progressState, operation.type)
            
            // Atomic read-modify-write: between capturing `operation` above and the
            // suspending getProgress I/O, a concurrent coroutine (the FGS 1000ms poll
            // vs. the UI 500ms poll, or a clear/replace) may have changed the flow. An
            // unconditional write would resurrect a cleared op as a phantom non-done
            // state or clobber a newer op. Update conditionally on the latest value.
            _currentOperation.update { current ->
                if (current == null || current.id != operation.id || current.done) {
                    // cleared, replaced, or already finished concurrently -- do not
                    // resurrect/clobber.
                    current
                } else {
                    // Copy onto `current` (not the captured `operation`): same id,
                    // latest base.
                    current.copy(
                        status = progressState.status,
                        detail = progressState.detail,
                        progress = progressState.progress,
                        done = progressState.done,
                        error = error
                    )
                }
            }
        }
        
        _currentOperation.value
    }
    
    /**
     * Cancels the current operation.
     */
    suspend fun cancelOperation(): Result<Unit> = withContext(Dispatchers.IO) {
        val operation = _currentOperation.value ?: return@withContext Result.failure(
            AppError.OperationError.GenericOperation(
                userMessage = "",
                messageResId = R.string.error_no_active_operation,
            )
        )
        
        val result = GoBridge.cancelOperation(operation.id)
        result.onSuccess { progressState ->
            val error = progressError(progressState, operation.type)
            _currentOperation.update { current ->
                if (current == null || current.id != operation.id || current.done) {
                    current
                } else {
                    current.copy(
                        status = progressState.status,
                        detail = progressState.detail,
                        progress = progressState.progress,
                        done = progressState.done,
                        error = error,
                    )
                }
            }
        }
        result.map { Unit }
    }
    
    /**
     * Clears the current operation.
     * @param shouldCleanupFiles If true, deletes input, output, and keyfiles from internal storage.
     */
    suspend fun clearOperation(
        context: Context? = null,
        shouldCleanupFiles: Boolean = true,
    ): Result<Unit> {
        val operation = _currentOperation.value
            ?: return Result.success(Unit)
        
        // Clear passwords from form data before clearing operation
        operation.formData?.clearPasswords()

        if (!shouldCleanupFiles) {
            _currentOperation.compareAndSet(operation, null)
            return Result.success(Unit)
        }

        if (context == null) {
            val error = AppError.FileError.DeleteFailed(
                technicalMessage = "Android context is required to clean operation files",
            )
            retainCleanupFailure(operation, error)
            return Result.failure(error)
        }

        val formData = operation.formData
        val keyfilePaths = formData?.keyfileFilenames?.map { it.internalPath } ?: emptyList()

        val filesCleaned = FileCopyService.cleanupOperationFiles(
                context = context,
                inputFilePath = operation.inputFile,
                outputFilePath = operation.outputFile,
                keyfilePaths = keyfilePaths,
            )

        // A folder/multi selection stages plaintext copies under STAGING_DIR that the
        // per-file cleanup above does not cover (it only knows the single input path).
        // Always attempt this cleanup even if one of the paths above could not be removed.
        val stagingCleaned = withContext(Dispatchers.IO) {
            StagingService.wipeStaging(context)
        }

        if (!filesCleaned || !stagingCleaned) {
            val error = AppError.FileError.DeleteFailed(
                technicalMessage = buildString {
                    append("Operation cleanup incomplete:")
                    if (!filesCleaned) append(" operation files")
                    if (!stagingCleaned) append(" staging")
                },
            )
            retainCleanupFailure(operation, error)
            return Result.failure(error)
        }

        _currentOperation.compareAndSet(operation, null)
        return Result.success(Unit)
    }

    private fun retainCleanupFailure(
        operation: OperationState,
        error: AppError.FileError.DeleteFailed,
    ) {
        _currentOperation.update { current ->
            if (current == null || current.id != operation.id) {
                current
            } else {
                current.copy(
                    status = OperationStatusData(OperationStatus.ERROR),
                    detail = OperationProgressDetail(OperationProgress.NONE),
                    done = true,
                    error = error,
                )
            }
        }
    }
    
    /**
     * Retries an operation with the same files and options but allows password to be re-entered.
     * This should be called when a password/auth error occurs.
     * @param context Android context
     * @param formData Updated form data (typically with new password, but same files/options)
     * @return Result with operation ID on success
     */
    suspend fun retryOperation(
        context: Context,
        formData: FormData
    ): Result<String> = withContext(Dispatchers.IO) {
        val operation = _currentOperation.value ?: return@withContext Result.failure(
            AppError.OperationError.GenericOperation(
                userMessage = "",
                messageResId = R.string.error_no_operation_to_retry,
            )
        )
        
        if (formData.copiedFilePath.isEmpty()) {
            return@withContext Result.failure(AppError.ValidationError.NoFileSelected)
        }
        
        if (!formData.isPasswordValid) {
            val error = if (formData.isEncrypt && !formData.isPasswordsMatch) {
                AppError.ValidationError.PasswordsMismatch
            } else {
                AppError.ValidationError.InvalidPassword
            }
            return@withContext Result.failure(error)
        }
        
        // Clear the current operation state (but don't cleanup files)
        _currentOperation.value = null
        
        // Start new operation with same files/options but new password
        val result = if (operation.type == OperationType.ENCRYPT) {
            startEncrypt(context, formData)
        } else {
            startDecrypt(context, formData)
        }
        
        result
    }
    
    /**
     * Retries decryption with force decrypt enabled.
     * This should only be called when a decryption operation has failed due to data corruption.
     */
    suspend fun retryDecryptWithForce(context: Context): Result<String> = withContext(Dispatchers.IO) {
        val operation = _currentOperation.value ?: return@withContext Result.failure(
            AppError.OperationError.GenericOperation(
                userMessage = "",
                messageResId = R.string.error_no_active_operation,
            )
        )
        
        if (operation.type != OperationType.DECRYPT) {
            return@withContext Result.failure(
                AppError.OperationError.GenericOperation(
                    userMessage = "",
                    messageResId = R.string.error_decrypt_retry_only,
                )
            )
        }
        
        val formData = operation.formData ?: return@withContext Result.failure(
            AppError.OperationError.GenericOperation(
                userMessage = "",
                messageResId = R.string.error_operation_data_unavailable,
            )
        )

        // Force-decrypt BYPASSES integrity/RS checks, so an empty password (e.g. a
        // CharArray zeroed by a prior clear) would silently run. Mirror startDecrypt's
        // guard and fail loud before encoding the password or starting the op.
        if (!formData.isPasswordValid) {
            return@withContext Result.failure(AppError.ValidationError.InvalidPassword)
        }

        if (!FileCopyService.cleanupOperationFilesBeforeStart(context)) {
            return@withContext Result.failure(AppError.FileError.DeleteFailed())
        }

        // Clear the current operation state
        _currentOperation.value = null

        // Start new operation with force decrypt enabled
        val operationID = GoBridge.startOperation().getOrElse { return@withContext Result.failure(it) }
        
        val options = DecryptOptions(
            keyfiles = formData.keyfileFilenames.map { it.internalPath },
            forceDecrypt = true, // Enable force decrypt
            verifyFirst = formData.verifyFirst,
            autoUnzip = false, // See startDecrypt: off until SAF tree-export exists.
            sameLevel = false,
            recombine = false,
            deniability = formData.decryptionInfo?.deniability ?: false
        )
        
        // Encode the password to UTF-8 bytes without a String; GoBridge zeroes them.
        val result = GoBridge.startDecrypt(
            operationID,
            operation.inputFile,
            operation.outputFile,
            formData.passwordInput.toUtf8BytesSecure(),
            options
        )
        
        result.onSuccess {
            _currentOperation.value = OperationState(
                id = operationID,
                type = OperationType.DECRYPT,
                inputFile = operation.inputFile,
                outputFile = operation.outputFile,
                status = OperationStatusData(OperationStatus.STARTING),
                detail = OperationProgressDetail(OperationProgress.NONE),
                progress = 0f,
                formData = formData
            )
        }
        
        result.map { operationID }
    }
}

/**
 * State of an encryption/decryption operation.
 */
data class OperationState(
    val id: String,
    val type: OperationType,
    val inputFile: String,
    val outputFile: String,
    val status: OperationStatusData,
    val detail: OperationProgressDetail,
    val progress: Float,
    val done: Boolean = false,
    val error: AppError? = null,
    val formData: FormData? = null
)

enum class OperationType {
    ENCRYPT,
    DECRYPT
}
