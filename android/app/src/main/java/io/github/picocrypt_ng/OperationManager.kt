package io.github.picocrypt_ng

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import io.github.picocrypt_ng.FileCopyService

/**
 * Manages encryption/decryption operations and their progress.
 */
object OperationManager {
    private val _currentOperation = MutableStateFlow<OperationState?>(null)
    val currentOperation: StateFlow<OperationState?> = _currentOperation.asStateFlow()
    
    /**
     * Starts an encryption operation.
     */
    suspend fun startEncrypt(
        context: Context,
        formData: FormData
    ): Result<String> = withContext(Dispatchers.IO) {
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
        
        // Clean up old files before starting new operation to prevent contamination
        FileCopyService.cleanupOperationFilesBeforeStart(context)
        
        // Generate output file path using FileCopyService
        val outputFilePath = FileCopyService.getOutputFilePath(context, formData.copiedFilePath, isEncrypt = true)
        
        // Start operation
        val operationID = GoBridge.startOperation()
        
        val options = EncryptOptions(
            comments = formData.comments,
            paranoid = formData.paranoid,
            reedSolomon = formData.reedSolomon,
            deniability = formData.deniability,
            compress = false, // Not supported in UI yet
            keyfiles = formData.keyfileFilenames.map { it.internalPath },
            keyfileOrdered = formData.keyfileOrdered
        )
        
        // Pass CharArray directly to GoBridge (it will convert to String internally only when needed)
        val result = GoBridge.startEncrypt(
            operationID,
            formData.copiedFilePath,
            outputFilePath,
            formData.passwordInput, // Pass CharArray directly
            options
        )
        
        result.onSuccess {
            _currentOperation.value = OperationState(
                id = operationID,
                type = OperationType.ENCRYPT,
                inputFile = formData.copiedFilePath,
                outputFile = outputFilePath,
                status = "Starting...",
                progress = 0f,
                info = "",
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
        
        if (!formData.isPasswordValid) {
            return@withContext Result.failure(AppError.ValidationError.InvalidPassword)
        }
        
        // Clean up old files before starting new operation to prevent contamination
        FileCopyService.cleanupOperationFilesBeforeStart(context)
        
        // Generate output file path using FileCopyService
        val outputFilePath = FileCopyService.getOutputFilePath(context, formData.copiedFilePath, isEncrypt = false)
        
        // Start operation
        val operationID = GoBridge.startOperation()
        
        val options = DecryptOptions(
            keyfiles = formData.keyfileFilenames.map { it.internalPath },
            forceDecrypt = false,
            verifyFirst = false,
            autoUnzip = true, // Auto-unzip decrypted files
            sameLevel = false,
            recombine = false, // Split volumes are not supported in the Android app
            deniability = formData.decryptionInfo?.deniability ?: false
        )
        
        // Pass CharArray directly to GoBridge (it will convert to String internally only when needed)
        val result = GoBridge.startDecrypt(
            operationID,
            formData.copiedFilePath,
            outputFilePath,
            formData.passwordInput, // Pass CharArray directly
            options
        )
        
        result.onSuccess {
            _currentOperation.value = OperationState(
                id = operationID,
                type = OperationType.DECRYPT,
                inputFile = formData.copiedFilePath,
                outputFile = outputFilePath,
                status = "Starting...",
                progress = 0f,
                info = "",
                formData = formData
            )
        }
        
        result.map { operationID }
    }
    
    /**
     * Polls progress for the current operation.
     */
    suspend fun pollProgress(): OperationState? = withContext(Dispatchers.IO) {
        val operation = _currentOperation.value ?: return@withContext null
        
        val result = GoBridge.getProgress(operation.id)
        result.getOrNull()?.let { progressState ->
            val error = if (progressState.done && progressState.status == "Error") {
                // Convert Go error string to AppError
                AppError.fromGoError(progressState.info, operation.type)
            } else {
                null
            }
            
            _currentOperation.value = operation.copy(
                status = progressState.status,
                progress = progressState.progress,
                info = progressState.info,
                done = progressState.done,
                error = error
            )
        }
        
        _currentOperation.value
    }
    
    /**
     * Cancels the current operation.
     */
    suspend fun cancelOperation(): Result<Unit> = withContext(Dispatchers.IO) {
        val operation = _currentOperation.value ?: return@withContext Result.failure(
            AppError.OperationError.GenericOperation("No active operation")
        )
        
        val result = GoBridge.cancelOperation(operation.id)
        result.onSuccess {
            _currentOperation.value = operation.copy(
                status = "Cancelled",
                done = true
            )
        }
        result
    }
    
    /**
     * Clears the current operation.
     * @param shouldCleanupFiles If true, deletes input, output, and keyfiles from internal storage.
     */
    suspend fun clearOperation(context: Context? = null, shouldCleanupFiles: Boolean = true) {
        val operation = _currentOperation.value
        
        // Clear passwords from form data before clearing operation
        operation?.formData?.clearPasswords()
        
        // Cleanup files if requested and context is provided
        if (shouldCleanupFiles && context != null && operation != null) {
            val formData = operation.formData
            val keyfilePaths = formData?.keyfileFilenames?.map { it.internalPath } ?: emptyList()
            
            FileCopyService.cleanupOperationFiles(
                context = context,
                inputFilePath = operation.inputFile,
                outputFilePath = operation.outputFile,
                keyfilePaths = keyfilePaths
            )
        }
        
        _currentOperation.value = null
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
            AppError.OperationError.GenericOperation("No active operation to retry")
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
    suspend fun retryDecryptWithForce(): Result<String> = withContext(Dispatchers.IO) {
        val operation = _currentOperation.value ?: return@withContext Result.failure(
            AppError.OperationError.GenericOperation("No active operation")
        )
        
        if (operation.type != OperationType.DECRYPT) {
            return@withContext Result.failure(
                AppError.OperationError.GenericOperation("Can only retry decryption operations")
            )
        }
        
        val formData = operation.formData ?: return@withContext Result.failure(
            AppError.OperationError.GenericOperation("Operation data not available for retry")
        )
        
        // Clear the current operation state
        _currentOperation.value = null
        
        // Start new operation with force decrypt enabled
        val operationID = GoBridge.startOperation()
        
        val options = DecryptOptions(
            keyfiles = formData.keyfileFilenames.map { it.internalPath },
            forceDecrypt = true, // Enable force decrypt
            verifyFirst = false,
            autoUnzip = true,
            sameLevel = false,
            recombine = false,
            deniability = formData.decryptionInfo?.deniability ?: false
        )
        
        // Pass CharArray directly to GoBridge (it will convert to String internally only when needed)
        val result = GoBridge.startDecrypt(
            operationID,
            operation.inputFile,
            operation.outputFile,
            formData.passwordInput, // Pass CharArray directly
            options
        )
        
        result.onSuccess {
            _currentOperation.value = OperationState(
                id = operationID,
                type = OperationType.DECRYPT,
                inputFile = operation.inputFile,
                outputFile = operation.outputFile,
                status = "Starting...",
                progress = 0f,
                info = "",
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
    val status: String,
    val progress: Float,
    val info: String,
    val done: Boolean = false,
    val error: AppError? = null,
    val formData: FormData? = null
)

enum class OperationType {
    ENCRYPT,
    DECRYPT
}

