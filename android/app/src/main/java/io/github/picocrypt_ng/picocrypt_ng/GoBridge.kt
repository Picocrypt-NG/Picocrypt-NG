package io.github.picocrypt_ng.picocrypt_ng

import android.os.Parcelable
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.parcelize.Parcelize
import mobile.Mobile
import mobile.ProgressResult as GoProgressResult
import org.json.JSONArray
import org.json.JSONObject

/**
 * Options for encryption operations.
 * This is the Kotlin representation of the Go EncryptOptions struct.
 */
data class EncryptOptions(
    val comments: String = "",
    val paranoid: Boolean = false,
    val reedSolomon: Boolean = false,
    val deniability: Boolean = false,
    val compress: Boolean = false,
    val keyfiles: List<String> = emptyList(),
    val keyfileOrdered: Boolean = false
)

/**
 * Options for decryption operations.
 * This is the Kotlin representation of the Go DecryptOptions struct.
 */
data class DecryptOptions(
    val keyfiles: List<String> = emptyList(),
    val forceDecrypt: Boolean = false,
    val verifyFirst: Boolean = false,
    val autoUnzip: Boolean = false,
    val sameLevel: Boolean = false,
    val recombine: Boolean = false,
    val deniability: Boolean = false
)

/**
 * Decryption metadata information.
 * This contains encryption settings and requirements that can be read
 * from an encrypted file without decrypting it.
 */
@Parcelize
data class DecryptionInfo(
    val keyfilesRequired: Boolean,
    val keyfileOrdered: Boolean,
    val reedSolomon: Boolean,
    val deniability: Boolean,
    val paranoid: Boolean,
    val comments: String,
    val readable: Boolean // false if deniable (can't read other fields without password)
) : Parcelable

/**
 * Progress state for an operation.
 * This is the Kotlin representation of the Go ProgressResult struct.
 */
data class ProgressState(
    val status: OperationStatusData,
    val detail: OperationProgressDetail,
    val progress: Float,
    val done: Boolean,
    val technicalError: String = "",
    val errorCode: String = "",
)

/**
 * Kotlin wrapper for Go mobile bindings.
 * 
 * This bridge connects the Android app to the Go encryption backend
 * through gomobile bindings. The Go mobile package provides all
 * encryption/decryption functionality.
 */
object GoBridge {
    /**
     * Starts a new operation and returns its ID.
     * This should be called before StartEncrypt or StartDecrypt.
     *
     * @return Result containing the operation ID, or an AppError if the Go binding
     *   fails. A failure is never masked with a fabricated ID: a fake ID would not
     *   exist in the Go operation map, so the next call would fail with a misleading
     *   "operation not found" and hide the real cause.
     */
    fun startOperation(): Result<String> {
        return try {
            Result.success(Mobile.startOperation())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }
    
    /**
     * Detects if a file should be encrypted or decrypted.
     * @param filePath Path to the file to check
     * @return Result containing true for encrypt, false for decrypt, or error if detection fails
     */
    fun detectOperation(filePath: String): Result<Boolean> {
        return try {
            val result = Mobile.detectOperation(filePath)
            Result.success(result)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Return error instead of fallback - Go binding failure is a critical error
            Result.failure(
                AppError.OperationError.GenericOperation(
                    userMessage = "",
                    technicalMessage = "Go binding error: ${e.message ?: e.toString()}",
                    messageResId = R.string.error_detect_operation_type_failed,
                )
            )
        }
    }
    
    /**
     * Starts an encryption operation in the background.
     * 
     * @param operationID Operation ID from startOperation()
     * @param inputFile Path to input file
     * @param outputFile Path to output file
     * @param password Password for encryption as UTF-8 bytes; zeroed before this returns
     * @param options Encryption options
     * @return Result indicating success or failure
     */
    fun startEncrypt(
        operationID: String,
        inputFile: String,
        outputFile: String,
        password: ByteArray,
        options: EncryptOptions,
        inputFiles: List<String> = emptyList(),
        onlyFolders: List<String> = emptyList(),
        onlyFiles: List<String> = emptyList()
    ): Result<Unit> {
        return try {
            // Build JSON request (password is passed separately as bytes, never in JSON)
            val requestJson = buildEncryptRequestJson(
                operationID, inputFile, outputFile, options, inputFiles, onlyFolders, onlyFiles
            )

            // Note: gomobile copies the array across JNI; that transient bridge copy is not reachable for zeroing (intrinsic to the binding).
            val errorMsg = Mobile.startEncrypt(requestJson, password)

            if (errorMsg.isNotEmpty()) {
                // Convert Go error to AppError (operation type unknown here, use generic)
                val appError = AppError.fromGoError(errorMsg, OperationType.ENCRYPT)
                Result.failure(appError)
            } else {
                Result.success(Unit)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        } finally {
            password.fill(0)
        }
    }
    
    /**
     * Starts a decryption operation in the background.
     * 
     * @param operationID Operation ID from startOperation()
     * @param inputFile Path to input file
     * @param outputFile Path to output file
     * @param password Password for decryption as UTF-8 bytes; zeroed before this returns
     * @param options Decryption options
     * @return Result indicating success or failure
     */
    fun startDecrypt(
        operationID: String,
        inputFile: String,
        outputFile: String,
        password: ByteArray,
        options: DecryptOptions
    ): Result<Unit> {
        return try {
            // Build JSON request (password is passed separately as bytes, never in JSON)
            val requestJson = buildDecryptRequestJson(operationID, inputFile, outputFile, options)

            // Note: gomobile copies the array across JNI; that transient bridge copy is not reachable for zeroing (intrinsic to the binding).
            val errorMsg = Mobile.startDecrypt(requestJson, password)

            if (errorMsg.isNotEmpty()) {
                // Convert Go error to AppError
                val appError = AppError.fromGoError(errorMsg, OperationType.DECRYPT)
                Result.failure(appError)
            } else {
                Result.success(Unit)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        } finally {
            password.fill(0)
        }
    }
    
    /**
     * Gets the current progress state for an operation.
     * 
     * @param operationID Operation ID to get progress for
     * @return Result containing ProgressState or error
     */
    fun getProgress(operationID: String): Result<ProgressState> {
        return try {
            val result: GoProgressResult = Mobile.getProgress(operationID)

            Result.success(result.toProgressState())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }
    
    /**
     * Cancels a running operation.
     * 
     * @param operationID Operation ID to cancel
     * @return Result containing the canonical terminal state, or an error
     */
    fun cancelOperation(operationID: String): Result<ProgressState> {
        return try {
            val result: GoProgressResult = Mobile.cancelOperation(operationID)
            Result.success(result.toProgressState())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }

    internal fun GoProgressResult.toProgressState(): ProgressState = ProgressState(
        status = OperationStatusData(
            code = getStatusCode() ?: "",
            speedMiBPerSecond = getStatusSpeedMiBPerSecond(),
            eta = getStatusETA() ?: "",
        ),
        detail = OperationProgressDetail(
            code = getInfoCode() ?: "",
            current = getInfoCurrent(),
            total = getInfoTotal(),
        ),
        progress = getProgress(),
        done = getDone(),
        technicalError = getError() ?: "",
        errorCode = getCode() ?: "",
    )
    
    /**
     * Gets decryption metadata from an encrypted file without decrypting it.
     * This allows the app to determine what credentials and settings were used
     * during encryption.
     * 
     * @param filePath Path to the encrypted file
     * @return Result containing DecryptionInfo or error
     */
    fun getDecryptionInfo(filePath: String): Result<DecryptionInfo> {
        return try {
            val jsonString = Mobile.getDecryptionInfo(filePath)
            Result.success(parseDecryptionInfo(jsonString))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }

    /**
     * Builds the encryption request JSON sent to Mobile.startEncrypt. The password is
     * intentionally NEVER included here -- it is passed to Mobile as raw bytes and zeroed.
     * Extracted so unit tests verify the REAL serialization instead of re-deriving it.
     */
    internal fun buildEncryptRequestJson(
        operationID: String,
        inputFile: String,
        outputFile: String,
        options: EncryptOptions,
        inputFiles: List<String> = emptyList(),
        onlyFolders: List<String> = emptyList(),
        onlyFiles: List<String> = emptyList()
    ): String = JSONObject().apply {
        put("operationID", operationID)
        put("inputFile", inputFile)
        // Folder/multi-file selection arrays forwarded to the Go core (it zips them).
        // Always present (empty for the single-file path) so the Go side reads a stable shape.
        put("inputFiles", JSONArray().apply { inputFiles.forEach { put(it) } })
        put("onlyFolders", JSONArray().apply { onlyFolders.forEach { put(it) } })
        put("onlyFiles", JSONArray().apply { onlyFiles.forEach { put(it) } })
        put("outputFile", outputFile)
        put("comments", options.comments)
        put("keyfiles", JSONArray().apply { options.keyfiles.forEach { put(it) } })
        put("paranoid", options.paranoid)
        put("reedSolomon", options.reedSolomon)
        put("deniability", options.deniability)
        put("compress", options.compress)
        put("keyfileOrdered", options.keyfileOrdered)
    }.toString()

    /**
     * Builds the decryption request JSON sent to Mobile.startDecrypt. As with encryption,
     * the password is never serialized. Extracted for the same testability reason.
     */
    internal fun buildDecryptRequestJson(
        operationID: String,
        inputFile: String,
        outputFile: String,
        options: DecryptOptions
    ): String = JSONObject().apply {
        put("operationID", operationID)
        put("inputFile", inputFile)
        put("outputFile", outputFile)
        put("keyfiles", JSONArray().apply { options.keyfiles.forEach { put(it) } })
        put("forceDecrypt", options.forceDecrypt)
        put("verifyFirst", options.verifyFirst)
        put("autoUnzip", options.autoUnzip)
        put("sameLevel", options.sameLevel)
        put("recombine", options.recombine)
        put("deniability", options.deniability)
    }.toString()

    /**
     * Parses the decryption-metadata JSON returned by Mobile.getDecryptionInfo. Uses
     * getBoolean/getString, which THROW on a missing field rather than silently
     * defaulting (a missing keyfilesRequired must never be read as false). Extracted so
     * the parser is unit-tested directly.
     */
    internal fun parseDecryptionInfo(jsonString: String): DecryptionInfo {
        val json = JSONObject(jsonString)
        return DecryptionInfo(
            keyfilesRequired = json.getBoolean("keyfilesRequired"),
            keyfileOrdered = json.getBoolean("keyfileOrdered"),
            reedSolomon = json.getBoolean("reedSolomon"),
            deniability = json.getBoolean("deniability"),
            paranoid = json.getBoolean("paranoid"),
            comments = json.getString("comments"),
            readable = json.getBoolean("readable")
        )
    }
}
