package io.github.picocrypt_ng

import android.os.Parcelable
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
    val status: String,
    val progress: Float,
    val info: String,
    val done: Boolean
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
     */
    fun startOperation(): String {
        return try {
            Mobile.startOperation()
        } catch (e: Exception) {
            // Generate a fallback ID if Go binding fails
            "op_${System.currentTimeMillis()}"
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
        } catch (e: Exception) {
            // Return error instead of fallback - Go binding failure is a critical error
            Result.failure(
                AppError.OperationError.GenericOperation(
                    userMessage = "Failed to detect operation type: ${e.message ?: "Unknown error"}",
                    technicalMessage = "Go binding error: ${e.message ?: e.toString()}"
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
     * @param password Password for encryption (as CharArray for security)
     * @param options Encryption options
     * @return Result indicating success or failure
     */
    fun startEncrypt(
        operationID: String,
        inputFile: String,
        outputFile: String,
        password: CharArray,
        options: EncryptOptions
    ): Result<Unit> {
        return try {
            // Convert CharArray to String only when needed for Go backend
            // This is the only place where password becomes a String
            val passwordString = String(password)
            
            // Build JSON request
            val requestJson = JSONObject().apply {
                put("operationID", operationID)
                put("inputFile", inputFile)
                put("outputFile", outputFile)
                put("password", passwordString)
                put("comments", options.comments)
                put("keyfiles", JSONArray().apply {
                    options.keyfiles.forEach { put(it) }
                })
                put("paranoid", options.paranoid)
                put("reedSolomon", options.reedSolomon)
                put("deniability", options.deniability)
                put("compress", options.compress)
                put("keyfileOrdered", options.keyfileOrdered)
            }.toString()
            
            // Call StartEncrypt with JSON string
            val errorMsg = Mobile.startEncrypt(requestJson)
            
            // Clear password string from memory (best effort - JVM may keep it)
            // Note: String is immutable, so we can't zero it, but we can clear the reference
            // The actual clearing happens when the CharArray is cleared
            
            if (errorMsg.isNotEmpty()) {
                // Convert Go error to AppError (operation type unknown here, use generic)
                val appError = AppError.fromGoError(errorMsg, OperationType.ENCRYPT)
                Result.failure(appError)
            } else {
                Result.success(Unit)
            }
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }
    
    /**
     * Starts a decryption operation in the background.
     * 
     * @param operationID Operation ID from startOperation()
     * @param inputFile Path to input file
     * @param outputFile Path to output file
     * @param password Password for decryption (as CharArray for security)
     * @param options Decryption options
     * @return Result indicating success or failure
     */
    fun startDecrypt(
        operationID: String,
        inputFile: String,
        outputFile: String,
        password: CharArray,
        options: DecryptOptions
    ): Result<Unit> {
        return try {
            // Convert CharArray to String only when needed for Go backend
            // This is the only place where password becomes a String
            val passwordString = String(password)
            
            // Build JSON request
            val requestJson = JSONObject().apply {
                put("operationID", operationID)
                put("inputFile", inputFile)
                put("outputFile", outputFile)
                put("password", passwordString)
                put("keyfiles", JSONArray().apply {
                    options.keyfiles.forEach { put(it) }
                })
                put("forceDecrypt", options.forceDecrypt)
                put("verifyFirst", options.verifyFirst)
                put("autoUnzip", options.autoUnzip)
                put("sameLevel", options.sameLevel)
                put("recombine", options.recombine)
                put("deniability", options.deniability)
            }.toString()
            
            // Call StartDecrypt with JSON string
            val errorMsg = Mobile.startDecrypt(requestJson)
            
            // Clear password string from memory (best effort - JVM may keep it)
            // Note: String is immutable, so we can't zero it, but we can clear the reference
            // The actual clearing happens when the CharArray is cleared
            
            if (errorMsg.isNotEmpty()) {
                // Convert Go error to AppError
                val appError = AppError.fromGoError(errorMsg, OperationType.DECRYPT)
                Result.failure(appError)
            } else {
                Result.success(Unit)
            }
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
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
            
            // If there's an error, include it in the info field (OperationManager expects this)
            val error = result.getError()
            val info = if (error != null && error.isNotEmpty()) {
                error
            } else {
                result.getInfo() ?: ""
            }
            
            // Convert Go ProgressResult to Kotlin ProgressState
            Result.success(ProgressState(
                status = result.getStatus() ?: "Unknown",
                progress = result.getProgress(),
                info = info,
                done = result.getDone()
            ))
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }
    
    /**
     * Cancels a running operation.
     * 
     * @param operationID Operation ID to cancel
     * @return Result indicating success or failure
     */
    fun cancelOperation(operationID: String): Result<Unit> {
        return try {
            Mobile.cancelOperation(operationID)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }
    
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
            val json = JSONObject(jsonString)
            
            Result.success(DecryptionInfo(
                keyfilesRequired = json.getBoolean("keyfilesRequired"),
                keyfileOrdered = json.getBoolean("keyfileOrdered"),
                reedSolomon = json.getBoolean("reedSolomon"),
                deniability = json.getBoolean("deniability"),
                paranoid = json.getBoolean("paranoid"),
                comments = json.getString("comments"),
                readable = json.getBoolean("readable")
            ))
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }
}
