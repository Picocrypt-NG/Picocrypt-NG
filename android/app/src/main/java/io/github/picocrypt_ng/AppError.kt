package io.github.picocrypt_ng

/**
 * Sealed hierarchy for all application errors.
 * Provides type-safe error handling with user-friendly messages.
 * Extends Exception to be compatible with Result.failure().
 */
sealed class AppError(
    /**
     * User-friendly error message to display in UI.
     */
    val userMessage: String,
    /**
     * Optional technical message for logging/debugging.
     */
    val technicalMessage: String? = null
) : Exception(userMessage) {
    
    /**
     * Checks if this is a data corruption error (for force decrypt option).
     */
    fun isDataCorruption(): Boolean = this is OperationError.DataCorruption
    
    /**
     * Checks if this is a password or authentication error (for retry option).
     */
    fun isPasswordError(): Boolean = this is OperationError.PasswordAuth
    
    /**
     * Checks if this error allows retry with force decrypt.
     */
    fun allowsForceDecrypt(): Boolean = isDataCorruption()
    
    /**
     * Checks if this error allows retry with new password.
     */
    fun allowsPasswordRetry(): Boolean = isPasswordError()
    
    /**
     * Operation-related errors from encryption/decryption operations.
     */
    sealed class OperationError(
        userMessage: String,
        technicalMessage: String? = null
    ) : AppError(userMessage, technicalMessage) {
        /**
         * Data corruption detected during decryption.
         * Allows force decrypt option.
         */
        class DataCorruption(
            userMessage: String,
            technicalMessage: String? = null
        ) : OperationError(userMessage, technicalMessage)
        
        /**
         * Password or keyfile authentication failed.
         * Allows retry with new password.
         */
        class PasswordAuth(
            userMessage: String,
            technicalMessage: String? = null
        ) : OperationError(userMessage, technicalMessage)
        
        /**
         * File not found or inaccessible.
         */
        class FileNotFound(
            userMessage: String = "File not found or inaccessible",
            technicalMessage: String? = null
        ) : OperationError(userMessage, technicalMessage)
        
        /**
         * Generic operation error.
         */
        class GenericOperation(
            userMessage: String,
            technicalMessage: String? = null
        ) : OperationError(userMessage, technicalMessage)
    }
    
    /**
     * File operation errors (copy, save, delete).
     */
    sealed class FileError(
        userMessage: String,
        technicalMessage: String? = null
    ) : AppError(userMessage, technicalMessage) {
        /**
         * Failed to copy file to internal storage.
         */
        class CopyFailed(
            userMessage: String = "Failed to copy file",
            technicalMessage: String? = null
        ) : FileError(userMessage, technicalMessage)
        
        /**
         * Failed to delete file.
         */
        class DeleteFailed(
            userMessage: String = "Failed to delete file",
            technicalMessage: String? = null
        ) : FileError(userMessage, technicalMessage)
        
        /**
         * Failed to save file to user-selected location.
         */
        class SaveFailed(
            userMessage: String = "Failed to save file",
            technicalMessage: String? = null
        ) : FileError(userMessage, technicalMessage)
    }
    
    /**
     * Form validation errors.
     */
    sealed class ValidationError(
        userMessage: String
    ) : AppError(userMessage) {
        /**
         * No file selected.
         */
        object NoFileSelected : ValidationError("Please select a file")
        
        /**
         * Invalid password (empty or doesn't meet requirements).
         */
        object InvalidPassword : ValidationError("Please enter a password")
        
        /**
         * Passwords don't match (for encryption).
         */
        object PasswordsMismatch : ValidationError("Passwords do not match")
    }
    
    companion object {
        /**
         * Converts a Go error string to an AppError.
         * Analyzes the error message to determine the appropriate error type.
         */
        fun fromGoError(errorString: String, operationType: OperationType): AppError {
            val errorLower = errorString.lowercase()
            
            // Check for data corruption (only for decryption)
            if (operationType == OperationType.DECRYPT) {
                val hasDataCorruption = errorLower.contains("data corrupted") || 
                                       errorLower.contains("data corruption")
                val hasHeaderError = errorLower.contains("header")
                val hasAuthError = errorLower.contains("password") || 
                                  errorLower.contains("incorrect") ||
                                  errorLower.contains("keyfile") ||
                                  errorLower.contains("authentication failed")
                
                if (hasDataCorruption && !hasHeaderError && !hasAuthError) {
                    return OperationError.DataCorruption(
                        userMessage = errorString,
                        technicalMessage = errorString
                    )
                }
            }
            
            // Check for password/auth errors
            val isPasswordError = (errorLower.contains("password") && 
                                  (errorLower.contains("incorrect") || 
                                   errorLower.contains("authentication failed"))) ||
                                 (errorLower.contains("keyfile") && errorLower.contains("incorrect")) ||
                                 errorLower.contains("authentication failed")
            
            if (isPasswordError) {
                return OperationError.PasswordAuth(
                    userMessage = errorString,
                    technicalMessage = errorString
                )
            }
            
            // Check for file not found
            if (errorLower.contains("file not found") || 
                errorLower.contains("no such file") ||
                errorLower.contains("cannot find")) {
                return OperationError.FileNotFound(
                    userMessage = "File not found or inaccessible",
                    technicalMessage = errorString
                )
            }
            
            // Generic operation error
            return OperationError.GenericOperation(
                userMessage = errorString,
                technicalMessage = errorString
            )
        }
        
        /**
         * Converts an Exception to an AppError.
         */
        fun fromException(exception: Exception): AppError {
            val message = exception.message ?: "Unknown error occurred"
            val errorLower = message.lowercase()
            
            if (errorLower.contains("file not found") || 
                errorLower.contains("no such file")) {
                return OperationError.FileNotFound(
                    technicalMessage = message
                )
            }
            
            return OperationError.GenericOperation(
                userMessage = message,
                technicalMessage = message
            )
        }
    }
}

