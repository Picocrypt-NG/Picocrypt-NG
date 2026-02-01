package io.github.picocrypt_ng

import android.os.Parcelable
import kotlinx.parcelize.Parcelize


@Parcelize
data class KeyfileInfo(
    val internalPath: String,  // Path in internal storage (e.g., "keyfile_0")
    val displayName: String     // User-chosen name for display
) : Parcelable

/**
 * Form data for encryption/decryption operations.
 * 
 * Note: This class is NOT Parcelable because passwords are stored as CharArray
 * for security reasons and should never be serialized.
 */
data class FormData(
    val selectedFilename: String,
    val copiedFilePath: String = "", // Path to file copied to internal storage
    val comments: String,
    val passwordInput: CharArray,  // Use CharArray for secure memory handling
    val confirmPasswordInput: CharArray,  // Use CharArray for secure memory handling
    val reedSolomon: Boolean,
    val paranoid: Boolean,
    val deniability: Boolean,
    val keyfileFilenames: List<KeyfileInfo>, // Keyfile info with internal path and display name
    val keyfileOrdered: Boolean,
    val decryptionInfo: DecryptionInfo? = null
) {
    val isDecrypt: Boolean
        get() = selectedFilename.isNotEmpty() && selectedFilename.endsWith(".pcv")
    val isEncrypt: Boolean
        get() = selectedFilename.isNotEmpty() && !selectedFilename.endsWith(".pcv")
    val isPasswordsMatch: Boolean
        get() = passwordInput.contentEquals(confirmPasswordInput)
    val isPasswordValid: Boolean
        get() = passwordInput.isNotEmpty() && ((isEncrypt && isPasswordsMatch) || isDecrypt)
    
    /**
     * Clears password fields by zeroing the character arrays.
     * This helps prevent passwords from remaining in memory.
     */
    fun clearPasswords() {
        passwordInput.fill('\u0000')
        confirmPasswordInput.fill('\u0000')
    }
    
    /**
     * Creates a copy with cleared passwords.
     */
    fun copyWithClearedPasswords(): FormData {
        val cleared = this.copy(
            passwordInput = CharArray(0),
            confirmPasswordInput = CharArray(0)
        )
        // Clear original arrays
        clearPasswords()
        return cleared
    }
    
    /**
     * Converts password to String for operations that require it.
     * WARNING: This creates a String copy that may remain in memory.
     * Use only when necessary (e.g., passing to Go backend).
     */
    fun passwordAsString(): String {
        return String(passwordInput)
    }
    
    /**
     * Converts confirm password to String for operations that require it.
     * WARNING: This creates a String copy that may remain in memory.
     * Use only when necessary.
     */
    fun confirmPasswordAsString(): String {
        return String(confirmPasswordInput)
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as FormData
        
        if (selectedFilename != other.selectedFilename) return false
        if (copiedFilePath != other.copiedFilePath) return false
        if (comments != other.comments) return false
        if (!passwordInput.contentEquals(other.passwordInput)) return false
        if (!confirmPasswordInput.contentEquals(other.confirmPasswordInput)) return false
        if (reedSolomon != other.reedSolomon) return false
        if (paranoid != other.paranoid) return false
        if (deniability != other.deniability) return false
        if (keyfileFilenames != other.keyfileFilenames) return false
        if (keyfileOrdered != other.keyfileOrdered) return false
        if (decryptionInfo != other.decryptionInfo) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = selectedFilename.hashCode()
        result = 31 * result + copiedFilePath.hashCode()
        result = 31 * result + comments.hashCode()
        result = 31 * result + passwordInput.contentHashCode()
        result = 31 * result + confirmPasswordInput.contentHashCode()
        result = 31 * result + reedSolomon.hashCode()
        result = 31 * result + paranoid.hashCode()
        result = 31 * result + deniability.hashCode()
        result = 31 * result + keyfileFilenames.hashCode()
        result = 31 * result + keyfileOrdered.hashCode()
        result = 31 * result + (decryptionInfo?.hashCode() ?: 0)
        return result
    }
    
    /**
     * Checks if keyfiles are required for decryption but not provided.
     * Returns true if keyfiles are required but missing.
     */
    val areKeyfilesRequiredButMissing: Boolean
        get() {
            if (!isDecrypt || decryptionInfo == null) return false
            // Only check if metadata is readable (not deniability mode)
            if (!decryptionInfo.readable) return false
            return decryptionInfo.keyfilesRequired && keyfileFilenames.isEmpty()
        }
    
    val isFormValid: Boolean
        get() = selectedFilename.isNotEmpty() && isPasswordValid && !areKeyfilesRequiredButMissing
}