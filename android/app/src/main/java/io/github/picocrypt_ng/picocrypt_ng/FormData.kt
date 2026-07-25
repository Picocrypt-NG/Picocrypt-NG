package io.github.picocrypt_ng.picocrypt_ng

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
    val verifyFirst: Boolean = false,
    val keyfileFilenames: List<KeyfileInfo>, // Keyfile info with internal path and display name
    val keyfileOrdered: Boolean,
    val compress: Boolean = false,
    // Folder/multi-file selection (StagingService output). For SINGLE_FILE these stay
    // empty and copiedFilePath carries the one input; for FOLDER/MULTI_FILE the staged
    // tree is forwarded to Go as these arrays and copiedFilePath is empty.
    val inputFiles: List<String> = emptyList(),
    val onlyFolders: List<String> = emptyList(),
    val onlyFiles: List<String> = emptyList(),
    val selectionKind: SelectionKind = SelectionKind.SINGLE_FILE,
    val suggestedOutputName: String = "",
    val decryptionInfo: DecryptionInfo? = null
) {
    // A folder/multi selection always encrypts (Go zips it) and is never a decrypt or a
    // split-volume chunk -- those are single-file concepts keyed off the filename.
    val isDecrypt: Boolean
        get() = selectionKind == SelectionKind.SINGLE_FILE &&
            selectedFilename.isNotEmpty() && selectedFilename.endsWith(".pcv")
    val isEncrypt: Boolean
        get() = selectionKind != SelectionKind.SINGLE_FILE ||
            (selectedFilename.isNotEmpty() && !selectedFilename.endsWith(".pcv"))
    // clearPasswords overwrites buffers in place, so allocated length does not imply a credential.
    val hasPassword: Boolean
        get() = passwordInput.any { it != '\u0000' }
    private val hasConfirmPassword: Boolean
        get() = confirmPasswordInput.any { it != '\u0000' }
    val isPasswordsMatch: Boolean
        get() = (!hasPassword && !hasConfirmPassword) ||
            passwordInput.contentEquals(confirmPasswordInput)
    val hasKeyfiles: Boolean
        get() = keyfileFilenames.isNotEmpty()
    val isKeyfileEncryptionUnsupported: Boolean
        get() = isEncrypt && hasKeyfiles
    val isDeniabilityPasswordMissing: Boolean
        get() = isEncrypt && deniability && !hasPassword
    val isPasswordInputRequired: Boolean
        get() = !hasPassword && (isEncrypt || !hasKeyfiles)
    val isPasswordValid: Boolean
        get() = when {
            isEncrypt -> hasPassword && !hasKeyfiles && isPasswordsMatch
            isDecrypt -> hasPassword || hasKeyfiles
            else -> false
        }

    /**
     * True when a concrete input is selected: a single copied file, or a staged
     * folder/multi-file selection. WorkButton gates the Encrypt button on this so
     * folder/multi selections (which have an empty copiedFilePath) are not blocked.
     */
    val hasSelectedInput: Boolean
        get() = copiedFilePath.isNotEmpty() || inputFiles.isNotEmpty()

    /**
     * True when the selected file is a numbered split-volume chunk (e.g. secret.pcv.0).
     * Mirrors Go fileops.IsSplitChunkPath. Android cannot recombine chunks (single-file
     * picker, no sibling access), so such files are rejected loudly rather than run --
     * a chunk does not end in .pcv, so without this it would be treated as an encrypt
     * target and double-encrypted.
     */
    val isSplitVolumeChunk: Boolean
        get() = selectionKind == SelectionKind.SINGLE_FILE && isSplitVolumeChunkName(selectedFilename)
    
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
        if (verifyFirst != other.verifyFirst) return false
        if (keyfileFilenames != other.keyfileFilenames) return false
        if (keyfileOrdered != other.keyfileOrdered) return false
        if (compress != other.compress) return false
        if (inputFiles != other.inputFiles) return false
        if (onlyFolders != other.onlyFolders) return false
        if (onlyFiles != other.onlyFiles) return false
        if (selectionKind != other.selectionKind) return false
        if (suggestedOutputName != other.suggestedOutputName) return false
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
        result = 31 * result + verifyFirst.hashCode()
        result = 31 * result + keyfileFilenames.hashCode()
        result = 31 * result + keyfileOrdered.hashCode()
        result = 31 * result + compress.hashCode()
        result = 31 * result + inputFiles.hashCode()
        result = 31 * result + onlyFolders.hashCode()
        result = 31 * result + onlyFiles.hashCode()
        result = 31 * result + selectionKind.hashCode()
        result = 31 * result + suggestedOutputName.hashCode()
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
        get() = selectedFilename.isNotEmpty() && isPasswordValid &&
            !areKeyfilesRequiredButMissing && !isSplitVolumeChunk

    fun suggestedOutputNameFor(type: OperationType): String {
        suggestedOutputName.takeIf { it.isNotEmpty() }?.let { return it }
        if (selectedFilename.isEmpty()) return ""

        return when (type) {
            OperationType.ENCRYPT -> encryptedOutputName(selectedFilename, compress)
            OperationType.DECRYPT -> decryptedOutputName(selectedFilename)
        }
    }

    companion object {
        // Mirrors Go fileops.splitChunkRE: (?i)\.pcv\.[0-9]+$ matched on the base name.
        private val SPLIT_CHUNK_REGEX = Regex("""(?i)\.pcv\.[0-9]+$""")

        /**
         * Reports whether [filename] names a numbered split-volume chunk (e.g.
         * secret.pcv.0). Kept in sync with Go fileops.IsSplitChunkPath so detection is
         * identical on both sides of the bridge.
         */
        fun isSplitVolumeChunkName(filename: String): Boolean =
            SPLIT_CHUNK_REGEX.containsMatchIn(filename.substringAfterLast('/'))

        private fun encryptedOutputName(filename: String, compress: Boolean): String {
            if (filename.endsWith(".pcv")) return filename
            return if (compress) "$filename.zip.pcv" else "$filename.pcv"
        }

        private fun decryptedOutputName(filename: String): String =
            if (filename.endsWith(".pcv")) {
                filename.removeSuffix(".pcv")
            } else {
                filename
            }
    }
}
