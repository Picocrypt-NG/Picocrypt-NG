package io.github.picocrypt_ng.picocrypt_ng

import android.os.Parcelable
import kotlinx.parcelize.Parcelize


@Parcelize
data class KeyfileInfo(
    val internalPath: String,  // Path in internal storage (e.g., "keyfile_0")
    val displayName: String     // User-chosen name for display
) : Parcelable

enum class Pcv3FormatIntent { NORMAL, D1 }

/**
 * Explicit user-selected PCV3 operation. The two Force variants stay distinct:
 * requesting unverified recovery never itself grants the live role-bound consent.
 */
enum class Pcv3ActionIntent {
    DECRYPT,
    RECOVERY,
    FORCE_AUTHENTICATED_ONLY,
    FORCE_WITH_UNVERIFIED_CONSENT;

    val isRecovery: Boolean
        get() = this != DECRYPT
}

enum class Pcv3FactorPolicyIntent { PASSWORD_ONLY, KEYFILES_ONLY, PASSWORD_AND_KEYFILES }

enum class Pcv3KeyfileOrderIntent { SELECTED, ANY }

/** Operation-local, authority-free intent. Null fields are explicit incomplete state. */
data class Pcv3OperationIntent(
    val format: Pcv3FormatIntent,
    val action: Pcv3ActionIntent? = null,
    val factorPolicy: Pcv3FactorPolicyIntent? = null,
    val keyfileOrder: Pcv3KeyfileOrderIntent? = null,
) {
    internal fun goModeOrNull(): String? = when (format) {
        Pcv3FormatIntent.NORMAL -> when (action) {
            Pcv3ActionIntent.DECRYPT -> "read-normal"
            Pcv3ActionIntent.RECOVERY -> "recover-normal"
            Pcv3ActionIntent.FORCE_AUTHENTICATED_ONLY -> "force-normal"
            Pcv3ActionIntent.FORCE_WITH_UNVERIFIED_CONSENT -> "force-unverified-normal"
            null -> null
        }
        Pcv3FormatIntent.D1 -> when (action) {
            Pcv3ActionIntent.DECRYPT -> "read-d1"
            Pcv3ActionIntent.RECOVERY -> "recover-d1"
            Pcv3ActionIntent.FORCE_AUTHENTICATED_ONLY -> "force-d1"
            Pcv3ActionIntent.FORCE_WITH_UNVERIFIED_CONSENT -> "force-unverified-d1"
            null -> null
        }
    }

    internal fun factorPolicyCodeOrNull(): String? = when (factorPolicy) {
        Pcv3FactorPolicyIntent.PASSWORD_ONLY -> "password"
        Pcv3FactorPolicyIntent.KEYFILES_ONLY -> "keyfiles"
        Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES -> "password-and-keyfiles"
        null -> null
    }

    internal fun keyfileOrderCodeOrNull(): String? = when (factorPolicy) {
        Pcv3FactorPolicyIntent.PASSWORD_ONLY -> if (keyfileOrder == null) "none" else null
        Pcv3FactorPolicyIntent.KEYFILES_ONLY,
        Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES,
        -> when (keyfileOrder) {
            Pcv3KeyfileOrderIntent.SELECTED -> "ordered"
            Pcv3KeyfileOrderIntent.ANY -> "unordered"
            null -> null
        }
        null -> null
    }
}

/**
 * One app-private copied source. Copies of FormData share this owner, so take and
 * release remain exactly-once even if a stale UI snapshot attempts either again.
 */
class Pcv3OwnedSource internal constructor(sourcePath: String) {
    private var sourcePath: String? = sourcePath.also { require(it.isNotBlank()) }

    @Synchronized
    internal fun isAvailable(): Boolean = sourcePath != null

    @Synchronized
    internal fun take(): String? = sourcePath.also { sourcePath = null }

    @Synchronized
    internal fun release(): String? = take()

    override fun toString(): String = "Pcv3OwnedSource([REDACTED])"
}

/** The sole Kotlin-to-operation ownership transfer; [password] is mutable and caller-owned. */
class Pcv3OperationTransfer internal constructor(
    internal val intent: Pcv3OperationIntent,
    internal val request: Pcv3Request,
    internal val password: CharArray,
) {
    override fun toString(): String = "Pcv3OperationTransfer([REDACTED])"
}

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
    val decryptionInfo: DecryptionInfo? = null,
    val pcvUnavailable: Boolean = false,
    val pcv3Intent: Pcv3OperationIntent? = null,
    internal val pcv3OwnedSource: Pcv3OwnedSource? = null,
) {
    // A folder/multi selection always encrypts (Go zips it) and is never a decrypt or a
    // split-volume chunk -- those are single-file concepts keyed off the filename.
    val isDecrypt: Boolean
        get() = !pcvUnavailable && !isPcv3Selection && selectionKind == SelectionKind.SINGLE_FILE &&
            selectedFilename.isNotEmpty() && selectedFilename.endsWith(".pcv")
    val isEncrypt: Boolean
        get() = !pcvUnavailable && !isPcv3Selection && (
            selectionKind != SelectionKind.SINGLE_FILE ||
                (selectedFilename.isNotEmpty() && !selectedFilename.endsWith(".pcv"))
            )
    val isPcv3Selection: Boolean
        get() = pcv3Intent != null
    // clearPasswords overwrites buffers in place, so allocated length does not imply a credential.
    val hasPassword: Boolean
        get() = passwordInput.any { it != '\u0000' }
    private val hasConfirmPassword: Boolean
        get() = confirmPasswordInput.any { it != '\u0000' }
    val hasAnyCredentialInput: Boolean
        get() = hasPassword || hasConfirmPassword || hasKeyfiles
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
        get() = if (pcvUnavailable) {
            false
        } else if (isPcv3Selection) {
            !hasPassword && pcv3Intent?.factorPolicy != Pcv3FactorPolicyIntent.KEYFILES_ONLY
        } else {
            !hasPassword && (isEncrypt || !hasKeyfiles)
        }
    val isPasswordValid: Boolean
        get() = when {
            pcvUnavailable -> false
            isPcv3Selection -> isPcv3CredentialIntentValid
            isEncrypt -> hasPassword && !hasKeyfiles && isPasswordsMatch
            isDecrypt -> hasPassword || hasKeyfiles
            else -> false
        }

    private val isPcv3CredentialIntentValid: Boolean
        get() = when (pcv3Intent?.factorPolicy) {
            Pcv3FactorPolicyIntent.PASSWORD_ONLY ->
                hasPassword && !hasKeyfiles && pcv3Intent.keyfileOrder == null
            Pcv3FactorPolicyIntent.KEYFILES_ONLY ->
                !hasPassword && hasKeyfiles && pcv3Intent.keyfileOrder != null
            Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES ->
                hasPassword && hasKeyfiles && pcv3Intent.keyfileOrder != null
            null -> false
        }

    /**
     * True when a concrete input is selected: a single copied file, or a staged
     * folder/multi-file selection. WorkButton gates the Encrypt button on this so
     * folder/multi selections (which have an empty copiedFilePath) are not blocked.
     */
    val hasSelectedInput: Boolean
        get() = pcv3OwnedSource?.isAvailable() == true || copiedFilePath.isNotEmpty() || inputFiles.isNotEmpty()

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
        if (pcvUnavailable != other.pcvUnavailable) return false
        if (pcv3Intent != other.pcv3Intent) return false
        if (pcv3OwnedSource !== other.pcv3OwnedSource) return false

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
        result = 31 * result + pcvUnavailable.hashCode()
        result = 31 * result + (pcv3Intent?.hashCode() ?: 0)
        result = 31 * result + (pcv3OwnedSource?.hashCode() ?: 0)
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
        get() = if (isPcv3Selection) {
            !pcvUnavailable && pcv3OwnedSource?.isAvailable() == true &&
                pcv3Intent?.goModeOrNull() != null &&
                pcv3Intent.factorPolicyCodeOrNull() != null &&
                pcv3Intent.keyfileOrderCodeOrNull() != null &&
                isPcv3CredentialIntentValid
        } else {
            selectedFilename.isNotEmpty() && isPasswordValid &&
                !areKeyfilesRequiredButMissing && !isSplitVolumeChunk
        }

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
