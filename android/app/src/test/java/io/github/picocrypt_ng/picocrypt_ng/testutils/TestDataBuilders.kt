package io.github.picocrypt_ng.picocrypt_ng.testutils

import io.github.picocrypt_ng.picocrypt_ng.DecryptionInfo
import io.github.picocrypt_ng.picocrypt_ng.FormData
import io.github.picocrypt_ng.picocrypt_ng.KeyfileInfo
import io.github.picocrypt_ng.picocrypt_ng.OperationProgressDetail
import io.github.picocrypt_ng.picocrypt_ng.OperationState
import io.github.picocrypt_ng.picocrypt_ng.OperationStatus
import io.github.picocrypt_ng.picocrypt_ng.OperationStatusData
import io.github.picocrypt_ng.picocrypt_ng.OperationType
import io.github.picocrypt_ng.picocrypt_ng.SelectionKind

/**
 * Test data builders for creating test objects.
 */
object TestDataBuilders {
    
    /**
     * Creates a FormData for encryption with default values.
     */
    fun createEncryptFormData(
        selectedFilename: String = "test.txt",
        copiedFilePath: String = "/data/test/input_file.txt",
        comments: String = "",
        password: String = "testpassword",
        confirmPassword: String = "testpassword",
        reedSolomon: Boolean = false,
        paranoid: Boolean = false,
        deniability: Boolean = false,
        compress: Boolean = false,
        keyfiles: List<KeyfileInfo> = emptyList(),
        keyfileOrdered: Boolean = false
    ): FormData {
        return FormData(
            selectedFilename = selectedFilename,
            copiedFilePath = copiedFilePath,
            comments = comments,
            passwordInput = password.toCharArray(),
            confirmPasswordInput = confirmPassword.toCharArray(),
            reedSolomon = reedSolomon,
            paranoid = paranoid,
            deniability = deniability,
            compress = compress,
            keyfileFilenames = keyfiles,
            keyfileOrdered = keyfileOrdered,
            decryptionInfo = null
        )
    }
    
    /**
     * Creates a FormData for a FOLDER selection (folder/multi-file encrypt path).
     * The staged input lives in [inputFiles]/[onlyFolders]; [copiedFilePath] is empty
     * because a multi selection sends arrays, not a single inputFile.
     */
    fun createFolderEncryptFormData(
        displayName: String = "MyDocs",
        inputFiles: List<String> = listOf("/stage/MyDocs/a.txt", "/stage/MyDocs/sub/b.txt"),
        onlyFolders: List<String> = listOf("/stage/MyDocs"),
        password: String = "testpassword",
    ): FormData = FormData(
        selectedFilename = displayName,
        copiedFilePath = "",
        comments = "",
        passwordInput = password.toCharArray(),
        confirmPasswordInput = password.toCharArray(),
        reedSolomon = false,
        paranoid = false,
        deniability = false,
        keyfileFilenames = emptyList(),
        keyfileOrdered = false,
        inputFiles = inputFiles,
        onlyFolders = onlyFolders,
        selectionKind = SelectionKind.FOLDER,
        suggestedOutputName = "$displayName.zip.pcv",
        decryptionInfo = null,
    )

    /**
     * Creates a FormData for decryption with default values.
     */
    fun createDecryptFormData(
        selectedFilename: String = "test.pcv",
        copiedFilePath: String = "/data/test/input_file.pcv",
        password: String = "testpassword",
        keyfiles: List<KeyfileInfo> = emptyList(),
        decryptionInfo: DecryptionInfo? = null
    ): FormData {
        return FormData(
            selectedFilename = selectedFilename,
            copiedFilePath = copiedFilePath,
            comments = "",
            passwordInput = password.toCharArray(),
            confirmPasswordInput = password.toCharArray(),
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = keyfiles,
            keyfileOrdered = false,
            decryptionInfo = decryptionInfo
        )
    }
    
    /**
     * Creates a DecryptionInfo with default values.
     */
    fun createDecryptionInfo(
        keyfilesRequired: Boolean = false,
        keyfileOrdered: Boolean = false,
        reedSolomon: Boolean = false,
        deniability: Boolean = false,
        paranoid: Boolean = false,
        comments: String = "",
        readable: Boolean = true
    ): DecryptionInfo {
        return DecryptionInfo(
            keyfilesRequired = keyfilesRequired,
            keyfileOrdered = keyfileOrdered,
            reedSolomon = reedSolomon,
            deniability = deniability,
            paranoid = paranoid,
            comments = comments,
            readable = readable
        )
    }
    
    /**
     * Creates a KeyfileInfo with default values.
     */
    fun createKeyfileInfo(
        internalPath: String = "keyfile_0",
        displayName: String = "keyfile.txt"
    ): KeyfileInfo {
        return KeyfileInfo(
            internalPath = internalPath,
            displayName = displayName
        )
    }
    
    /**
     * Creates an OperationState with default values.
     */
    fun createOperationState(
        id: String = "op_123",
        type: OperationType = OperationType.ENCRYPT,
        inputFile: String = "/data/test/input_file.txt",
        outputFile: String = "/data/test/output_file.pcv",
        status: OperationStatusData = OperationStatusData(OperationStatus.UNKNOWN),
        detail: OperationProgressDetail = OperationProgressDetail("NONE"),
        progress: Float = 0.5f,
        done: Boolean = false,
        error: io.github.picocrypt_ng.picocrypt_ng.AppError? = null,
        formData: FormData? = null
    ): OperationState {
        return OperationState(
            id = id,
            type = type,
            inputFile = inputFile,
            outputFile = outputFile,
            status = status,
            detail = detail,
            progress = progress,
            done = done,
            error = error,
            formData = formData
        )
    }
    
    /**
     * Generates a test password as CharArray.
     */
    fun generateTestPassword(length: Int = 12): CharArray {
        return "testpass$length".toCharArray()
    }
    
    /**
     * Clears a password CharArray (for cleanup in tests).
     */
    fun clearPassword(password: CharArray) {
        password.fill('\u0000')
    }
}
