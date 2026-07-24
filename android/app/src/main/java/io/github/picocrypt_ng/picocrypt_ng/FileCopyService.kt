package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream

object FileCopyService {
    private const val INTERNAL_FILES_DIR = "picocrypt_files"
    private val keyfileCopyMutex = Mutex()

    /**
     * Copies a file from a URI to the internal app data directory.
     * Uses fixed filename "input_file" (preserves extension if provided).
     * @return Result with file path on success, AppError on failure
     */
    suspend fun copyFileToInternalStorage(
        context: Context,
        uri: Uri,
        originalFileName: String
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            // Get internal files directory
            val internalDir = File(context.filesDir, INTERNAL_FILES_DIR)
            if (!internalDir.exists()) {
                internalDir.mkdirs()
            }

            // Use fixed filename "input_file" (preserve extension if present)
            val ext = if (originalFileName.contains(".")) {
                originalFileName.substringAfterLast(".", "")
            } else {
                ""
            }
            val fixedFileName = if (ext.isNotEmpty()) {
                "input_file.$ext"
            } else {
                "input_file"
            }
            val destFile = File(internalDir, fixedFileName)

            // Open input stream from URI
            val inputStream: InputStream = context.contentResolver.openInputStream(uri)
                ?: return@withContext Result.failure(
                    copyFailed(context, "Could not open input stream for URI: $uri")
                )

            // Copy file (overwrite if exists)
            inputStream.use { input ->
                FileOutputStream(destFile).use { output ->
                    input.copyTo(output)
                }
            }

            Result.success(destFile.absolutePath)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(
                copyFailed(context, e.message)
            )
        }
    }
    
    /**
     * Copies a keyfile from a URI to the internal app data directory.
     * Uses fixed filename "keyfile_<index>" where index is the current keyfile count.
     * A complete copy is published atomically and an existing slot is never overwritten.
     * @return Result with file path on success, AppError on failure
     */
    suspend fun copyKeyfileToInternalStorage(
        context: Context,
        uri: Uri,
        index: Int
    ): Result<String> = copyKeyfileToInternalStorage(
        context = context,
        uri = uri,
        index = index,
        afterAcquire = {},
        afterPublish = {},
    )

    internal suspend fun copyKeyfileToInternalStorage(
        context: Context,
        uri: Uri,
        index: Int,
        afterAcquire: suspend () -> Unit,
        afterPublish: suspend () -> Unit,
    ): Result<String> {
        keyfileCopyMutex.lock()
        return try {
            afterAcquire()
            val internalDir = File(context.filesDir, INTERNAL_FILES_DIR)
            val destFile = File(internalDir, "keyfile_$index")
            var incompleteFile: File? = null
            var published = false
            var resultDelivered = false

            try {
                val result = withContext(Dispatchers.IO) {
                    val copyResult = try {
                        if ((!internalDir.exists() && !internalDir.mkdirs()) || !internalDir.isDirectory) {
                            throw IOException("Could not create internal keyfile directory")
                        }
                        if (destFile.exists()) {
                            throw IOException("Keyfile target already exists")
                        }

                        val ownedIncompleteFile = File.createTempFile(
                            "keyfile_${index}_",
                            ".incomplete",
                            internalDir,
                        )
                        incompleteFile = ownedIncompleteFile
                        val inputStream: InputStream = context.contentResolver.openInputStream(uri)
                            ?: throw IOException("Could not open input stream for URI: $uri")

                        inputStream.use { input ->
                            FileOutputStream(ownedIncompleteFile).use { output ->
                                input.copyTo(output)
                            }
                        }
                        currentCoroutineContext().ensureActive()
                        if (destFile.exists()) {
                            throw IOException("Keyfile target was claimed during copy")
                        }

                        // Both paths share a directory, so the complete file becomes visible in one rename.
                        if (!ownedIncompleteFile.renameTo(destFile)) {
                            throw IOException("Could not publish copied keyfile")
                        }
                        published = true
                        Result.success(destFile.absolutePath)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Result.failure(copyFailed(context, e.message))
                    } finally {
                        if (!published) {
                            incompleteFile?.delete()
                        }
                    }

                    if (copyResult.isSuccess) {
                        afterPublish()
                    }
                    copyResult
                }
                resultDelivered = true
                result
            } finally {
                if (!resultDelivered) {
                    // Cancellation can arrive after rename while the IO result is dispatched
                    // back to the caller. Clean up before releasing ownership of this slot.
                    withContext(NonCancellable + Dispatchers.IO) {
                        incompleteFile?.delete()
                        if (published) {
                            destFile.delete()
                        }
                    }
                }
            }
        } finally {
            keyfileCopyMutex.unlock()
        }
    }

    /**
     * Deletes a file from internal storage.
     */
    suspend fun deleteFile(context: Context, filePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val file = File(filePath)
            if (file.exists()) {
                file.delete()
                true
            } else {
                false
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Cleans up all files copied into the internal runtime directory.
     *
     * This is used for process-start stale-file cleanup. Do not use it as the
     * pre-operation cleanup path: staged folder/multi-file inputs live under
     * staging/ and must survive until the Go operation has consumed them.
     */
    suspend fun cleanupAllFiles(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val filesDir = context.filesDir
            val entries = filesDir.list() ?: return@withContext false
            if (INTERNAL_FILES_DIR !in entries) {
                return@withContext true
            }

            val internalDir = File(filesDir, INTERNAL_FILES_DIR)
            val expectedInternalDir = File(filesDir.canonicalFile, INTERNAL_FILES_DIR)
            if (internalDir.canonicalFile != expectedInternalDir ||
                !internalDir.exists() ||
                !internalDir.isDirectory
            ) {
                return@withContext false
            }

            val files = internalDir.listFiles() ?: return@withContext false

            var allDeleted = true
            files.forEach { file ->
                if (!NoFollowFileTree.delete(filesDir, file)) {
                    allDeleted = false
                }
            }

            allDeleted
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Gets the internal storage directory path.
     */
    fun getInternalStoragePath(context: Context): String {
        return File(context.filesDir, INTERNAL_FILES_DIR).absolutePath
    }

    /**
     * Cleans up files from a specific operation (input, output, and keyfiles).
     * Returns true if all deletions succeeded or files didn't exist.
     */
    suspend fun cleanupOperationFiles(
        context: Context,
        inputFilePath: String?,
        outputFilePath: String?,
        keyfilePaths: List<String>
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            var allSuccess = true
            
            // Delete input file if provided
            inputFilePath?.let { path ->
                if (path.isNotEmpty()) {
                    val file = File(path)
                    if (file.exists()) {
                        if (!file.delete()) {
                            allSuccess = false
                        }
                    }
                }
            }
            
            // Delete output file if provided
            outputFilePath?.let { path ->
                if (path.isNotEmpty()) {
                    val file = File(path)
                    if (file.exists()) {
                        if (!file.delete()) {
                            allSuccess = false
                        }
                    }
                }
            }
            
            // Delete all keyfiles
            keyfilePaths.forEach { path ->
                if (path.isNotEmpty()) {
                    val file = File(path)
                    if (file.exists()) {
                        if (!file.delete()) {
                            allSuccess = false
                        }
                    }
                }
            }
            
            allSuccess
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Saves a file from internal storage to a user-selected URI.
     * @param context Android context
     * @param sourceFilePath Path to source file in internal storage
     * @param destinationUri Destination URI selected by user
     * @return Result with Unit on success, AppError on failure
     */
    suspend fun saveFileToUri(
        context: Context,
        sourceFilePath: String,
        destinationUri: Uri
    ): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val sourceFile = File(sourceFilePath)
            if (!sourceFile.exists()) {
                return@withContext Result.failure(
                    saveFailed(context, "File does not exist: $sourceFilePath")
                )
            }
            
            context.contentResolver.openOutputStream(destinationUri)?.use { outputStream ->
                FileInputStream(sourceFile).use { inputStream ->
                    inputStream.copyTo(outputStream)
                }
            } ?: return@withContext Result.failure(
                saveFailed(context, "Could not open output stream for URI: $destinationUri")
            )
            
            Result.success(Unit)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(
                saveFailed(context, e.message)
            )
        }
    }
    
    /**
     * Generates the output file path based on operation type.
     * Uses fixed filename "output_file.pcv" for encryption, "output_file" for decryption.
     * @param context Android context
     * @param inputFilePath Path to input file (used to get parent directory)
     * @param isEncrypt True for encryption, false for decryption
     * @return Absolute path to output file
     */
    fun getOutputFilePath(
        context: Context,
        inputFilePath: String,
        isEncrypt: Boolean
    ): String {
        val inputFile = File(inputFilePath)
        val internalDir = File(context.filesDir, INTERNAL_FILES_DIR)
        
        return if (isEncrypt) {
            // For encryption: use fixed name "output_file.pcv"
            File(internalDir, "output_file.pcv").absolutePath
        } else {
            // For decryption: use fixed name "output_file"
            File(internalDir, "output_file").absolutePath
        }
    }
    
    /**
     * Validates that a file exists at the given path.
     * @param filePath Path to file to validate
     * @return True if file exists, false otherwise
     */
    fun validateFileExists(filePath: String): Boolean {
        return try {
            val file = File(filePath)
            file.exists() && file.isFile
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Cleans up all .incomplete files from previous failed operations.
     * Removes files matching pattern: output_file.pcv.incomplete, output_file.incomplete
     */
    suspend fun cleanupIncompleteFiles(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val filesDir = context.filesDir
            val entries = filesDir.list() ?: return@withContext false
            if (INTERNAL_FILES_DIR !in entries) {
                return@withContext true
            }

            val internalDir = File(filesDir, INTERNAL_FILES_DIR)
            val expectedInternalDir = File(filesDir.canonicalFile, INTERNAL_FILES_DIR)
            if (internalDir.canonicalFile != expectedInternalDir ||
                !internalDir.exists() ||
                !internalDir.isDirectory
            ) {
                return@withContext false
            }

            val files = internalDir.listFiles() ?: return@withContext false
            var allSuccess = true
            files.forEach { file ->
                if (file.name.endsWith(".incomplete")) {
                    if (!isRegularFileInDirectory(internalDir, file) ||
                        !file.delete() ||
                        file.exists()
                    ) {
                        allSuccess = false
                    }
                }
            }
            
            allSuccess
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Cleans up all keyfile files (keyfile_0, keyfile_1, etc.) from internal storage.
     */
    suspend fun cleanupKeyfiles(context: Context): Boolean {
        keyfileCopyMutex.lock()
        return try {
            withContext(Dispatchers.IO) {
                try {
                    val filesDir = context.filesDir
                    // File.exists() follows live links and treats dangling links as absent.
                    // Inspect the parent entry first, then require the root to resolve in place.
                    val entries = filesDir.list() ?: return@withContext false
                    if (INTERNAL_FILES_DIR !in entries) {
                        return@withContext true
                    }

                    val internalDir = File(filesDir, INTERNAL_FILES_DIR)
                    val expectedInternalDir = File(filesDir.canonicalFile, INTERNAL_FILES_DIR)
                    if (internalDir.canonicalFile != expectedInternalDir ||
                        !internalDir.exists() ||
                        !internalDir.isDirectory
                    ) {
                        return@withContext false
                    }

                    val files = internalDir.listFiles() ?: return@withContext false

                    var allSuccess = true
                    files.forEach { file ->
                        if (file.name.startsWith("keyfile_")) {
                            if (!file.isFile || !file.delete() || file.exists()) {
                                allSuccess = false
                            }
                        }
                    }

                    allSuccess
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    false
                }
            }
        } finally {
            keyfileCopyMutex.unlock()
        }
    }
    
    /**
     * Cleans up operation files (input, output, and incomplete variants).
     * Used before starting a new operation to prevent contamination.
     */
    suspend fun cleanupOperationFilesBeforeStart(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val filesDir = context.filesDir
            val entries = filesDir.list() ?: return@withContext false
            if (INTERNAL_FILES_DIR !in entries) {
                return@withContext true
            }

            val internalDir = File(filesDir, INTERNAL_FILES_DIR)
            val expectedInternalDir = File(filesDir.canonicalFile, INTERNAL_FILES_DIR)
            if (internalDir.canonicalFile != expectedInternalDir ||
                !internalDir.exists() ||
                !internalDir.isDirectory
            ) {
                return@withContext false
            }

            val files = internalDir.listFiles() ?: return@withContext false
            var allSuccess = true
            
            // NOTE: Do NOT delete input file here - it's needed for the operation!
            // Input file cleanup happens after operation completes via cleanupOperationFiles()
            
            // Clean up output files (output_file.pcv, output_file, and .incomplete variants)
            // NOTE: Do NOT delete input file or keyfiles here - they're needed for the operation!
            // Input file and keyfiles cleanup happens after operation completes via cleanupOperationFiles()
            val outputFiles = listOf(
                "output_file.pcv",
                "output_file.pcv.incomplete",
                "output_file",
                "output_file.incomplete"
            )
            files.forEach { file ->
                if (file.name in outputFiles) {
                    if (!isRegularFileInDirectory(internalDir, file) ||
                        !file.delete() ||
                        file.exists()
                    ) {
                        allSuccess = false
                    }
                }
            }

            // Go publishes through random sibling stages. A process crash can leave
            // one behind, including plaintext from decryption. Only remove direct
            // regular files with Go's exact private stage prefix; never follow links
            // or recursively delete a matching directory.
            files.forEach { file ->
                if (file.name.startsWith(".picocrypt-") &&
                    isRegularFileInDirectory(internalDir, file) &&
                    (!file.delete() || file.exists())
                ) {
                    allSuccess = false
                }
            }

            // Clean up any remaining incomplete files (but not input/keyfiles)
            if (!cleanupIncompleteFiles(context)) {
                allSuccess = false
            }

            allSuccess
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
    }

    private fun isRegularFileInDirectory(directory: File, file: File): Boolean {
        return file.isFile && file.canonicalFile == File(directory.canonicalFile, file.name)
    }

    private fun copyFailed(context: Context, technicalMessage: String?) =
        AppError.FileError.CopyFailed(
            userMessage = context.getString(R.string.error_copy_failed),
            technicalMessage = technicalMessage,
            messageResId = R.string.error_copy_failed,
        )

    private fun saveFailed(context: Context, technicalMessage: String?) =
        AppError.FileError.SaveFailed(
            userMessage = context.getString(R.string.error_save_failed),
            technicalMessage = technicalMessage,
            messageResId = R.string.error_save_failed,
        )
}
