package io.github.picocrypt_ng

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream

object FileCopyService {
    private const val INTERNAL_FILES_DIR = "picocrypt_files"

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
                    AppError.FileError.CopyFailed(
                        userMessage = "Failed to open file",
                        technicalMessage = "Could not open input stream for URI: $uri"
                    )
                )

            // Copy file (overwrite if exists)
            inputStream.use { input ->
                FileOutputStream(destFile).use { output ->
                    input.copyTo(output)
                }
            }

            Result.success(destFile.absolutePath)
        } catch (e: Exception) {
            Result.failure(
                AppError.FileError.CopyFailed(
                    userMessage = "Failed to copy file: ${e.message ?: "Unknown error"}",
                    technicalMessage = e.message
                )
            )
        }
    }
    
    /**
     * Copies a keyfile from a URI to the internal app data directory.
     * Uses fixed filename "keyfile_<index>" where index is the current keyfile count.
     * @return Result with file path on success, AppError on failure
     */
    suspend fun copyKeyfileToInternalStorage(
        context: Context,
        uri: Uri,
        index: Int
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            // Get internal files directory
            val internalDir = File(context.filesDir, INTERNAL_FILES_DIR)
            if (!internalDir.exists()) {
                internalDir.mkdirs()
            }

            // Use fixed filename "keyfile_<index>"
            val fixedFileName = "keyfile_$index"
            val destFile = File(internalDir, fixedFileName)

            // Open input stream from URI
            val inputStream: InputStream = context.contentResolver.openInputStream(uri)
                ?: return@withContext Result.failure(
                    AppError.FileError.CopyFailed(
                        userMessage = "Failed to open keyfile",
                        technicalMessage = "Could not open input stream for URI: $uri"
                    )
                )

            // Copy file (overwrite if exists)
            inputStream.use { input ->
                FileOutputStream(destFile).use { output ->
                    input.copyTo(output)
                }
            }

            Result.success(destFile.absolutePath)
        } catch (e: Exception) {
            Result.failure(
                AppError.FileError.CopyFailed(
                    userMessage = "Failed to copy keyfile: ${e.message ?: "Unknown error"}",
                    technicalMessage = e.message
                )
            )
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
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Cleans up all files in the internal storage directory.
     */
    suspend fun cleanupAllFiles(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val internalDir = File(context.filesDir, INTERNAL_FILES_DIR)
            if (internalDir.exists() && internalDir.isDirectory) {
                internalDir.listFiles()?.forEach { file ->
                    if (file.isFile) {
                        file.delete()
                    }
                }
                true
            } else {
                false
            }
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
                    AppError.FileError.SaveFailed(
                        userMessage = "Source file not found",
                        technicalMessage = "File does not exist: $sourceFilePath"
                    )
                )
            }
            
            context.contentResolver.openOutputStream(destinationUri)?.use { outputStream ->
                FileInputStream(sourceFile).use { inputStream ->
                    inputStream.copyTo(outputStream)
                }
            } ?: return@withContext Result.failure(
                AppError.FileError.SaveFailed(
                    userMessage = "Failed to open destination location",
                    technicalMessage = "Could not open output stream for URI: $destinationUri"
                )
            )
            
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(
                AppError.FileError.SaveFailed(
                    userMessage = "Failed to save file: ${e.message ?: "Unknown error"}",
                    technicalMessage = e.message
                )
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
            val internalDir = File(context.filesDir, INTERNAL_FILES_DIR)
            if (!internalDir.exists() || !internalDir.isDirectory) {
                return@withContext true
            }
            
            var allSuccess = true
            internalDir.listFiles()?.forEach { file ->
                if (file.isFile && file.name.endsWith(".incomplete")) {
                    if (!file.delete()) {
                        allSuccess = false
                    }
                }
            }
            
            allSuccess
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Cleans up all keyfile files (keyfile_0, keyfile_1, etc.) from internal storage.
     */
    suspend fun cleanupKeyfiles(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val internalDir = File(context.filesDir, INTERNAL_FILES_DIR)
            if (!internalDir.exists() || !internalDir.isDirectory) {
                return@withContext true
            }
            
            var allSuccess = true
            internalDir.listFiles()?.forEach { file ->
                if (file.isFile && file.name.startsWith("keyfile_")) {
                    if (!file.delete()) {
                        allSuccess = false
                    }
                }
            }
            
            allSuccess
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Cleans up operation files (input, output, and incomplete variants).
     * Used before starting a new operation to prevent contamination.
     */
    suspend fun cleanupOperationFilesBeforeStart(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val internalDir = File(context.filesDir, INTERNAL_FILES_DIR)
            if (!internalDir.exists() || !internalDir.isDirectory) {
                return@withContext true
            }
            
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
            outputFiles.forEach { fileName ->
                val file = File(internalDir, fileName)
                if (file.exists()) {
                    if (!file.delete()) {
                        allSuccess = false
                    }
                }
            }
            
            // Clean up any remaining incomplete files (but not input/keyfiles)
            cleanupIncompleteFiles(context)
            
            allSuccess
        } catch (e: Exception) {
            false
        }
    }
}

