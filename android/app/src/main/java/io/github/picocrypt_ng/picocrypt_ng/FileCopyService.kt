package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.system.Os
import android.system.OsConstants
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

object FileCopyService {
    private const val INTERNAL_FILES_DIR = "picocrypt_files"
    private const val PCV3_RETAINED_OUTPUT_NAME = "pcv3_retained_output"
    private const val PCV3_PRIVATE_PREFIX = ".picocrypt-pcv3-"
    private const val MAX_INPUT_EXTENSION_LENGTH = 32
    private const val MAX_PCV3_DESTINATION_DISPLAY_NAME_LENGTH = 255
    private const val PCV3_RECOVERY_SUFFIX = ".pcv3-recovery"
    private const val PCV3_RECOVERY_DESTINATION_NAME_INVALID =
        "PCV3_RECOVERY_DESTINATION_NAME_INVALID"
    private const val PCV3_OUTPUT_DESCRIPTOR_OPEN_FAILED = "PCV3_OUTPUT_DESCRIPTOR_OPEN_FAILED"
    private val safeInputExtensionCharacters = Regex("[A-Za-z0-9_+-]+")
    private val startupInputName = Regex("input_file(?:\\.[^/\\\\]+)?")
    private val startupInputStageName = Regex("input_.+\\.incomplete")
    private val startupKeyfileName = Regex("keyfile_[0-9]+")
    private val startupKeyfileStageName = Regex("keyfile_[0-9]+_.+\\.incomplete")
    private val inputCopyMutex = Mutex()
    private val keyfileCopyMutex = Mutex()

    internal data class FileIdentity(val device: Long, val inode: Long)

    internal interface AtomicFilePublisher {
        fun identity(file: File): FileIdentity?
        fun publishNoReplace(source: File, target: File, expected: FileIdentity): InputCopyPublication
    }

    private object AndroidAtomicFilePublisher : AtomicFilePublisher {
        override fun identity(file: File): FileIdentity? {
            val stat = try {
                Os.lstat(file.absolutePath)
            } catch (error: android.system.ErrnoException) {
                if (error.errno == OsConstants.ENOENT) return null
                throw error
            }
            if (!OsConstants.S_ISREG(stat.st_mode)) {
                throw IOException("Owned path is not a regular file")
            }
            return FileIdentity(stat.st_dev, stat.st_ino)
        }

        override fun publishNoReplace(source: File, target: File, expected: FileIdentity): InputCopyPublication =
            GoBridge.publishInputCopy(requireNotNull(source.parentFile).absolutePath,
                source.name, target.name, expected.device, expected.inode)
    }

    /**
     * Copies a file from a URI to the internal app data directory.
     * Uses fixed filename "input_file" (preserves extension if provided).
     * @return Result with file path on success, AppError on failure
     */
    suspend fun copyFileToInternalStorage(
        context: Context,
        uri: Uri,
        originalFileName: String
    ): Result<String> = copyFileToInternalStorage(
        context = context,
        uri = uri,
        originalFileName = originalFileName,
        publisher = AndroidAtomicFilePublisher,
        afterAcquire = {},
        afterPublish = {},
    )

    internal suspend fun copyFileToInternalStorage(
        context: Context,
        uri: Uri,
        originalFileName: String,
        publisher: AtomicFilePublisher,
        afterAcquire: suspend () -> Unit,
        afterPublish: suspend () -> Unit,
        source: AndroidStagingSource = AndroidStagingSource(context),
    ): Result<String> {
        inputCopyMutex.lock()
        return try {
            afterAcquire()
            val internalDir = File(context.filesDir, INTERNAL_FILES_DIR)
            val ext = originalFileName.substringAfterLast(".", "")
                .takeIf {
                    it.length in 1..MAX_INPUT_EXTENSION_LENGTH &&
                        it.matches(safeInputExtensionCharacters)
                }
                .orEmpty()
            val fixedFileName = if (ext.isEmpty()) "input_file" else "input_file.$ext"
            val destFile = File(internalDir, fixedFileName)
            var incompleteFile: File? = null
            var incompleteIdentity: FileIdentity? = null
            var publishedIdentity: FileIdentity? = null
            var resultDelivered = false

            try {
                val result = withContext(Dispatchers.IO) {
                    try {
                        if ((!internalDir.exists() && !internalDir.mkdirs()) ||
                            !internalDir.isDirectory ||
                            internalDir.canonicalFile != File(context.filesDir.canonicalFile, INTERNAL_FILES_DIR)
                        ) {
                            throw IOException("Could not create internal input directory")
                        }

                        val ownedIncompleteFile = File.createTempFile(
                            "input_",
                            ".incomplete",
                            internalDir,
                        )
                        incompleteFile = ownedIncompleteFile
                        val ownedIncompleteIdentity = publisher.identity(ownedIncompleteFile)
                            ?: throw IOException("Could not identify incomplete input copy")
                        incompleteIdentity = ownedIncompleteIdentity

                        copyProviderInput(context, uri, ownedIncompleteFile, source)
                        currentCoroutineContext().ensureActive()

                        val publication = publisher.publishNoReplace(ownedIncompleteFile, destFile, ownedIncompleteIdentity)
                        if (publication != InputCopyPublication.PUBLISHED && publication != InputCopyPublication.PUBLISHED_ERROR) {
                            throw IOException("Input publication was not confirmed")
                        }
                        publishedIdentity = ownedIncompleteIdentity
                        // Confirmed native publication consumed the source name. A new
                        // file at that name belongs to a different owner.
                        incompleteIdentity = null
                        if (publisher.identity(destFile) != ownedIncompleteIdentity) {
                            throw IOException("Published input identity does not match its complete copy")
                        }
                        if (publication == InputCopyPublication.PUBLISHED_ERROR) {
                            throw IOException("Input publication completed with an error")
                        }
                        afterPublish()
                        Result.success(destFile.absolutePath)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Result.failure(copyFailed(context, e.message))
                    }
                }
                resultDelivered = result.isSuccess
                result
            } finally {
                if (!resultDelivered) {
                    // Until the successful result reaches FileCard this service remains
                    // the sole owner. A cancelled dispatcher handoff must not leak either
                    // name, and an identity mismatch must never delete a replacement.
                    withContext(NonCancellable + Dispatchers.IO) {
                        deleteIfOwned(incompleteFile, incompleteIdentity, publisher)
                        deleteIfOwned(destFile, publishedIdentity, publisher)
                    }
                }
            }
        } finally {
            inputCopyMutex.unlock()
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
        afterAcquire: suspend () -> Unit = {},
        afterPublish: suspend () -> Unit = {},
        publisher: AtomicFilePublisher = AndroidAtomicFilePublisher,
        source: AndroidStagingSource = AndroidStagingSource(context),
    ): Result<String> {
        keyfileCopyMutex.lock()
        return try {
            afterAcquire()
            val internalDir = File(context.filesDir, INTERNAL_FILES_DIR)
            val destFile = File(internalDir, "keyfile_$index")
            var incompleteFile: File? = null
            var incompleteIdentity: FileIdentity? = null
            var publishedIdentity: FileIdentity? = null
            var resultDelivered = false

            try {
                val result = withContext(Dispatchers.IO) {
                    try {
                        if ((!internalDir.exists() && !internalDir.mkdirs()) ||
                            !internalDir.isDirectory ||
                            internalDir.canonicalFile != File(context.filesDir.canonicalFile, INTERNAL_FILES_DIR)
                        ) {
                            throw IOException("Could not create internal keyfile directory")
                        }

                        if (destFile.exists()) throw IOException("Keyfile target already exists")

                        val ownedIncompleteFile = File.createTempFile(
                            "keyfile_${index}_",
                            ".incomplete",
                            internalDir,
                        )
                        incompleteFile = ownedIncompleteFile
                        val ownedIncompleteIdentity = publisher.identity(ownedIncompleteFile)
                            ?: throw IOException("Could not identify incomplete keyfile copy")
                        incompleteIdentity = ownedIncompleteIdentity

                        copyProviderInput(context, uri, ownedIncompleteFile, source)
                        currentCoroutineContext().ensureActive()

                        val publication = publisher.publishNoReplace(ownedIncompleteFile, destFile, ownedIncompleteIdentity)
                        if (publication != InputCopyPublication.PUBLISHED && publication != InputCopyPublication.PUBLISHED_ERROR) {
                            throw IOException("Keyfile publication was not confirmed")
                        }
                        publishedIdentity = ownedIncompleteIdentity
                        // Confirmed native publication consumed the source name. A new
                        // file at that name belongs to a different owner.
                        incompleteIdentity = null
                        if (publisher.identity(destFile) != ownedIncompleteIdentity) {
                            throw IOException("Published keyfile identity does not match its complete copy")
                        }
                        if (publication == InputCopyPublication.PUBLISHED_ERROR) {
                            throw IOException("Keyfile publication completed with an error")
                        }
                        afterPublish()
                        Result.success(destFile.absolutePath)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Result.failure(copyFailed(context, e.message))
                    }
                }
                resultDelivered = result.isSuccess
                result
            } finally {
                if (!resultDelivered) {
                    // Until the successful result reaches KeyfileCard this service remains
                    // the sole owner. A cancelled dispatcher handoff must not leak either
                    // name, and an identity mismatch must never delete a replacement.
                    withContext(NonCancellable + Dispatchers.IO) {
                        deleteIfOwned(incompleteFile, incompleteIdentity, publisher)
                        deleteIfOwned(destFile, publishedIdentity, publisher)
                    }
                }
            }
        } finally {
            keyfileCopyMutex.unlock()
        }
    }

    private suspend fun copyProviderInput(
        context: Context,
        uri: Uri,
        destination: File,
        source: AndroidStagingSource,
    ) = source.withCancellation {
        val buffer = ByteArray(64 * 1024)
        try {
            val input = source.open(uri)
            try {
                FileOutputStream(destination).use { output ->
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val count = input.read(buffer)
                        currentCoroutineContext().ensureActive()
                        if (count == -1) break
                        if (count <= 0 || count > buffer.size) throw IOException("Invalid source read progress")
                        val usable = context.filesDir.usableSpace
                        if (usable < StagingService.SPACE_MARGIN_BYTES ||
                            count.toLong() > usable - StagingService.SPACE_MARGIN_BYTES
                        ) throw IOException("Insufficient storage for source copy")
                        output.write(buffer, 0, count)
                    }
                }
            } finally {
                source.close(input)
            }
        } finally {
            buffer.fill(0)
        }
    }

    /**
     * Removes an owned app-private file or tree without following links. Absence is complete.
     */
    suspend fun deleteFile(context: Context, filePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            NoFollowFileTree.delete(context.filesDir, File(filePath))
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
                if (!isPcv3PrivateEntry(file) && !NoFollowFileTree.delete(filesDir, file)) {
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
     * Removes only app-private entries whose transient ownership is proven by
     * their production writer. Published or uncertain outputs, retained PCV3
     * trees, and unknown future entries remain untouched until their exact owner
     * authorizes removal.
     */
    suspend fun cleanupStartupTransientFiles(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val filesDir = context.filesDir
            val entries = filesDir.list() ?: return@withContext false
            if (INTERNAL_FILES_DIR !in entries) return@withContext true

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
                val transientTree = file.name == "staging"
                val transientFile = file.name.matches(startupInputName) ||
                    file.name.matches(startupInputStageName) ||
                    file.name.matches(startupKeyfileName) ||
                    file.name.matches(startupKeyfileStageName) ||
                    file.name == "output_file.incomplete" ||
                    file.name == "output_file.pcv.incomplete"

                when {
                    transientTree -> {
                        if (!NoFollowFileTree.delete(filesDir, file)) allDeleted = false
                    }
                    transientFile -> {
                        if (!isRegularFileInDirectory(internalDir, file) ||
                            !file.delete() ||
                            file.exists()
                        ) {
                            allDeleted = false
                        }
                    }
                }
            }
            allDeleted
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Confidentiality-first process-start discard for the one clean PCV3 output.
     * Receipt custody is decided by [StartupCleanup] before this exact-name path
     * can be called. Unexpected entries are preserved and block UI startup.
     */
    suspend fun cleanupPcv3RetainedOutputAtStartup(context: Context): Boolean =
        cleanupPcv3RetainedOutputAtStartup(context, AndroidAtomicFilePublisher)

    internal suspend fun cleanupPcv3RetainedOutputAtStartup(
        context: Context,
        publisher: AtomicFilePublisher,
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            val filesDir = context.filesDir
            val rootEntries = filesDir.list() ?: return@withContext false
            if (INTERNAL_FILES_DIR !in rootEntries) return@withContext true

            val internalDir = File(filesDir, INTERNAL_FILES_DIR)
            val expectedInternalDir = File(filesDir.canonicalFile, INTERNAL_FILES_DIR)
            if (internalDir.canonicalFile != expectedInternalDir ||
                !internalDir.exists() ||
                !internalDir.isDirectory
            ) {
                return@withContext false
            }

            val retainedEntries = internalDir.list() ?: return@withContext false
            if (PCV3_RETAINED_OUTPUT_NAME !in retainedEntries) return@withContext true

            val retainedOutput = File(internalDir, PCV3_RETAINED_OUTPUT_NAME)
            val identity = publisher.identity(retainedOutput) ?: return@withContext false
            deletePcv3RetainedOutputIfOwned(
                filesDir = filesDir,
                retainedOutput = retainedOutput,
                expectedIdentity = identity,
                publisher = publisher,
            )
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
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
     * Creates the existing app-private PCV3 parent on a clean install, then pins
     * and validates both directory identities without following a replacement.
     */
    suspend fun ensurePcv3PrivateParent(context: Context): File? =
        ensurePcv3PrivateParent(context, AndroidPcv3FilesystemBoundary)

    internal suspend fun ensurePcv3PrivateParent(
        context: Context,
        filesystem: Pcv3FilesystemBoundary,
    ): File? = withContext(Dispatchers.IO) {
        try {
            val filesDir = context.filesDir.absoluteFile.normalize()
            if (!verifyPcv3Directory(filesDir, filesystem, sync = false)) return@withContext null
            val parent = File(filesDir, INTERNAL_FILES_DIR).absoluteFile.normalize()
            if (parent.parentFile != filesDir) return@withContext null

            when (val existing = filesystem.lstat(parent)) {
                null -> {
                    filesystem.createDirectory(parent)
                    if (!verifyPcv3Directory(filesDir, filesystem, sync = true)) return@withContext null
                }
                else -> if (existing.kind != Pcv3FilesystemKind.DIRECTORY) return@withContext null
            }
            parent.takeIf { verifyPcv3Directory(it, filesystem, sync = false) }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            null
        } catch (_: LinkageError) {
            null
        }
    }

    /** Returns the sole app-private target accepted by Android PCV3 operations. */
    fun getPcv3RetainedOutputPath(context: Context): String {
        return File(context.filesDir, "$INTERNAL_FILES_DIR/$PCV3_RETAINED_OUTPUT_NAME").absolutePath
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
     * @param ownsSource Whether the initiating operation still owns this save
     * @return Result with Unit on success, AppError on failure
     */
    suspend fun saveFileToUri(
        context: Context,
        sourceFilePath: String,
        destinationUri: Uri,
        ownsSource: () -> Boolean,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            currentCoroutineContext().ensureActive()
            if (!ownsSource()) return@withContext Result.failure(saveFailed(context, "Save owner changed"))
            val sourceFile = File(sourceFilePath)
            if (!sourceFile.exists()) {
                return@withContext Result.failure(
                    saveFailed(context, "File does not exist: $sourceFilePath")
                )
            }
            
            // Pin the selected output before a provider call can suspend ownership
            // or allow the pathname to be reused by a later operation.
            FileInputStream(sourceFile).use { inputStream ->
                currentCoroutineContext().ensureActive()
                if (!ownsSource()) return@withContext Result.failure(saveFailed(context, "Save owner changed"))
                context.contentResolver.openOutputStream(destinationUri)?.use { outputStream ->
                    currentCoroutineContext().ensureActive()
                    if (!ownsSource()) return@withContext Result.failure(saveFailed(context, "Save owner changed"))
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    try {
                        while (true) {
                            currentCoroutineContext().ensureActive()
                            if (!ownsSource()) return@withContext Result.failure(saveFailed(context, "Save owner changed"))
                            val count = inputStream.read(buffer)
                            if (count < 0) break
                            currentCoroutineContext().ensureActive()
                            if (!ownsSource()) return@withContext Result.failure(saveFailed(context, "Save owner changed"))
                            outputStream.write(buffer, 0, count)
                        }
                    } finally {
                        buffer.fill(0)
                    }
                } ?: return@withContext Result.failure(
                    saveFailed(context, "Could not open output stream for URI: $destinationUri")
                )
            }
            
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
     * Validates the provider-owned display name for a Force recovery destination.
     * The content URI remains opaque; missing or untrusted metadata fails closed.
     */
    suspend fun validatePcv3RecoveryDestination(
        context: Context,
        destinationUri: Uri,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val displayName = context.contentResolver.query(
                destinationUri,
                arrayOf(OpenableColumns.DISPLAY_NAME),
                null,
                null,
                null,
            )?.use { cursor ->
                val nameColumn = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (nameColumn < 0 || !cursor.moveToFirst()) null else cursor.getString(nameColumn)
            }
            if (displayName != null &&
                displayName.length in 1..MAX_PCV3_DESTINATION_DISPLAY_NAME_LENGTH &&
                displayName.endsWith(PCV3_RECOVERY_SUFFIX)
            ) {
                Result.success(Unit)
            } else {
                Result.failure(saveFailed(context, PCV3_RECOVERY_DESTINATION_NAME_INVALID))
            }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            Result.failure(saveFailed(context, PCV3_RECOVERY_DESTINATION_NAME_INVALID))
        }
    }

    // Go repeats this check after descriptor ownership transfers. Refuse unsupported
    // providers here so the retained output remains available for another destination.
    internal fun supportsPcv3OutputDescriptor(descriptor: ParcelFileDescriptor): Boolean = try {
        OsConstants.S_ISREG(Os.fstat(descriptor.fileDescriptor).st_mode) &&
            Os.lseek(descriptor.fileDescriptor, 0, OsConstants.SEEK_CUR) >= 0
    } catch (_: Exception) {
        false
    }

    /**
     * Opens an opaque SAF destination for transfer to the Go-owned output action.
     * The successful descriptor is returned open and owned by the caller.
     */
    internal suspend fun openPcv3OutputDescriptor(
        context: Context,
        destinationUri: Uri,
        supportsDescriptor: (ParcelFileDescriptor) -> Boolean = ::supportsPcv3OutputDescriptor,
    ): Result<ParcelFileDescriptor> {
        var openedDescriptor: ParcelFileDescriptor? = null
        var resultDelivered = false
        try {
            val result = withContext(Dispatchers.IO) {
                try {
                    val descriptor = context.contentResolver.openFileDescriptor(destinationUri, "rwt")
                        ?: return@withContext Result.failure(
                            saveFailed(context, PCV3_OUTPUT_DESCRIPTOR_OPEN_FAILED),
                        )
                    openedDescriptor = descriptor
                    if (!supportsDescriptor(descriptor)) {
                        return@withContext Result.failure(
                            AppError.FileError.SaveFailed(
                                userMessage = context.getString(R.string.pcv3_output_provider_unsupported),
                                technicalMessage = "PCV3_OUTPUT_PROVIDER_UNSUPPORTED",
                                messageResId = R.string.pcv3_output_provider_unsupported,
                            ),
                        )
                    }
                    Result.success(descriptor)
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    Result.failure(saveFailed(context, PCV3_OUTPUT_DESCRIPTOR_OPEN_FAILED))
                }
            }
            resultDelivered = result.isSuccess
            return result
        } finally {
            if (!resultDelivered) {
                withContext(NonCancellable + Dispatchers.IO) {
                    try {
                        openedDescriptor?.close()
                    } catch (_: Exception) {
                        // The primary cancellation/failure remains authoritative.
                    }
                }
            }
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
                if (file.name.endsWith(".incomplete") && !isPcv3PrivateEntry(file)) {
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

    private fun isPcv3PrivateEntry(file: File): Boolean =
        file.name == PCV3_RETAINED_OUTPUT_NAME || file.name.startsWith(PCV3_PRIVATE_PREFIX)

    private fun deleteIfOwned(
        file: File?,
        expectedIdentity: FileIdentity?,
        publisher: AtomicFilePublisher,
    ): Boolean {
        if (file == null || expectedIdentity == null) return true
        return try {
            val currentIdentity = publisher.identity(file) ?: return true
            currentIdentity == expectedIdentity && file.delete() && !file.exists()
        } catch (_: Exception) {
            false
        }
    }

    private fun deletePcv3RetainedOutputIfOwned(
        filesDir: File,
        retainedOutput: File,
        expectedIdentity: FileIdentity,
        publisher: AtomicFilePublisher,
    ): Boolean {
        return try {
            val currentIdentity = publisher.identity(retainedOutput) ?: return false
            currentIdentity == expectedIdentity &&
                NoFollowFileTree.delete(filesDir, retainedOutput) &&
                publisher.identity(retainedOutput) == null
        } catch (_: Exception) {
            false
        }
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
