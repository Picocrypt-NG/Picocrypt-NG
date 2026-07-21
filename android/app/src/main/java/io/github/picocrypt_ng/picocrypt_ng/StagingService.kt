package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import androidx.annotation.StringRes
import androidx.documentfile.provider.DocumentFile
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

enum class SelectionKind { SINGLE_FILE, MULTI_FILE, FOLDER }

data class StagedSelection(
    val kind: SelectionKind,
    val displayName: String,
    val stagingRoot: String,
    val inputFiles: List<String>,
    val onlyFolders: List<String>,
    val onlyFiles: List<String>,
    val suggestedOutputName: String,
)

object StagingService {
    private const val STAGING_DIR = "picocrypt_files/staging"

    // ---- pure helpers (JVM-testable) ----
    fun resolveCollision(existing: Set<String>, name: String): String {
        if (name !in existing) return name
        val dot = name.lastIndexOf('.')
        val stem = if (dot > 0) name.substring(0, dot) else name
        val ext = if (dot > 0) name.substring(dot) else ""
        var i = 1
        while ("$stem ($i)$ext" in existing) i++
        return "$stem ($i)$ext"
    }
    fun folderOutputName(rootName: String): String = "$rootName.zip.pcv"
    fun multiFileOutputName(unixSeconds: Long): String = "encrypted-$unixSeconds.zip.pcv"

    const val SPACE_MARGIN_BYTES: Long = 16L * 1024 * 1024 // 16 MiB headroom

    /** Peak internal usage ~= staged copy + encrypted temp zip + output volume, before cleanup. */
    fun requiredBytes(total: Long): Long = 3L * total + SPACE_MARGIN_BYTES
    fun hasSpaceFor(total: Long, usable: Long): Boolean = usable >= requiredBytes(total)

    private fun usableSpace(context: Context): Long =
        File(context.filesDir, STAGING_DIR).let { it.mkdirs(); it.usableSpace }

    private fun treeSize(dir: DocumentFile): Long {
        var sum = 0L
        for (c in dir.listFiles()) {
            if (c.isVirtual) continue
            sum += if (c.isDirectory) treeSize(c) else c.length()
        }
        return sum
    }

    // ---- IO ----
    private fun stagingDir(context: Context): File = File(context.filesDir, STAGING_DIR).also { it.mkdirs() }
    fun wipeStaging(context: Context) { File(context.filesDir, STAGING_DIR).deleteRecursively() }

    suspend fun copyTreeToStaging(context: Context, treeUri: Uri): Result<StagedSelection> =
        withContext(Dispatchers.IO) {
            val tree = DocumentFile.fromTreeUri(context, treeUri)
                ?: return@withContext Result.failure(
                    copyError(context, R.string.error_could_not_open_folder, "$treeUri")
                )
            stageTree(context, tree)
        }

    internal suspend fun stageTree(context: Context, tree: DocumentFile): Result<StagedSelection> =
        withContext(Dispatchers.IO) {
            try {
                wipeStaging(context)
                val total = treeSize(tree)
                val usable = usableSpace(context)
                if (!hasSpaceFor(total, usable)) {
                    return@withContext Result.failure(insufficientStorageError(context, total, usable))
                }
                val rootName = sanitizeName(tree.name ?: "folder")
                val root = File(stagingDir(context), rootName)
                val files = mutableListOf<String>()
                copyChildren(context, tree, root, files)
                if (files.isEmpty()) {
                    return@withContext Result.failure(
                        copyError(context, R.string.error_selected_folder_empty, rootName)
                    )
                }
                Result.success(
                    StagedSelection(
                        kind = SelectionKind.FOLDER,
                        displayName = rootName,
                        stagingRoot = stagingDir(context).absolutePath,
                        inputFiles = files,
                        onlyFolders = listOf(root.absolutePath),
                        onlyFiles = emptyList(),
                        suggestedOutputName = folderOutputName(rootName),
                    )
                )
            } catch (e: CancellationException) {
                wipeStaging(context); throw e
            } catch (e: Exception) {
                wipeStaging(context)
                Result.failure(
                    localizedCopyError(
                        context,
                        R.string.error_read_folder_failed,
                        e,
                    )
                )
            }
        }

    /**
     * Strips path-traversal characters from a SAF display name so it cannot
     * escape the staging directory when used in File(parent, name).
     */
    internal fun sanitizeName(name: String): String =
        File(name).name                        // strips any leading path segments
            .replace("..", "")                 // remove remaining ".." sequences
            .replace('/', '_')                 // replace any residual separators
            .replace('\\', '_')
            .ifEmpty { "_" }                   // never produce an empty name

    private fun copyChildren(context: Context, dir: DocumentFile, dest: File, out: MutableList<String>) {
        dest.mkdirs()
        for (child in dir.listFiles()) {
            if (child.isVirtual) continue
            val rawName = child.name ?: continue
            val name = sanitizeName(rawName)
            when {
                child.isDirectory -> copyChildren(context, child, File(dest, name), out)
                child.isFile -> {
                    val target = File(dest, name)
                    context.contentResolver.openInputStream(child.uri)?.use { input ->
                        FileOutputStream(target).use { output -> input.copyTo(output) }
                    } ?: throw IllegalStateException("could not open ${child.uri}")
                    out.add(target.absolutePath)
                }
            }
        }
    }

    suspend fun copyFilesToStaging(context: Context, uris: List<Uri>, nowUnixSeconds: Long): Result<StagedSelection> =
        withContext(Dispatchers.IO) {
            try {
                wipeStaging(context)
                val total = uris.sumOf { DocumentFile.fromSingleUri(context, it)?.length() ?: 0L }
                val usable = usableSpace(context)
                if (!hasSpaceFor(total, usable)) {
                    return@withContext Result.failure(insufficientStorageError(context, total, usable))
                }
                val dir = stagingDir(context)
                val used = mutableSetOf<String>()
                val files = mutableListOf<String>()
                for (uri in uris) {
                    val display = sanitizeName(queryDisplayName(context, uri) ?: "file")
                    val name = resolveCollision(used, display)
                    used.add(name)
                    val target = File(dir, name)
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        FileOutputStream(target).use { output -> input.copyTo(output) }
                    } ?: return@withContext Result.failure(
                        copyError(context, R.string.error_could_not_open_selected_file, "$uri")
                    )
                    files.add(target.absolutePath)
                }
                if (files.isEmpty()) {
                    return@withContext Result.failure(
                        copyError(context, R.string.error_no_files_selected, null)
                    )
                }
                Result.success(
                    StagedSelection(
                        kind = SelectionKind.MULTI_FILE,
                        displayName = context.resources.getQuantityString(
                            R.plurals.selected_files_count,
                            files.size,
                            files.size,
                        ),
                        stagingRoot = dir.absolutePath,
                        inputFiles = files,
                        onlyFolders = emptyList(),
                        onlyFiles = files,
                        suggestedOutputName = multiFileOutputName(nowUnixSeconds),
                    )
                )
            } catch (e: CancellationException) {
                wipeStaging(context); throw e
            } catch (e: Exception) {
                wipeStaging(context)
                Result.failure(
                    localizedCopyError(
                        context,
                        R.string.error_copy_files_failed,
                        e,
                    )
                )
            }
        }

    private fun queryDisplayName(context: Context, uri: Uri): String? {
        context.contentResolver.query(uri, null, null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val i = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (i != -1) return c.getString(i)
            }
        }
        return null
    }

    internal fun insufficientStorageError(context: Context, total: Long, usable: Long): AppError.FileError.InsufficientStorage {
        val required = requiredBytes(total)
        return AppError.FileError.InsufficientStorage(
            userMessage = context.getString(R.string.error_insufficient_storage, required, usable),
            technicalMessage = "required=$required usable=$usable",
            messageResId = R.string.error_insufficient_storage,
            messageArgs = listOf(required, usable),
        )
    }

    internal fun localizedCopyError(
        context: Context,
        @StringRes messageResId: Int,
        error: Throwable,
    ): AppError.FileError.CopyFailed {
        val reasonResId = failureReasonResId(error)
        val fallbackReason = context.getString(reasonResId)
        return AppError.FileError.CopyFailed(
            userMessage = context.getString(messageResId, fallbackReason),
            technicalMessage = error.message ?: error.toString(),
            messageResId = messageResId,
            messageArgs = listOf(LocalizedMessageArg(reasonResId)),
        )
    }

    private fun copyError(
        context: Context,
        @StringRes messageResId: Int,
        tech: String?,
        messageArgs: List<Any> = emptyList(),
    ) = AppError.FileError.CopyFailed(
        userMessage = if (messageArgs.isEmpty()) {
            context.getString(messageResId)
        } else {
            context.getString(messageResId, *messageArgs.toTypedArray())
        },
        technicalMessage = tech,
        messageResId = messageResId,
        messageArgs = messageArgs,
    )
}
