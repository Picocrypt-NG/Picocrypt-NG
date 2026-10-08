package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import androidx.annotation.StringRes
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.ArrayDeque
import java.util.Collections
import java.util.IdentityHashMap
import org.json.JSONArray
import org.json.JSONObject

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
    fun requiredBytes(total: Long): Long =
        if (total < 0 || total > (Long.MAX_VALUE - SPACE_MARGIN_BYTES) / 3) Long.MAX_VALUE
        else 3L * total + SPACE_MARGIN_BYTES
    fun hasSpaceFor(total: Long, usable: Long): Boolean = total >= 0 && usable >= 0 &&
        total <= (Long.MAX_VALUE - SPACE_MARGIN_BYTES) / 3 && usable >= requiredBytes(total)

    private val stagingMutex = kotlinx.coroutines.sync.Mutex()

    private fun stagingDir(context: Context): File = File(context.filesDir, STAGING_DIR)

    fun wipeStaging(context: Context): Boolean {
        if (!stagingMutex.tryLock()) return false
        return try {
            wipeStagingUnlocked(context)
        } finally {
            stagingMutex.unlock()
        }
    }

    private fun wipeStagingUnlocked(context: Context): Boolean =
        NoFollowFileTree.delete(context.filesDir, stagingDir(context))

    suspend fun copyTreeToStaging(context: Context, treeUri: Uri): Result<StagedSelection> =
        stageSelection(context, R.string.error_read_folder_failed) { source, budget ->
            buildTreePlan(context, treeUri, source, budget)
        }

    suspend fun copyFilesToStaging(context: Context, uris: List<Uri>, nowUnixSeconds: Long): Result<StagedSelection> {
        currentCoroutineContext().ensureActive()
        if (uris.size > GoBridge.PCV3_MAX_SELECTION_PATHS) return Result.failure(resourceLimit())
        val selected = uris.toList()
        return stageSelection(context, R.string.error_copy_files_failed) { source, budget ->
            if (uris.isEmpty()) throw copyError(context, R.string.error_no_files_selected, null)
            val plan = StagingPlan(SelectionKind.MULTI_FILE, stagingDir(context), budget,
                context.resources.getQuantityString(R.plurals.selected_files_count, uris.size, uris.size),
                multiFileOutputName(nowUnixSeconds))
            val names = mutableSetOf<String>()
            for (uri in selected) {
                currentCoroutineContext().ensureActive()
                plan.admitUri(source, uri)
                val metadata = source.describe(uri)
                val name = resolveCollision(names, plan.admitName(metadata.name ?: "file"))
                names.add(name)
                plan.add(uri, plan.path(plan.directory.path, name), false, metadata.size)
            }
            plan
        }
    }

    /** The mutex includes dispatch delivery: cancelled waiters never acquire tree custody. */
    private suspend fun stageSelection(
        context: Context,
        @StringRes errorResource: Int,
        collect: suspend (AndroidStagingSource, Pcv3SafMemoryBudget) -> StagingPlan,
    ): Result<StagedSelection> {
        stagingMutex.lock()
        try {
            var ownsStaging = false
            var delivered = false
            var primaryFailure: Throwable? = null
            try {
                val selection = try {
                    withContext(Dispatchers.IO) {
                        val source = AndroidStagingSource(context)
                        val watcher = CoroutineScope(currentCoroutineContext()).launch(start = CoroutineStart.UNDISPATCHED) {
                            try {
                                awaitCancellation()
                            } finally {
                                source.cancel()
                            }
                        }
                        try {
                            currentCoroutineContext().ensureActive()
                            val plan = collect(source, workingBudget(source))
                            if (plan.files.isEmpty()) throw copyError(context, R.string.error_selected_folder_empty, plan.displayName)
                            currentCoroutineContext().ensureActive()
                            if (!wipeStagingUnlocked(context)) throw cleanupError("before staging")
                            ownsStaging = true
                            val available = context.filesDir.usableSpace
                            if (!hasSpaceFor(plan.declaredBytes, available)) {
                                throw insufficientStorageError(context, plan.declaredBytes, available)
                            }
                            if (!plan.directory.mkdirs() || !plan.directory.isDirectory) {
                                throw IOException("Could not create staging directory")
                            }
                            copyPlan(context, plan, source, (available - SPACE_MARGIN_BYTES) / 3)
                            currentCoroutineContext().ensureActive()
                            plan.selection()
                        } finally {
                            withContext(NonCancellable) { watcher.cancelAndJoin() }
                        }
                    }
                } catch (failure: Throwable) {
                    primaryFailure = if (failure is Exception) cancellationOrFailure(failure) else failure
                    throw requireNotNull(primaryFailure)
                }
                delivered = true
                return Result.success(selection)
            } finally {
                if (ownsStaging && !delivered) {
                    withContext(NonCancellable) {
                        withContext(Dispatchers.IO) {
                            if (!wipeStagingUnlocked(context)) {
                                val cleanup = cleanupError("after undelivered staging")
                                val cause = primaryFailure
                                if (cause is CancellationException) cause.addSuppressed(cleanup)
                                else {
                                    cause?.let(cleanup::addSuppressed)
                                    throw cleanup
                                }
                            }
                        }
                    }
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            val actual = cancellationOrFailure(failure)
            if (actual is CancellationException) throw actual
            return Result.failure(when (actual) {
                is AppError, is Pcv3BridgeFailure -> actual
                else -> localizedCopyError(context, errorResource, actual)
            })
        } finally {
            stagingMutex.unlock()
        }
    }

    private suspend fun cancellationOrFailure(failure: Exception): Exception = try {
        currentCoroutineContext().ensureActive()
        failure
    } catch (cancelled: CancellationException) {
        // Coroutine stack recovery can return a copy; async settlement retains
        // the Job's original cancellation. Attach cleanup to that original.
        if (failure !is CancellationException) cancelled.addSuppressed(failure)
        else if (failure !== cancelled) {
            failure.suppressed.forEach { diagnostic ->
                if (diagnostic !is CancellationException && cancelled.suppressed.none { it === diagnostic }) {
                    cancelled.addSuppressed(diagnostic)
                }
            }
        }
        cancelled
    }

    internal fun cleanupFailure(cancellation: CancellationException): AppError.FileError.DeleteFailed? {
        val seen = Collections.newSetFromMap(IdentityHashMap<Throwable, Boolean>())
        var current: Throwable? = cancellation
        while (current != null && seen.add(current)) {
            current.suppressed.forEach { if (it is AppError.FileError.DeleteFailed) return it }
            current = current.cause
        }
        return null
    }

    private fun workingBudget(source: AndroidStagingSource): Pcv3SafMemoryBudget {
        val facts = source.observation() ?: throw resourceLimit()
        if (facts.lowMemory || facts.effectiveAvailableBytes <= 0 || facts.platformThresholdBytes <= 0 ||
            facts.processFootprintBytes <= 0 || facts.effectiveAvailableBytes < facts.platformThresholdBytes ||
            facts.effectiveAvailableBytes - facts.platformThresholdBytes < facts.processFootprintBytes ||
            facts.effectiveAvailableBytes - facts.platformThresholdBytes - facts.processFootprintBytes < PCV3_SAF_MAX_WORKING_BYTES
        ) throw resourceLimit()
        return Pcv3SafMemoryBudget(PCV3_SAF_MAX_WORKING_BYTES).also {
            if (!it.reserve(8L * 1024 * 1024)) throw resourceLimit()
        }
    }

    private data class StagingEntry(val uri: Uri, val path: String, val directory: Boolean)
    private data class PendingDirectory(val documentId: String, val path: String)

    private class StagingPlan(
        val kind: SelectionKind,
        val directory: File,
        private val memory: Pcv3SafMemoryBudget,
        val displayName: String,
        private val outputName: String,
    ) {
        val entries = mutableListOf<StagingEntry>()
        val files = mutableListOf<String>()
        private val paths = mutableSetOf<String>()
        private val directories = mutableSetOf<String>()
        var folderRoot: String? = null
        var declaredBytes = 0L
            private set
        // Only selection-owned fields are known here. The complete envelope,
        // including later credentials/comment/target, is checked by GoBridge.
        private var wireBytes = JSONObject().put("source", "").put("inputFiles", JSONArray())
            .put("onlyFiles", JSONArray()).put("onlyFolders", JSONArray()).toString()
            .toByteArray(Charsets.UTF_8).size.toLong()

        fun admitUri(source: AndroidStagingSource, uri: Uri) {
            val bytes = source.uriWorkingBytes(uri) ?: throw resourceLimit()
            if (bytes <= 0 || !memory.reserve(bytes)) throw resourceLimit()
        }

        fun documentUri(source: AndroidStagingSource, tree: Uri, id: String, treeCharge: Long): Uri {
            val allowance = uriConstructionBytes(id, treeCharge)
            if (!memory.reserve(allowance)) throw resourceLimit()
            var transferred = false
            try {
                val uri = source.documentUri(tree, id)
                val retained = source.uriWorkingBytes(uri) ?: throw resourceLimit()
                if (retained <= 0 || retained > allowance) throw resourceLimit()
                memory.release(allowance - retained)
                transferred = true
                return uri
            } finally {
                if (!transferred) memory.release(allowance)
            }
        }

        fun forEachChild(source: AndroidStagingSource, tree: Uri, id: String, treeCharge: Long,
            visit: (StagingSourceEntry) -> Unit) {
            val allowance = uriConstructionBytes(id, treeCharge)
            if (!memory.reserve(allowance)) throw resourceLimit()
            try {
                // The query URI and cursor remain live while its rows grow the plan.
                source.forEachChild(tree, id, visit)
            } finally {
                memory.release(allowance)
            }
        }

        fun admitDirectoryIdentity(id: String) {
            if (id.isEmpty()) throw IOException("Missing source directory identity")
            val bytes = id.strictUtf8Size((PCV3_SAF_MAX_WORKING_BYTES / 4).toInt()) ?: throw resourceLimit()
            if (!memory.reserve(128L + 4L * bytes)) throw resourceLimit()
            if (!directories.add(id)) throw IOException("Repeated source directory identity")
        }

        fun admitName(raw: String): String {
            return admittedName(memory, raw)
        }

        fun path(parent: String, name: String): String {
            val parentBytes = parent.strictUtf8Size(GoBridge.PCV3_MAX_PATH_BYTES) ?: throw resourceLimit()
            val nameBytes = name.strictUtf8Size(GoBridge.PCV3_MAX_PATH_BYTES) ?: throw resourceLimit()
            if (parentBytes.toLong() + 1 + nameBytes > GoBridge.PCV3_MAX_PATH_BYTES) throw resourceLimit()
            return File(parent, name).absolutePath
        }

        fun setRoot(path: String) {
            folderRoot = path
            addWire(quotedBytes(path))
        }

        fun add(uri: Uri, path: String, directory: Boolean, size: Long?) {
            val pathBytes = path.strictUtf8Size(GoBridge.PCV3_MAX_PATH_BYTES) ?: throw resourceLimit()
            if (!memory.reserve(768L + 4L * pathBytes)) throw resourceLimit()
            if (!paths.add(path)) throw IOException("Ambiguous staging destination")
            if (!directory) {
                if (files.size >= GoBridge.PCV3_MAX_SELECTION_PATHS) throw resourceLimit()
                val quoted = quotedBytes(path)
                val item = quoted + if (files.isEmpty()) 0 else 1
                addWire(item * if (kind == SelectionKind.MULTI_FILE) 2 else 1)
                if (files.isEmpty()) addWire(quoted - 2) // replaces source:""
                if (size != null) {
                    if (size < 0 || size > Long.MAX_VALUE - declaredBytes) throw IOException("Invalid aggregate source size")
                    declaredBytes += size
                }
                files.add(path)
            }
            entries.add(StagingEntry(uri, path, directory))
        }

        private fun quotedBytes(path: String): Long =
            (JSONObject.quote(path).strictUtf8Size(GoBridge.PCV3_MAX_ENVELOPE_BYTES) ?: throw resourceLimit()).toLong()

        private fun addWire(bytes: Long) {
            if (bytes < 0 || bytes > GoBridge.PCV3_MAX_ENVELOPE_BYTES - wireBytes) throw resourceLimit()
            wireBytes += bytes
        }

        fun selection(): StagedSelection {
            val inputs = files.toList()
            return StagedSelection(kind, displayName, directory.path, inputs,
                folderRoot?.let(::listOf) ?: emptyList(),
                if (kind == SelectionKind.MULTI_FILE) inputs else emptyList(), outputName)
        }
    }

    private suspend fun buildTreePlan(
        context: Context,
        tree: Uri,
        source: AndroidStagingSource,
        memory: Pcv3SafMemoryBudget,
    ): StagingPlan {
        val rootCharge = source.uriWorkingBytes(tree) ?: throw resourceLimit()
        if (rootCharge <= 0 || !memory.reserve(rootCharge)) throw resourceLimit()
        val rootId = source.treeDocumentId(tree)
        val rootAllowance = uriConstructionBytes(rootId, rootCharge)
        if (!memory.reserve(rootAllowance)) throw resourceLimit()
        var rootTransferred = false
        val rootUri = try {
            val uri = source.documentUri(tree, rootId)
            val retained = source.uriWorkingBytes(uri) ?: throw resourceLimit()
            if (retained <= 0 || retained > rootAllowance) throw resourceLimit()
            memory.release(rootAllowance - retained)
            rootTransferred = true
            uri
        } finally {
            if (!rootTransferred) memory.release(rootAllowance)
        }
        val directory = stagingDir(context)
        val rootMetadata = source.describe(rootUri, false)
        val name = admittedName(memory, rootMetadata.name ?: "folder")
        val plan = StagingPlan(SelectionKind.FOLDER, directory, memory, name, folderOutputName(name))
        val rootPath = plan.path(directory.path, name)
        plan.setRoot(rootPath)
        plan.admitDirectoryIdentity(rootId)
        plan.add(rootUri, rootPath, true, null)
        val pending = ArrayDeque<PendingDirectory>()
        pending.add(PendingDirectory(rootId, rootPath))
        val operationContext = currentCoroutineContext()
        while (pending.isNotEmpty()) {
            currentCoroutineContext().ensureActive()
            val parent = pending.removeFirst()
            plan.forEachChild(source, tree, parent.documentId, rootCharge) { entry ->
                operationContext.ensureActive()
                if (entry.virtual || !entry.regular || entry.name == null) return@forEachChild
                val name = plan.admitName(entry.name)
                val path = plan.path(parent.path, name)
                val id = entry.documentId ?: throw IOException("Missing source document identity")
                if (entry.directory) plan.admitDirectoryIdentity(id)
                val uri = plan.documentUri(source, tree, id, rootCharge)
                plan.add(uri, path, entry.directory, entry.size)
                if (entry.directory) pending.add(PendingDirectory(id, path))
            }
        }
        return plan
    }

    private suspend fun copyPlan(context: Context, plan: StagingPlan, source: AndroidStagingSource, availableBytes: Long) {
        val buffer = ByteArray(64 * 1024)
        var copied = 0L
        try {
            for (entry in plan.entries) {
                currentCoroutineContext().ensureActive()
                val target = File(entry.path)
                if (entry.directory) {
                    if (!target.mkdir()) throw IOException("Could not create exclusive staging directory")
                    continue
                }
                if (!target.createNewFile()) throw IOException("Staging destination already exists")
                val input = source.open(entry.uri)
                try {
                    FileOutputStream(target).use { output ->
                        try {
                            while (true) {
                                currentCoroutineContext().ensureActive()
                                val count = input.read(buffer)
                                currentCoroutineContext().ensureActive()
                                if (count == -1) break
                                if (count <= 0 || count > buffer.size) throw IOException("Invalid source read progress")
                                if (count.toLong() > availableBytes - copied) {
                                    throw insufficientStorageError(context, copied + count, context.filesDir.usableSpace)
                                }
                                output.write(buffer, 0, count)
                                copied += count
                            }
                        } finally {
                            buffer.fill(0)
                        }
                    }
                } finally {
                    source.close(input)
                }
            }
        } finally {
            buffer.fill(0)
        }
    }

    internal fun sanitizeName(name: String): String =
        File(name).name.replace("..", "").replace('/', '_').replace('\\', '_').ifEmpty { "_" }

    private fun admittedName(memory: Pcv3SafMemoryBudget, raw: String): String {
        val bytes = raw.strictUtf8Size((PCV3_SAF_MAX_WORKING_BYTES / 6).toInt()) ?: throw resourceLimit()
        val temporary = 6L * bytes
        if (!memory.reserve(temporary)) throw resourceLimit()
        return try {
            sanitizeName(raw).also {
                if (it == "." || '\u0000' in it) throw IOException("Invalid source display name")
                if (it.strictUtf8Size(GoBridge.PCV3_MAX_PATH_BYTES) == null) throw resourceLimit()
            }
        } finally {
            memory.release(temporary)
        }
    }

    private fun uriConstructionBytes(id: String, treeCharge: Long): Long {
        // Percent encoding can expand UTF-8 threefold. Allow for UTF-16 backing,
        // builder/result copies and Parcel sizing, while the original tree stays live.
        // This is a working-memory estimate, not an exact heap/RSS measurement.
        val idBytes = id.strictUtf8Size((PCV3_SAF_MAX_WORKING_BYTES / 32).toInt()) ?: throw resourceLimit()
        val variable = 32L * idBytes + 1024
        if (treeCharge <= 0 || treeCharge > (Long.MAX_VALUE - variable) / 4) throw resourceLimit()
        return 4 * treeCharge + variable
    }

    private fun resourceLimit() = Pcv3BridgeFailure("PCV3_RESOURCE_LIMIT")
    private fun cleanupError(phase: String) = AppError.FileError.DeleteFailed(
        technicalMessage = "Could not clear staging $phase",
    )

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
