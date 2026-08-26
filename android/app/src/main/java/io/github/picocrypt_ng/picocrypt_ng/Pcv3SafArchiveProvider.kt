package io.github.picocrypt_ng.picocrypt_ng

import android.content.ContentResolver
import android.net.Uri
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import java.util.concurrent.atomic.AtomicBoolean

internal const val PCV3_SAF_DIRECTORY_MIME = DocumentsContract.Document.MIME_TYPE_DIR
internal const val PCV3_SAF_FILE_MIME = "application/octet-stream"
internal const val PCV3_SAF_FIXED_WRITE_ERROR = "Picocrypt NG archive export failed"

private const val PCV3_SAF_MAX_ENTRIES = 65_536
private const val PCV3_SAF_MAX_COMPONENT_BYTES = 255
private const val PCV3_SAF_MAX_PATH_BYTES = 4_096
private const val PCV3_SAF_MAX_TOTAL_PATH_BYTES = 16 * 1_024 * 1_024
private const val PCV3_SAF_MAX_DEPTH = 128

data class Pcv3ArchiveEntryData(
    val name: String,
    val parentIndex: Long,
    val isDirectory: Boolean,
    val size: Long,
)

data class Pcv3ArchiveStepData(
    val kind: String,
    val nextIndex: Long,
)

/** Closed Kotlin owner around one Go SAF session. Finish and Abort remain lifecycle-only. */
interface Pcv3ArchiveSessionCapability {
    fun entryCount(): Long
    fun entry(index: Long): Pcv3ArchiveEntryData?
    fun confirmCrashReceiptPersisted(receipt: String): Pcv3ArchiveStepData
    fun attempt(index: Long): Pcv3ArchiveStepData
    fun ackDirectory(index: Long): Pcv3ArchiveStepData
    fun writeFd(index: Long, descriptor: Long): Pcv3ArchiveStepData
    fun cancel(): Pcv3ArchiveStepData
    fun finish(): Pcv3SnapshotData
    fun abort(): Pcv3SnapshotData
}

internal class Pcv3SafManifest internal constructor(
    val entries: List<Pcv3ArchiveEntryData>,
)

/**
 * Reads the gomobile manifest exactly once into a path-free immutable value and
 * independently revalidates every bound before Android can persist a receipt.
 */
internal fun capturePcv3SafManifest(
    session: Pcv3ArchiveSessionCapability,
): Pcv3SafManifest? = try {
    val count = session.entryCount()
    if (count !in 1..PCV3_SAF_MAX_ENTRIES.toLong()) return null

    val entries = ArrayList<Pcv3ArchiveEntryData>(count.toInt())
    val pathBytes = IntArray(count.toInt())
    val depths = IntArray(count.toInt())
    val siblings = HashSet<Pcv3SafSibling>(count.toInt())
    var totalPathBytes = 0L
    var totalFileBytes = 0L

    repeat(count.toInt()) { index ->
        val entry = session.entry(index.toLong()) ?: return null
        val componentBytes = entry.name.strictUtf8Size() ?: return null
        if (componentBytes !in 1..PCV3_SAF_MAX_COMPONENT_BYTES ||
            entry.name == "." || entry.name == ".." ||
            entry.name.any { it == '\u0000' || it == '/' || it == '\\' } ||
            entry.parentIndex < -1 || entry.parentIndex >= index ||
            entry.parentIndex == -1L && entry.name.hasWindowsDrivePrefix() ||
            entry.size < 0 || entry.isDirectory && entry.size != 0L
        ) {
            return null
        }

        val depth: Int
        val fullPathBytes: Int
        if (entry.parentIndex == -1L) {
            depth = 1
            fullPathBytes = componentBytes
        } else {
            val parentIndex = entry.parentIndex.toInt()
            if (!entries[parentIndex].isDirectory) return null
            depth = depths[parentIndex] + 1
            fullPathBytes = pathBytes[parentIndex] + 1 + componentBytes
        }
        if (depth > PCV3_SAF_MAX_DEPTH || fullPathBytes > PCV3_SAF_MAX_PATH_BYTES) return null

        totalPathBytes += fullPathBytes.toLong()
        if (totalPathBytes > PCV3_SAF_MAX_TOTAL_PATH_BYTES) return null
        if (!entry.isDirectory) {
            if (totalFileBytes > Long.MAX_VALUE - entry.size) return null
            totalFileBytes += entry.size
        }
        if (!siblings.add(Pcv3SafSibling(entry.parentIndex, entry.name))) return null

        entries += entry
        pathBytes[index] = fullPathBytes
        depths[index] = depth
    }
    Pcv3SafManifest(entries.toList())
} catch (_: Exception) {
    null
} catch (_: LinkageError) {
    null
}

private data class Pcv3SafSibling(val parentIndex: Long, val name: String)

private fun String.strictUtf8Size(): Int? {
    var index = 0
    while (index < length) {
        val current = this[index]
        when {
            current.isHighSurrogate() -> {
                if (index + 1 >= length || !this[index + 1].isLowSurrogate()) return null
                index += 2
            }
            current.isLowSurrogate() -> return null
            else -> index += 1
        }
    }
    return toByteArray(Charsets.UTF_8).size
}

private fun String.hasWindowsDrivePrefix(): Boolean =
    length >= 2 && this[1] == ':' && (this[0] in 'A'..'Z' || this[0] in 'a'..'z')

internal enum class Pcv3SafPublicationResult {
    READY_TO_FINISH,
    NEEDS_ABORT,
}

internal data class Pcv3SafDocumentMetadata(
    val authority: String?,
    val queriedDocumentId: String?,
    val uriDocumentId: String?,
    val displayName: String?,
    val mimeType: String?,
)

internal interface Pcv3SafCancellation {
    fun isCancelled(): Boolean
    fun cancel()
}

internal interface Pcv3SafDuplicateDescriptor {
    fun detachFd(): Int
    fun close()
}

internal interface Pcv3SafOriginalDescriptor {
    fun duplicate(): Pcv3SafDuplicateDescriptor
    fun close()
    fun closeWithError(message: String)
}

/** Direct Android boundary. It performs no retries, deletes, renames, URI logging, or persistence. */
internal interface Pcv3SafPlatform {
    fun newCancellation(): Pcv3SafCancellation
    fun normalizeTreeRoot(tree: Uri): Uri?
    fun documentIdentity(document: Uri): Pcv3SafDocumentIdentity?
    fun createDocument(parent: Uri, mimeType: String, displayName: String): Uri?
    fun queryDocument(document: Uri, cancellation: Pcv3SafCancellation): Pcv3SafDocumentMetadata?
    fun openDocument(
        document: Uri,
        mode: String,
        cancellation: Pcv3SafCancellation,
    ): Pcv3SafOriginalDescriptor?
}

/** Provider-facing least authority: no receipt, cancellation, or terminal session methods. */
internal interface Pcv3SafEntrySession {
    fun attempt(index: Long): Pcv3ArchiveStepData
    fun ackDirectory(index: Long): Pcv3ArchiveStepData
    fun writeFd(index: Long, descriptor: Long): Pcv3ArchiveStepData
}

/**
 * Executes provider entry effects only. The lifecycle owner must confirm the
 * durable crash receipt before invoking this class and retains Finish/Abort.
 */
internal interface Pcv3SafPublisher {
    fun newCancellation(): Pcv3SafCancellation
    fun publish(
        root: Uri,
        manifest: Pcv3SafManifest,
        session: Pcv3SafEntrySession,
        cancellation: Pcv3SafCancellation,
    ): Pcv3SafPublicationResult
}

internal class Pcv3SafArchiveProvider(
    private val platform: Pcv3SafPlatform,
) : Pcv3SafPublisher {
    override fun newCancellation(): Pcv3SafCancellation = platform.newCancellation()

    override fun publish(
        root: Uri,
        manifest: Pcv3SafManifest,
        session: Pcv3SafEntrySession,
        cancellation: Pcv3SafCancellation,
    ): Pcv3SafPublicationResult {
        val normalizedRoot = platformCall { platform.normalizeTreeRoot(root) }
            ?: return Pcv3SafPublicationResult.NEEDS_ABORT
        val rootIdentity = platformCall { platform.documentIdentity(normalizedRoot) }
            ?: return Pcv3SafPublicationResult.NEEDS_ABORT
        val rootAuthority = rootIdentity.authority

        val documents = arrayOfNulls<Uri>(manifest.entries.size)
        val identities = HashSet<Pcv3SafDocumentIdentity>(manifest.entries.size + 1).apply {
            add(rootIdentity)
        }
        manifest.entries.forEachIndexed { index, entry ->
            if (cancellation.isCancelled()) return Pcv3SafPublicationResult.NEEDS_ABORT
            val attempted = safStep { session.attempt(index.toLong()) }
            if (attempted?.kind != "attempted" || attempted.nextIndex != index.toLong()) {
                return Pcv3SafPublicationResult.NEEDS_ABORT
            }
            if (cancellation.isCancelled()) return Pcv3SafPublicationResult.NEEDS_ABORT

            val parent = if (entry.parentIndex == -1L) {
                normalizedRoot
            } else {
                documents[entry.parentIndex.toInt()]
                    ?: return Pcv3SafPublicationResult.NEEDS_ABORT
            }
            val expectedMime = if (entry.isDirectory) PCV3_SAF_DIRECTORY_MIME else PCV3_SAF_FILE_MIME
            val created = platformCall {
                platform.createDocument(parent, expectedMime, entry.name)
            } ?: return Pcv3SafPublicationResult.NEEDS_ABORT
            if (cancellation.isCancelled()) return Pcv3SafPublicationResult.NEEDS_ABORT

            val createdIdentity = platformCall { platform.documentIdentity(created) }
                ?.takeIf { it.authority == rootAuthority }
                ?: return Pcv3SafPublicationResult.NEEDS_ABORT
            if (!identities.add(createdIdentity)) return Pcv3SafPublicationResult.NEEDS_ABORT

            val metadata = platformCall { platform.queryDocument(created, cancellation) }
                ?: return Pcv3SafPublicationResult.NEEDS_ABORT
            if (!metadata.isExactMetadata(
                expectedIdentity = createdIdentity,
                expectedName = entry.name,
                expectedMime = expectedMime,
                directory = entry.isDirectory,
            )) return Pcv3SafPublicationResult.NEEDS_ABORT
            documents[index] = created
            if (cancellation.isCancelled()) return Pcv3SafPublicationResult.NEEDS_ABORT

            if (entry.isDirectory) {
                val acknowledged = safStep { session.ackDirectory(index.toLong()) }
                if (acknowledged?.kind != "ready" || acknowledged.nextIndex != index.toLong() + 1L) {
                    return Pcv3SafPublicationResult.NEEDS_ABORT
                }
            } else if (publishFile(created, index, session, cancellation) != Pcv3SafPublicationResult.READY_TO_FINISH) {
                return Pcv3SafPublicationResult.NEEDS_ABORT
            }
        }
        return Pcv3SafPublicationResult.READY_TO_FINISH
    }

    private fun publishFile(
        document: Uri,
        index: Int,
        session: Pcv3SafEntrySession,
        cancellation: Pcv3SafCancellation,
    ): Pcv3SafPublicationResult {
        val original = platformCall {
            platform.openDocument(document, "w", cancellation)
        } ?: return Pcv3SafPublicationResult.NEEDS_ABORT
        if (cancellation.isCancelled()) {
            original.closeWithFixedError()
            return Pcv3SafPublicationResult.NEEDS_ABORT
        }

        var duplicate: Pcv3SafDuplicateDescriptor? = null
        var detached = false
        var originalSettled = false
        return try {
            duplicate = original.duplicate()
            if (cancellation.isCancelled()) {
                duplicate.closeQuietly()
                originalSettled = true
                original.closeWithError(PCV3_SAF_FIXED_WRITE_ERROR)
                return Pcv3SafPublicationResult.NEEDS_ABORT
            }
            val rawDescriptor = duplicate.detachFd()
            detached = true
            val written = session.writeFd(index.toLong(), rawDescriptor.toLong())
            if (written.kind == "ready" && written.nextIndex == index.toLong() + 1L &&
                !cancellation.isCancelled()
            ) {
                originalSettled = true
                original.close()
                Pcv3SafPublicationResult.READY_TO_FINISH
            } else {
                originalSettled = true
                original.closeWithError(PCV3_SAF_FIXED_WRITE_ERROR)
                Pcv3SafPublicationResult.NEEDS_ABORT
            }
        } catch (_: Exception) {
            if (!detached) duplicate.closeQuietly()
            if (!originalSettled) original.closeWithFixedError()
            Pcv3SafPublicationResult.NEEDS_ABORT
        } catch (_: LinkageError) {
            if (!detached) duplicate.closeQuietly()
            if (!originalSettled) original.closeWithFixedError()
            Pcv3SafPublicationResult.NEEDS_ABORT
        }
    }
}

internal data class Pcv3SafDocumentIdentity(val authority: String, val documentId: String)

private fun Pcv3SafDocumentMetadata.isExactMetadata(
    expectedIdentity: Pcv3SafDocumentIdentity,
    expectedName: String,
    expectedMime: String,
    directory: Boolean,
): Boolean = authority == expectedIdentity.authority &&
    queriedDocumentId == expectedIdentity.documentId &&
    displayName == expectedName &&
    if (directory) {
        mimeType == expectedMime
    } else {
        !mimeType.isNullOrBlank() && mimeType != PCV3_SAF_DIRECTORY_MIME
    }

private inline fun <T> safStep(call: () -> T): T? = try {
    call()
} catch (_: Exception) {
    null
} catch (_: LinkageError) {
    null
}

private inline fun <T> platformCall(call: () -> T): T? = try {
    call()
} catch (_: Exception) {
    null
} catch (_: LinkageError) {
    null
}

private fun Pcv3SafDuplicateDescriptor?.closeQuietly() {
    try {
        this?.close()
    } catch (_: Exception) {
        // The descriptor remains publication-uncertain; no second effect is attempted.
    } catch (_: LinkageError) {
        // The descriptor remains publication-uncertain; no second effect is attempted.
    }
}

private fun Pcv3SafOriginalDescriptor.closeWithFixedError() {
    try {
        closeWithError(PCV3_SAF_FIXED_WRITE_ERROR)
    } catch (_: Exception) {
        // Closing is already uncertain and must remain a terminal Abort.
    } catch (_: LinkageError) {
        // Closing is already uncertain and must remain a terminal Abort.
    }
}

internal class AndroidPcv3SafPlatform(
    private val resolver: ContentResolver,
) : Pcv3SafPlatform {
    override fun newCancellation(): Pcv3SafCancellation = AndroidPcv3SafCancellation()

    override fun normalizeTreeRoot(tree: Uri): Uri? =
        DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))

    override fun documentIdentity(document: Uri): Pcv3SafDocumentIdentity? {
        val authority = document.authority?.takeIf { it.isNotBlank() } ?: return null
        val documentId = DocumentsContract.getDocumentId(document).takeIf { it.isNotBlank() } ?: return null
        return Pcv3SafDocumentIdentity(authority, documentId)
    }

    override fun createDocument(parent: Uri, mimeType: String, displayName: String): Uri? =
        DocumentsContract.createDocument(resolver, parent, mimeType, displayName)

    override fun queryDocument(
        document: Uri,
        cancellation: Pcv3SafCancellation,
    ): Pcv3SafDocumentMetadata? {
        val androidCancellation = cancellation as? AndroidPcv3SafCancellation ?: return null
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
        )
        val cursor = resolver.query(
            document,
            projection,
            null,
            null,
            null,
            androidCancellation.signal,
        ) ?: return null
        return cursor.use {
            if (!it.moveToFirst()) return@use null
            val idColumn = it.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameColumn = it.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            val mimeColumn = it.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
            if (idColumn < 0 || nameColumn < 0 || mimeColumn < 0) return@use null
            val queriedId = it.getString(idColumn)
            val displayName = it.getString(nameColumn)
            val mimeType = it.getString(mimeColumn)
            if (it.moveToNext()) return@use null
            Pcv3SafDocumentMetadata(
                authority = document.authority,
                queriedDocumentId = queriedId,
                uriDocumentId = null,
                displayName = displayName,
                mimeType = mimeType,
            )
        }
    }

    override fun openDocument(
        document: Uri,
        mode: String,
        cancellation: Pcv3SafCancellation,
    ): Pcv3SafOriginalDescriptor? {
        val androidCancellation = cancellation as? AndroidPcv3SafCancellation ?: return null
        return resolver.openFileDescriptor(document, mode, androidCancellation.signal)
            ?.let(::AndroidPcv3SafOriginalDescriptor)
    }
}

internal class AndroidPcv3SafCancellation : Pcv3SafCancellation {
    val signal = CancellationSignal()
    private val cancelled = AtomicBoolean(false)

    override fun isCancelled(): Boolean = cancelled.get()

    override fun cancel() {
        if (cancelled.compareAndSet(false, true)) signal.cancel()
    }
}

private class AndroidPcv3SafOriginalDescriptor(
    private val descriptor: ParcelFileDescriptor,
) : Pcv3SafOriginalDescriptor {
    override fun duplicate(): Pcv3SafDuplicateDescriptor =
        AndroidPcv3SafDuplicateDescriptor(ParcelFileDescriptor.dup(descriptor.fileDescriptor))

    override fun close() = descriptor.close()

    override fun closeWithError(message: String) = descriptor.closeWithError(message)
}

private class AndroidPcv3SafDuplicateDescriptor(
    private val descriptor: ParcelFileDescriptor,
) : Pcv3SafDuplicateDescriptor {
    override fun detachFd(): Int = descriptor.detachFd()

    override fun close() = descriptor.close()
}
