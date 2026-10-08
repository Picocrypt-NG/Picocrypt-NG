package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.content.res.AssetFileDescriptor
import android.database.Cursor
import android.net.Uri
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.IOException
import java.io.FilterInputStream
import java.io.InputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobile.Mobile

internal data class StagingSourceEntry(
    val documentId: String?,
    val name: String?,
    val directory: Boolean,
    val virtual: Boolean,
    val size: Long?,
    val regular: Boolean = true,
)

/** Android IPC boundary; cursors are consumed one row at a time and always closed. */
internal class AndroidStagingSource(private val context: Context) {
    private val resolver = context.contentResolver
    private val signal by lazy { CancellationSignal() }
    private class ActiveSource(val descriptor: AssetFileDescriptor) {
        @Volatile var input: InputStream? = null
        private val closed = AtomicBoolean()

        @Synchronized fun close() {
            if (!closed.compareAndSet(false, true)) return
            try { input?.close() } finally { descriptor.close() }
        }
    }

    private val activeSource = AtomicReference<ActiveSource?>()
    private val uriSizer = AndroidPcv3SafPlatform(resolver)

    fun observation(): Pcv3AndroidResourceObservation? = Pcv3AndroidResourceObservationReader(context).read()
    fun uriWorkingBytes(uri: Uri): Long? = uriSizer.retainedUriWorkingBytes(uri)
    fun treeDocumentId(tree: Uri): String = DocumentsContract.getTreeDocumentId(tree)
    fun documentUri(tree: Uri, documentId: String): Uri = DocumentsContract.buildDocumentUriUsingTree(tree, documentId)

    fun displayName(uri: Uri): String? {
        val cursor = resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null, signal)
            ?: return null
        return cursor.use {
            signal.throwIfCanceled()
            if (!it.moveToFirst()) return@use null
            val name = it.optionalString(OpenableColumns.DISPLAY_NAME)
                ?.takeIf { value -> value.length <= 255 && value.isNotBlank() }
            if (it.moveToNext()) return@use null
            signal.throwIfCanceled()
            name
        }
    }

    fun describe(uri: Uri, includeSize: Boolean = true): StagingSourceEntry {
        val projection = arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        val cursor = resolver.query(uri, projection, null, null, null, signal)
            ?: throw IOException("Source metadata unavailable")
        return cursor.use {
            if (!it.moveToFirst()) throw IOException("Source metadata missing")
            val entry = StagingSourceEntry(null, it.optionalString(OpenableColumns.DISPLAY_NAME), false, false,
                if (includeSize) it.optionalSize() else null)
            if (it.moveToNext()) throw IOException("Ambiguous source metadata")
            entry
        }
    }

    fun forEachChild(tree: Uri, documentId: String, visit: (StagingSourceEntry) -> Unit) {
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, documentId)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_FLAGS,
            DocumentsContract.Document.COLUMN_SIZE,
        )
        val cursor = resolver.query(children, projection, null, null, null, signal)
            ?: throw IOException("Folder metadata unavailable")
        cursor.use {
            val idColumn = it.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            if (idColumn < 0) throw IOException("Document identity unavailable")
            while (it.moveToNext()) {
                signal.throwIfCanceled()
                val id = it.getString(idColumn)?.takeIf(String::isNotEmpty)
                    ?: throw IOException("Document identity missing")
                val flagsColumn = it.getColumnIndex(DocumentsContract.Document.COLUMN_FLAGS)
                val flags = if (flagsColumn >= 0 && !it.isNull(flagsColumn)) it.getLong(flagsColumn) else 0L
                if (flags and DocumentsContract.Document.FLAG_VIRTUAL_DOCUMENT.toLong() != 0L) continue
                val mime = it.optionalString(DocumentsContract.Document.COLUMN_MIME_TYPE)
                val directory = mime == DocumentsContract.Document.MIME_TYPE_DIR
                visit(StagingSourceEntry(
                    id, it.optionalString(DocumentsContract.Document.COLUMN_DISPLAY_NAME),
                    directory, false,
                    if (directory || mime.isNullOrEmpty()) null else it.optionalSize(), !mime.isNullOrEmpty(),
                ))
            }
        }
    }

    fun open(uri: Uri): InputStream {
        val descriptor = resolver.openAssetFileDescriptor(uri, "r", signal)
            ?: throw IOException("Source stream unavailable")
        val owner = ActiveSource(descriptor)
        if (!activeSource.compareAndSet(null, owner)) {
            owner.close()
            throw IOException("Source stream already active")
        }
        try {
            signal.throwIfCanceled()
            val mode = Os.fstat(descriptor.fileDescriptor).st_mode
            val nonblocking = OsConstants.S_ISFIFO(mode) || OsConstants.S_ISSOCK(mode)
            if (nonblocking) {
                // Keep the borrowed number alive across the native call. Closing
                // concurrently could recycle it into an unrelated descriptor.
                synchronized(owner) {
                    Mobile.setInputNonblocking(descriptor.parcelFileDescriptor.fd.toLong())
                }
            }
            // Framework bounded pipe streams skip offsets in their constructor.
            // Keep that work in the cancellation-aware reader owned above.
            val stream = if (nonblocking) ParcelFileDescriptor.AutoCloseInputStream(descriptor.parcelFileDescriptor)
                else descriptor.createInputStream()
            owner.input = stream
            val readiness = arrayOf(StructPollfd().apply {
                fd = descriptor.fileDescriptor
                events = OsConstants.POLLIN.toShort()
            })
            val input = object : FilterInputStream(stream) {
                private var offsetRemaining = if (nonblocking) descriptor.startOffset else 0L
                private var remaining = descriptor.declaredLength

                private fun readReady(buffer: ByteArray, offset: Int, length: Int): Int {
                    while (true) {
                        signal.throwIfCanceled()
                        if (Os.poll(readiness, 100) == 0) continue
                        signal.throwIfCanceled()
                        val count = stream.read(buffer, offset, length)
                        // Android's IoBridge maps EAGAIN on an empty nonblocking
                        // pipe to zero. Another reader may consume ready bytes.
                        if (!nonblocking || count != 0) return count
                    }
                }

                private fun skipOffset() {
                    if (offsetRemaining == 0L) return
                    val scratch = ByteArray(minOf(offsetRemaining, 8192L).toInt())
                    try {
                        while (offsetRemaining > 0) {
                            val count = readReady(scratch, 0, minOf(offsetRemaining, scratch.size.toLong()).toInt())
                            if (count == -1) throw IOException("Source ended before asset offset")
                            offsetRemaining -= count
                        }
                    } finally {
                        scratch.fill(0)
                    }
                }

                override fun read(): Int {
                    val single = ByteArray(1)
                    try {
                        return if (read(single, 0, 1) == -1) -1 else single[0].toInt() and 0xff
                    } finally {
                        single.fill(0)
                    }
                }

                override fun read(buffer: ByteArray): Int = read(buffer, 0, buffer.size)

                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    if (offset < 0 || length < 0 || offset > buffer.size - length) throw IndexOutOfBoundsException()
                    if (length == 0) return 0
                    // A bounded asset's EOF is local, even while its pipe writer
                    // remains open and there is no descriptor readiness event.
                    if (remaining == 0L) return -1
                    skipOffset()
                    val limit = if (remaining < 0) length else minOf(remaining, length.toLong()).toInt()
                    val count = readReady(buffer, offset, limit)
                    if (count > 0 && remaining >= 0) remaining -= count
                    return count
                }
            }
            owner.input = input
            signal.throwIfCanceled()
            return input
        } catch (failure: Throwable) {
            activeSource.compareAndSet(owner, null)
            runCatching { owner.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    fun close(input: InputStream) {
        val owner = activeSource.get()
        if (owner != null && owner.input === input && activeSource.compareAndSet(owner, null)) owner.close()
        else input.close()
    }

    fun cancel() {
        // The descriptor owner exists before stream construction or offset skip.
        // Close first, even if cooperative provider cancellation later stalls.
        try { activeSource.get()?.close() } catch (_: Exception) { }
        try { signal.cancel() } catch (_: Exception) { }
    }

    private fun Cursor.optionalString(column: String): String? {
        val index = getColumnIndex(column)
        return if (index >= 0 && !isNull(index)) getString(index) else null
    }

    private fun Cursor.optionalSize(): Long? {
        val index = getColumnIndex(OpenableColumns.SIZE)
        if (index < 0 || isNull(index)) return null
        return getLong(index).also { if (it < 0) throw IOException("Invalid source size") }
    }
}

/** Keep cancellation ownership alive until provider work and descriptor cleanup settle. */
internal suspend fun <T> AndroidStagingSource.withCancellation(block: suspend () -> T): T = coroutineScope {
    val watcher = launch(start = CoroutineStart.UNDISPATCHED) {
        try {
            awaitCancellation()
        } finally {
            this@withCancellation.cancel()
        }
    }
    try {
        currentCoroutineContext().ensureActive()
        block()
    } finally {
        withContext(NonCancellable) { watcher.cancelAndJoin() }
    }
}

internal suspend fun readKeyfileDisplayName(context: Context, uri: Uri): String? = withContext(Dispatchers.IO) {
    val source = AndroidStagingSource(context)
    source.withCancellation {
        try {
            source.displayName(uri)
        } catch (failure: Exception) {
            currentCoroutineContext().ensureActive()
            null
        }
    }
}
