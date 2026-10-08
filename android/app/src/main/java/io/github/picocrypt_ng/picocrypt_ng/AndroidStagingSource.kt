package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.CancellationSignal
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.atomic.AtomicReference

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
    private val activeInput = AtomicReference<InputStream?>()
    private val uriSizer = AndroidPcv3SafPlatform(resolver)

    fun observation(): Pcv3AndroidResourceObservation? = Pcv3AndroidResourceObservationReader(context).read()
    fun uriWorkingBytes(uri: Uri): Long? = uriSizer.retainedUriWorkingBytes(uri)
    fun treeDocumentId(tree: Uri): String = DocumentsContract.getTreeDocumentId(tree)
    fun documentUri(tree: Uri, documentId: String): Uri = DocumentsContract.buildDocumentUriUsingTree(tree, documentId)

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
        val input = try {
            descriptor.createInputStream()
        } catch (failure: Throwable) {
            runCatching { descriptor.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
        if (!activeInput.compareAndSet(null, input)) {
            input.close()
            throw IOException("Source stream already active")
        }
        if (signal.isCanceled) {
            close(input)
            signal.throwIfCanceled()
        }
        return input
    }

    fun close(input: InputStream) {
        activeInput.compareAndSet(input, null)
        input.close()
    }

    fun cancel() {
        // Closing the framework stream interrupts an active descriptor read;
        // the copy owner still waits for that reader before deleting staging.
        try { signal.cancel() } catch (_: Exception) { }
        try { activeInput.get()?.close() } catch (_: Exception) { }
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
