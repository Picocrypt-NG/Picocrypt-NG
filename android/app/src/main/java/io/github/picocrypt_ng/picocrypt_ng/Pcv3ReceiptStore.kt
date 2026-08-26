package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.os.Build
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.core.util.AtomicFile
import java.io.File
import java.io.FileDescriptor
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import kotlin.coroutines.cancellation.CancellationException

internal sealed interface ReceiptCustody {
    data object None : ReceiptCustody
    data class Exact(val receipt: String) : ReceiptCustody
    data object Unknown : ReceiptCustody
}

/** Startup accepts exact bytes only together with the actual restored projection. */
internal sealed interface Pcv3ReceiptRestore {
    val custody: ReceiptCustody

    data object None : Pcv3ReceiptRestore {
        override val custody: ReceiptCustody = ReceiptCustody.None
    }

    data class Exact(
        override val custody: ReceiptCustody.Exact,
        val presentation: Pcv3Presentation.Restored,
    ) : Pcv3ReceiptRestore

    data object Unknown : Pcv3ReceiptRestore {
        override val custody: ReceiptCustody = ReceiptCustody.Unknown
    }
}

internal enum class Pcv3FilesystemKind {
    REGULAR,
    DIRECTORY,
    OTHER,
}

internal data class Pcv3FilesystemNode(
    val identity: String,
    val kind: Pcv3FilesystemKind,
)

internal interface Pcv3DirectoryHandle {
    fun node(): Pcv3FilesystemNode
    fun sync()
    fun close()
}

/** Small injectable boundary; Android production is always descriptor-backed. */
internal interface Pcv3FilesystemBoundary {
    fun lstat(file: File): Pcv3FilesystemNode?
    fun openedFileNode(file: File, descriptor: FileDescriptor): Pcv3FilesystemNode?
    fun syncFile(descriptor: FileDescriptor)
    fun createDirectory(directory: File)
    fun openDirectoryNoFollow(directory: File): Pcv3DirectoryHandle
}

internal object AndroidPcv3FilesystemBoundary : Pcv3FilesystemBoundary {
    override fun lstat(file: File): Pcv3FilesystemNode? {
        val stat = try {
            Os.lstat(file.absolutePath)
        } catch (error: ErrnoException) {
            if (error.errno == OsConstants.ENOENT) return null
            throw error
        }
        return stat.st_mode.toPcv3Node(stat.st_dev, stat.st_ino)
    }

    override fun openedFileNode(file: File, descriptor: FileDescriptor): Pcv3FilesystemNode {
        val stat = Os.fstat(descriptor)
        return stat.st_mode.toPcv3Node(stat.st_dev, stat.st_ino)
    }

    override fun syncFile(descriptor: FileDescriptor) {
        Os.fsync(descriptor)
    }

    override fun createDirectory(directory: File) {
        Os.mkdir(directory.absolutePath, 0b111_000_000)
    }

    override fun openDirectoryNoFollow(directory: File): Pcv3DirectoryHandle {
        var flags = OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            flags = flags or OsConstants.O_CLOEXEC
        }
        val descriptor = Os.open(directory.absolutePath, flags, 0)
        return object : Pcv3DirectoryHandle {
            override fun node(): Pcv3FilesystemNode {
                val stat = Os.fstat(descriptor)
                return stat.st_mode.toPcv3Node(stat.st_dev, stat.st_ino)
            }

            override fun sync() {
                Os.fsync(descriptor)
            }

            override fun close() {
                Os.close(descriptor)
            }
        }
    }

    private fun Int.toPcv3Node(device: Long, inode: Long): Pcv3FilesystemNode {
        val kind = when {
            OsConstants.S_ISREG(this) -> Pcv3FilesystemKind.REGULAR
            OsConstants.S_ISDIR(this) -> Pcv3FilesystemKind.DIRECTORY
            else -> Pcv3FilesystemKind.OTHER
        }
        return Pcv3FilesystemNode("$device:$inode", kind)
    }
}

/**
 * Holds the monotonic runtime custody state around one active/terminal receipt.
 * The state becomes Unknown before an effect, so cancellation cannot leave a
 * caller believing that either the old or desired receipt is durable.
 */
internal class Pcv3ReceiptCustodian(
    private val file: File,
    initial: ReceiptCustody,
    private val filesystem: Pcv3FilesystemBoundary = AndroidPcv3FilesystemBoundary,
) {
    var custody: ReceiptCustody = initial
        private set

    fun transition(desiredReceipt: String?): ReceiptCustody {
        val current = custody
        if (current === ReceiptCustody.Unknown) return current
        custody = ReceiptCustody.Unknown
        val transitioned = Pcv3ReceiptStore.transition(file, current, desiredReceipt, filesystem)
        custody = transitioned
        return transitioned
    }
}

internal object Pcv3ReceiptStore {
    private const val RECEIPT_FILE_NAME = "pcv3-deny-only.receipt"
    private const val MAX_RECEIPT_BYTES = 4_096

    private sealed interface DiskReceipt {
        data object None : DiskReceipt
        data class Exact(val receipt: String) : DiskReceipt
        data object Unknown : DiskReceipt
    }

    fun receiptFile(context: Context): File = File(context.filesDir, RECEIPT_FILE_NAME)

    fun save(context: Context, receipt: String): Boolean = save(receiptFile(context), receipt)

    internal fun save(
        file: File,
        receipt: String,
        filesystem: Pcv3FilesystemBoundary = AndroidPcv3FilesystemBoundary,
    ): Boolean = try {
        val current = readDiskReceipt(file, filesystem, syncFile = false).toCustody()
        if (current === ReceiptCustody.Unknown) return false
        transition(file, current, receipt, filesystem) == ReceiptCustody.Exact(receipt)
    } catch (error: CancellationException) {
        throw error
    } catch (_: Exception) {
        false
    } catch (_: LinkageError) {
        false
    }

    suspend fun restore(
        context: Context,
        restoreReceipt: suspend (String) -> Result<Pcv3Presentation>,
    ): Pcv3ReceiptRestore = restore(receiptFile(context), AndroidPcv3FilesystemBoundary, restoreReceipt)

    internal suspend fun restore(
        file: File,
        filesystem: Pcv3FilesystemBoundary = AndroidPcv3FilesystemBoundary,
        restoreReceipt: suspend (String) -> Result<Pcv3Presentation>,
    ): Pcv3ReceiptRestore {
        val disk = try {
            readDiskReceipt(file, filesystem, syncFile = false)
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            return Pcv3ReceiptRestore.Unknown
        } catch (_: LinkageError) {
            return Pcv3ReceiptRestore.Unknown
        }
        if (disk === DiskReceipt.None) return Pcv3ReceiptRestore.None
        val receipt = (disk as? DiskReceipt.Exact)?.receipt ?: return Pcv3ReceiptRestore.Unknown
        val restored = try {
            restoreReceipt(receipt).getOrNull()
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            null
        } catch (_: LinkageError) {
            null
        }
        return if (restored is Pcv3Presentation.Restored &&
            restored.snapshot.restoredReceipt == receipt
        ) {
            Pcv3ReceiptRestore.Exact(ReceiptCustody.Exact(receipt), restored)
        } else {
            Pcv3ReceiptRestore.Unknown
        }
    }

    fun clear(context: Context): Boolean = clear(receiptFile(context))

    internal fun clear(
        file: File,
        filesystem: Pcv3FilesystemBoundary = AndroidPcv3FilesystemBoundary,
    ): Boolean = try {
        val current = readDiskReceipt(file, filesystem, syncFile = false).toCustody()
        if (current === ReceiptCustody.Unknown) return false
        transition(file, current, null, filesystem) === ReceiptCustody.None
    } catch (error: CancellationException) {
        throw error
    } catch (_: Exception) {
        false
    } catch (_: LinkageError) {
        false
    }

    internal fun transition(
        file: File,
        current: ReceiptCustody,
        desiredReceipt: String?,
        filesystem: Pcv3FilesystemBoundary = AndroidPcv3FilesystemBoundary,
    ): ReceiptCustody {
        if (current === ReceiptCustody.Unknown) return current
        return try {
            val actual = readDiskReceipt(file, filesystem, syncFile = false).toCustody()
            if (actual != current) return ReceiptCustody.Unknown

            if (desiredReceipt == null) {
                val parent = file.parentFile ?: return ReceiptCustody.Unknown
                if (current === ReceiptCustody.None) {
                    return if (atomicPaths(file).all { filesystem.lstat(it) == null } &&
                        verifyPcv3Directory(parent, filesystem, sync = true)
                    ) {
                        ReceiptCustody.None
                    } else {
                        ReceiptCustody.Unknown
                    }
                }
                AtomicFile(file).delete()
                if (atomicPaths(file).any { filesystem.lstat(it) != null } ||
                    !verifyPcv3Directory(parent, filesystem, sync = true)
                ) {
                    return ReceiptCustody.Unknown
                }
                return ReceiptCustody.None
            }

            val encoded = encodeReceipt(desiredReceipt) ?: return ReceiptCustody.Unknown
            if (current == ReceiptCustody.Exact(desiredReceipt)) {
                val exact = readDiskReceipt(file, filesystem, syncFile = true)
                if (exact != DiskReceipt.Exact(desiredReceipt) ||
                    !verifyPcv3Directory(file.parentFile ?: return ReceiptCustody.Unknown, filesystem, sync = true)
                ) {
                    return ReceiptCustody.Unknown
                }
                return current
            }

            val atomicFile = AtomicFile(file)
            val output = atomicFile.startWrite()
            try {
                output.write(encoded)
                atomicFile.finishWrite(output)
            } catch (error: Throwable) {
                try {
                    atomicFile.failWrite(output)
                } catch (rollback: Throwable) {
                    error.addSuppressed(rollback)
                }
                throw error
            }

            val exact = readDiskReceipt(file, filesystem, syncFile = true)
            val parent = file.parentFile ?: return ReceiptCustody.Unknown
            if (exact != DiskReceipt.Exact(desiredReceipt) ||
                !verifyPcv3Directory(parent, filesystem, sync = true) ||
                readDiskReceipt(file, filesystem, syncFile = false) != exact
            ) {
                ReceiptCustody.Unknown
            } else {
                ReceiptCustody.Exact(desiredReceipt)
            }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            ReceiptCustody.Unknown
        } catch (_: LinkageError) {
            ReceiptCustody.Unknown
        }
    }

    private fun readDiskReceipt(
        file: File,
        filesystem: Pcv3FilesystemBoundary,
        syncFile: Boolean,
    ): DiskReceipt {
        val parent = file.parentFile ?: return DiskReceipt.Unknown
        if (!verifyPcv3Directory(parent, filesystem, sync = false)) return DiskReceipt.Unknown

        val base = filesystem.lstat(file)
        if (atomicPaths(file).drop(1).any { filesystem.lstat(it) != null }) return DiskReceipt.Unknown
        if (base == null) return DiskReceipt.None
        if (base.kind != Pcv3FilesystemKind.REGULAR) return DiskReceipt.Unknown

        val encoded = AtomicFile(file).openRead().use { input ->
            val opened = filesystem.openedFileNode(file, input.fd)
            if (opened != base || opened.kind != Pcv3FilesystemKind.REGULAR) return DiskReceipt.Unknown
            if (syncFile) filesystem.syncFile(input.fd)

            val output = ByteArray(MAX_RECEIPT_BYTES + 1)
            var total = 0
            while (total < output.size) {
                val read = input.read(output, total, output.size - total)
                if (read < 0) break
                if (read == 0) continue
                total += read
            }
            if (total == 0 || total > MAX_RECEIPT_BYTES || input.read() >= 0) {
                return DiskReceipt.Unknown
            }
            output.copyOf(total)
        }
        if (filesystem.lstat(file) != base ||
            atomicPaths(file).drop(1).any { filesystem.lstat(it) != null }
        ) {
            return DiskReceipt.Unknown
        }
        val receipt = decodeUtf8(encoded) ?: return DiskReceipt.Unknown
        if (encodeReceipt(receipt)?.contentEquals(encoded) != true) return DiskReceipt.Unknown
        return DiskReceipt.Exact(receipt)
    }

    private fun DiskReceipt.toCustody(): ReceiptCustody = when (this) {
        DiskReceipt.None -> ReceiptCustody.None
        is DiskReceipt.Exact -> ReceiptCustody.Exact(receipt)
        DiskReceipt.Unknown -> ReceiptCustody.Unknown
    }

    private fun encodeReceipt(receipt: String): ByteArray? {
        if (!receipt.all { it.code in 0x20..0x7e }) return null
        return receipt.toByteArray(Charsets.UTF_8).takeIf { it.isNotEmpty() && it.size <= MAX_RECEIPT_BYTES }
    }

    private fun atomicPaths(file: File): List<File> = listOf(
        file,
        File(file.path + ".new"),
        File(file.path + ".bak"),
    )

    private fun decodeUtf8(encoded: ByteArray): String? = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(encoded))
            .toString()
    } catch (_: Exception) {
        null
    }
}

internal fun verifyPcv3Directory(
    directory: File,
    filesystem: Pcv3FilesystemBoundary,
    sync: Boolean,
): Boolean {
    val expected = filesystem.lstat(directory) ?: return false
    if (expected.kind != Pcv3FilesystemKind.DIRECTORY) return false
    val handle = filesystem.openDirectoryNoFollow(directory)
    var pending: Throwable? = null
    var verified = false
    try {
        if (handle.node() == expected) {
            if (sync) handle.sync()
            verified = filesystem.lstat(directory) == expected
        }
    } catch (error: Throwable) {
        pending = error
    }
    try {
        handle.close()
    } catch (error: Throwable) {
        if (pending == null) pending = error else pending.addSuppressed(error)
    }
    pending?.let { throw it }
    return verified
}
