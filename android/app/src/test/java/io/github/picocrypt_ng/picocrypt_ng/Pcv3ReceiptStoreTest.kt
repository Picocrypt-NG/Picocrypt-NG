package io.github.picocrypt_ng.picocrypt_ng

import java.io.File
import java.io.FileDescriptor
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.BasicFileAttributes
import kotlin.coroutines.cancellation.CancellationException
import kotlin.io.path.createTempDirectory
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class Pcv3ReceiptStoreTest {
    @Test
    fun `durable receipt restores only with the actual Go-owned deny-only presentation`() = runTest {
        withReceiptFile { receiptFile, filesystem ->
            val receipt = validReceipt("active")
            var restoredInput: String? = null

            assertTrue(Pcv3ReceiptStore.save(receiptFile, receipt, filesystem))
            val restored = Pcv3ReceiptStore.restore(receiptFile, filesystem) { input ->
                restoredInput = input
                Result.success(restoredPresentation(input))
            }

            val exact = restored as Pcv3ReceiptRestore.Exact
            assertEquals(receipt, exact.custody.receipt)
            assertEquals(receipt, exact.presentation.snapshot.restoredReceipt)
            assertEquals(receipt, restoredInput)
            assertArrayEquals(receipt.toByteArray(Charsets.US_ASCII), receiptFile.readBytes())
        }
    }

    @Test
    fun `bytes without an actual restored presentation remain unknown`() = runTest {
        withReceiptFile { receiptFile, filesystem ->
            val receipt = validReceipt("active")
            assertTrue(Pcv3ReceiptStore.save(receiptFile, receipt, filesystem))

            val failed = Pcv3ReceiptStore.restore(receiptFile, filesystem) {
                Result.failure(Pcv3BridgeFailure("PCV3_RECEIPT_INVALID"))
            }
            val live = Pcv3ReceiptStore.restore(receiptFile, filesystem) {
                Result.success(livePresentation(it))
            }

            assertSame(ReceiptCustody.Unknown, failed.custody)
            assertSame(ReceiptCustody.Unknown, live.custody)
            assertArrayEquals(
                "A failed projection must preserve the sole warning bytes",
                receipt.toByteArray(Charsets.US_ASCII),
                receiptFile.readBytes(),
            )
        }
    }

    @Test
    fun `runtime transition replaces and clears only exact durable custody`() = runTest {
        withReceiptFile { receiptFile, filesystem ->
            val active = validReceipt("active")
            val terminal = validReceipt("terminal")
            val custodian = Pcv3ReceiptCustodian(
                file = receiptFile,
                initial = ReceiptCustody.None,
                filesystem = filesystem,
            )

            assertEquals(ReceiptCustody.Exact(active), custodian.transition(active))
            assertArrayEquals(active.toByteArray(Charsets.US_ASCII), receiptFile.readBytes())
            val activeIdentity = filesystem.lstat(receiptFile)
            assertEquals(ReceiptCustody.Exact(active), custodian.transition(active))
            assertEquals(
                "Persisting the same exact bytes must not replace the receipt",
                activeIdentity,
                filesystem.lstat(receiptFile),
            )
            assertEquals(ReceiptCustody.Exact(terminal), custodian.transition(terminal))
            assertArrayEquals(terminal.toByteArray(Charsets.US_ASCII), receiptFile.readBytes())
            assertSame(ReceiptCustody.None, custodian.transition(null))
            assertFalse(receiptFile.exists())
            assertFalse(File(receiptFile.path + ".new").exists())
            assertFalse(File(receiptFile.path + ".bak").exists())
        }
    }

    @Test
    fun `cancellation leaves custody sticky unknown and rethrows the identical exception`() = runTest {
        withReceiptFile { receiptFile, filesystem ->
            val cancellation = CancellationException("receipt parent sync cancelled")
            filesystem.directorySyncFailure = cancellation
            val custodian = Pcv3ReceiptCustodian(
                file = receiptFile,
                initial = ReceiptCustody.None,
                filesystem = filesystem,
            )

            try {
                custodian.transition(validReceipt("active"))
                fail("The receipt owner must observe transition cancellation")
            } catch (actual: CancellationException) {
                assertSame(cancellation, actual)
            }

            assertSame(ReceiptCustody.Unknown, custodian.custody)
            filesystem.directorySyncFailure = null
            assertSame(
                "Unknown custody must never be inferred back to exact from on-disk bytes",
                ReceiptCustody.Unknown,
                custodian.transition(validReceipt("terminal")),
            )
        }
    }

    @Test
    fun `readback mismatch and parent sync uncertainty cannot become exact`() = runTest {
        listOf<(TestFilesystem) -> Unit>(
            { filesystem ->
                filesystem.onOpenedFile = { file -> file.writeText("different bytes") }
            },
            { filesystem -> filesystem.fileSyncFailure = java.io.IOException("file fsync failed") },
            { filesystem -> filesystem.directorySyncFailure = java.io.IOException("fsync failed") },
            { filesystem -> filesystem.directorySyncFailure = NoSuchMethodError("stale Os boundary") },
        ).forEachIndexed { index, configure ->
            withReceiptFile("pcv3-receipt-uncertain-$index") { receiptFile, filesystem ->
                configure(filesystem)
                val custodian = Pcv3ReceiptCustodian(
                    file = receiptFile,
                    initial = ReceiptCustody.None,
                    filesystem = filesystem,
                )

                assertSame(ReceiptCustody.Unknown, custodian.transition(validReceipt("active")))
                assertSame(ReceiptCustody.Unknown, custodian.custody)
            }
        }
    }

    @Test
    fun `clearing already absent custody still requires durable parent absence`() = runTest {
        withReceiptFile { receiptFile, filesystem ->
            filesystem.directorySyncFailure = java.io.IOException("parent fsync failed")
            val custodian = Pcv3ReceiptCustodian(
                file = receiptFile,
                initial = ReceiptCustody.None,
                filesystem = filesystem,
            )

            assertSame(ReceiptCustody.Unknown, custodian.transition(null))
            assertSame(ReceiptCustody.Unknown, custodian.custody)
        }
    }

    @Test
    fun `sidecars malformed bytes and oversized bytes are unknown rather than absent`() = runTest {
        listOf<(File) -> Unit>(
            { receiptFile -> File(receiptFile.path + ".new").writeText("interrupted") },
            { receiptFile -> File(receiptFile.path + ".bak").writeText("backup") },
            { receiptFile -> receiptFile.writeBytes(byteArrayOf(0xC3.toByte(), 0x28)) },
            { receiptFile -> receiptFile.writeBytes(ByteArray(4_097) { 'x'.code.toByte() }) },
        ).forEachIndexed { index, arrange ->
            withReceiptFile("pcv3-receipt-invalid-$index") { receiptFile, filesystem ->
                arrange(receiptFile)
                var restoreCalls = 0

                val restored = Pcv3ReceiptStore.restore(receiptFile, filesystem) {
                    restoreCalls++
                    Result.success(restoredPresentation(it))
                }

                assertSame(ReceiptCustody.Unknown, restored.custody)
                assertEquals(0, restoreCalls)
            }
        }
    }

    @Test
    fun `missing receipt is none but a symlinked receipt is unknown and never read`() = runTest {
        withReceiptFile { receiptFile, filesystem ->
            var restoreCalls = 0
            assertSame(
                ReceiptCustody.None,
                Pcv3ReceiptStore.restore(receiptFile, filesystem) {
                    restoreCalls++
                    Result.success(restoredPresentation(it))
                }.custody,
            )
            assertEquals(0, restoreCalls)

            val outside = File(receiptFile.parentFile, "outside-receipt").apply {
                writeText(validReceipt("outside"))
            }
            Files.createSymbolicLink(receiptFile.toPath(), outside.toPath())

            assertSame(
                ReceiptCustody.Unknown,
                Pcv3ReceiptStore.restore(receiptFile, filesystem) {
                    restoreCalls++
                    Result.success(restoredPresentation(it))
                }.custody,
            )
            assertEquals(0, restoreCalls)
            assertTrue(Files.isSymbolicLink(receiptFile.toPath()))
            assertEquals(validReceipt("outside"), outside.readText())
        }
    }

    @Test
    fun `compatibility bool caller cannot report success from unknown sidecar custody`() = runTest {
        withReceiptFile { receiptFile, filesystem ->
            val sidecar = File(receiptFile.path + ".new").apply { writeText("ambiguous") }

            assertFalse(Pcv3ReceiptStore.save(receiptFile, validReceipt("terminal"), filesystem))
            assertFalse(Pcv3ReceiptStore.clear(receiptFile, filesystem))
            assertEquals("ambiguous", sidecar.readText())
        }
    }

    private suspend fun withReceiptFile(
        prefix: String = "pcv3-receipt-store",
        block: suspend (File, TestFilesystem) -> Unit,
    ) {
        val directory = createTempDirectory(prefix).toFile()
        try {
            block(File(directory, "deny-only.receipt"), TestFilesystem())
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun validReceipt(id: String): String =
        """{"version":1,"receiptID":"r_$id","operationID":"op_1700000000000000000_7"}"""

    private fun restoredPresentation(receipt: String) = Pcv3Presentation.Restored(
        snapshot = snapshot(receipt),
        operationId = "op_1700000000000000000_7",
        generation = 1,
        receiptId = "r_restored",
    )

    private fun livePresentation(receipt: String) = Pcv3Presentation.Live(
        snapshot = snapshot(receipt),
        operationId = "op_1700000000000000000_7",
        generation = 1,
        operationHandle = object : Pcv3OperationCapability {
            override val id = "op_1700000000000000000_7"
            override fun snapshot() = error("not called")
            override fun consent(): Pcv3ConsentCapability? = null
            override fun archive(): Pcv3ArchiveCapability? = null
            override fun cancel() = error("not called")
            override fun release() = error("not called")
        },
        consentHandle = null,
        archiveHandle = null,
        consent = null,
    )

    private fun snapshot(receipt: String) = Pcv3SnapshotView(
        statusCode = "none",
        statusArgs = emptyList(),
        semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
        publication = Pcv3Publication(
            attempted = true,
            state = "published-durability-uncertain",
            stage = "directory-sync",
            code = "PCV3_PUBLICATION_DURABILITY_UNCERTAIN",
        ),
        forceProvenance = "verified",
        d1BootstrapProvenance = "matching",
        detailStage = "metadata",
        diagnostic = "none",
        completionClass = "durability-uncertain",
        resultArgs = emptyList(),
        warnings = listOf("durability-uncertain"),
        archivePending = false,
        restoredReceipt = receipt,
    )

    private class TestFilesystem : Pcv3FilesystemBoundary {
        var fileSyncFailure: Throwable? = null
        var directorySyncFailure: Throwable? = null
        var onOpenedFile: (File) -> Unit = {}

        override fun lstat(file: File): Pcv3FilesystemNode? {
            if (!Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS)) return null
            val attributes = Files.readAttributes(
                file.toPath(),
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            val kind = when {
                attributes.isRegularFile -> Pcv3FilesystemKind.REGULAR
                attributes.isDirectory -> Pcv3FilesystemKind.DIRECTORY
                else -> Pcv3FilesystemKind.OTHER
            }
            return Pcv3FilesystemNode(attributes.fileKey().toString(), kind)
        }

        override fun openedFileNode(file: File, descriptor: FileDescriptor): Pcv3FilesystemNode? {
            onOpenedFile(file)
            return lstat(file)
        }

        override fun syncFile(descriptor: FileDescriptor) {
            fileSyncFailure?.let { throw it }
        }

        override fun createDirectory(directory: File) {
            Files.createDirectory(directory.toPath())
        }

        override fun openDirectoryNoFollow(directory: File): Pcv3DirectoryHandle {
            val opened = lstat(directory) ?: throw java.io.IOException("directory missing")
            return object : Pcv3DirectoryHandle {
                override fun node(): Pcv3FilesystemNode = opened

                override fun sync() {
                    directorySyncFailure?.let { throw it }
                }

                override fun close() = Unit
            }
        }
    }
}
