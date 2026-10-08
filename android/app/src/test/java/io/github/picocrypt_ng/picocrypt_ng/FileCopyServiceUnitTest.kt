package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import io.github.picocrypt_ng.picocrypt_ng.ui.components.dispatchPcv3Selection
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.Runs
import io.mockk.verify
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.createTempDirectory
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class FileCopyServiceUnitTest {
    @Test
    fun legacySavePinsSourceBeforeWaitingForTheProvider() = runTest {
        val root = createTempDirectory("legacy-save-source-").toFile()
        val oldBytes = "output of the operation whose Save was selected".toByteArray()
        val replacementBytes = "private output of a later operation".toByteArray()
        val source = File(root, "output").apply { writeBytes(oldBytes) }
        val destination = File(root, "saved")
        val resolver = mockk<android.content.ContentResolver>()
        val context = mockk<Context> { every { contentResolver } returns resolver }
        val uri = mockk<Uri>()
        val providerEntered = CountDownLatch(1)
        val releaseProvider = CountDownLatch(1)
        every { resolver.openOutputStream(uri) } answers {
            providerEntered.countDown()
            check(releaseProvider.await(5, TimeUnit.SECONDS))
            destination.outputStream()
        }
        try {
            val saving = async(Dispatchers.Default) {
                FileCopyService.saveFileToUri(context, source.path, uri) { true }
            }
            assertTrue(providerEntered.await(5, TimeUnit.SECONDS))
            // A later publication replaces the pathname while the old picker is
            // waiting on its provider. The already selected input must stay pinned.
            assertTrue(source.delete())
            source.writeBytes(replacementBytes)
            releaseProvider.countDown()
            saving.await().getOrThrow()
            assertArrayEquals("A delayed provider must never redirect a Save to later bytes", oldBytes, destination.readBytes())
            assertArrayEquals(replacementBytes, source.readBytes())
        } finally {
            releaseProvider.countDown()
            root.deleteRecursively()
        }
    }

    @Test
    fun legacySaveDoesNotWriteAfterOwnerLossOrCancellationDuringProviderOpen() = runTest {
        for (cancelled in listOf(false, true)) {
            val root = createTempDirectory("legacy-save-revoked-").toFile()
            val replacementBytes = "new output must remain private".toByteArray()
            val source = File(root, "output").apply { writeText("old output") }
            val destination = File(root, "saved")
            val resolver = mockk<android.content.ContentResolver>()
            val context = mockk<Context> {
                every { contentResolver } returns resolver
                every { getString(any()) } returns "Save failed"
            }
            val uri = mockk<Uri>()
            val owned = AtomicBoolean(true)
            val providerEntered = CountDownLatch(1)
            val releaseProvider = CountDownLatch(1)
            var openedOutput: java.io.FileOutputStream? = null
            every { resolver.openOutputStream(uri) } answers {
                providerEntered.countDown()
                check(releaseProvider.await(5, TimeUnit.SECONDS))
                destination.outputStream().also { openedOutput = it }
            }
            try {
                val saving = async(Dispatchers.Default) {
                    FileCopyService.saveFileToUri(context, source.path, uri, owned::get)
                }
                assertTrue(providerEntered.await(5, TimeUnit.SECONDS))
                assertTrue(source.delete())
                source.writeBytes(replacementBytes)
                if (cancelled) saving.cancel() else owned.set(false)
                releaseProvider.countDown()
                if (cancelled) {
                    assertTrue(runCatching { saving.await() }.exceptionOrNull() is CancellationException)
                    saving.join()
                } else {
                    assertTrue(saving.await().exceptionOrNull() is AppError.FileError.SaveFailed)
                }
                assertEquals("No bytes may be sent after revocation (cancelled=$cancelled)", 0L, destination.length())
                assertFalse("The eventual provider descriptor must be closed", requireNotNull(openedOutput).fd.valid())
                assertArrayEquals(replacementBytes, source.readBytes())
            } finally {
                releaseProvider.countDown()
                root.deleteRecursively()
            }
        }
    }

    @Test
    fun ownedDeletionRemovesNestedStagingAndTreatsAbsentAsComplete() = runTest {
        val root = createTempDirectory("owned-cleanup-").toFile()
        val context = mockk<Context> { every { filesDir } returns root }
        val directory = File(root, "picocrypt_files/staging/selection")
        File(directory, "nested/plaintext").apply { parentFile!!.mkdirs(); writeText("private") }
        try {
            assertTrue(FileCopyService.deleteFile(context, directory.path))
            assertFalse("no nested staging may remain after reported cleanup", directory.exists())
            assertTrue("repeated cleanup is already complete", FileCopyService.deleteFile(context, directory.path))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun ownedDeletionRefusesOutsideRootAndDoesNotTraverseLinks() = runTest {
        val root = createTempDirectory("owned-cleanup-").toFile()
        val outside = createTempDirectory("unowned-").toFile()
        val context = mockk<Context> { every { filesDir } returns root }
        val kept = File(outside, "keep").apply { writeText("unowned") }
        val link = File(root, "link")
        Files.createSymbolicLink(link.toPath(), outside.toPath())
        try {
            assertFalse(FileCopyService.deleteFile(context, kept.path))
            assertFalse(FileCopyService.deleteFile(context, File(link, "keep").path))
            assertTrue(FileCopyService.deleteFile(context, link.path))
            assertEquals("unowned", kept.readText())
            assertFalse(FileCopyService.deleteFile(context, root.path))
        } finally {
            root.deleteRecursively()
            outside.deleteRecursively()
        }
    }

    @Test
    fun ownedDeletionReportsFailedUnlinkAndAllowsRetry() = runTest {
        val root = createTempDirectory("owned-cleanup-").toFile()
        val context = mockk<Context> { every { filesDir } returns root }
        val parent = File(root, "blocked").apply { mkdir() }
        val file = File(parent, "plaintext").apply { writeText("private") }
        try {
            check(parent.setWritable(false, false))
            assertFalse("failed unlink must not claim plaintext cleanup", FileCopyService.deleteFile(context, file.path))
            assertTrue(file.exists())
            check(parent.setWritable(true, true))
            assertTrue(FileCopyService.deleteFile(context, file.path))
            assertFalse(file.exists())
        } finally {
            parent.setWritable(true, true)
            root.deleteRecursively()
        }
    }

    @Test
    fun providerCopyBuffersAreWipedAfterSuccessAndReadFailure() = runTest {
        for (keyfile in listOf(false, true)) {
            for (readFailure in listOf(false, true)) {
                var bufferOwner: ByteArray? = null
                val input = object : InputStream() {
                    var reads = 0
                    override fun read(): Int = error("bulk read expected")
                    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                        if (reads++ == 0) {
                            bufferOwner = buffer
                            buffer[offset] = 0x51
                            buffer[offset + 1] = 0x72
                            return 2
                        }
                        if (readFailure) throw IOException("provider read failed")
                        return -1
                    }
                }
                val fixture = singleFileCopyFixture(input)
                try {
                    val result = if (keyfile) FileCopyService.copyKeyfileToInternalStorage(
                        fixture.context, fixture.uri, 0, publisher = JvmAtomicFilePublisher, source = fixture.source,
                    ) else FileCopyService.copyFileToInternalStorage(
                        fixture.context, fixture.uri, "secret.txt", JvmAtomicFilePublisher, {}, {}, fixture.source,
                    )
                    assertEquals(readFailure, result.isFailure)
                    assertTrue("Owned provider buffer must be zero after settlement", requireNotNull(bufferOwner).all { it == 0.toByte() })
                    if (!readFailure) assertArrayEquals(byteArrayOf(0x51, 0x72), File(result.getOrThrow()).readBytes())
                    else assertTrue(fixture.destination.parentFile!!.list().isNullOrEmpty())
                } finally { fixture.filesDir.deleteRecursively() }
            }
        }
    }

    @Test
    fun failedProviderCopyNeverDeletesForeignReplacementAtItsPartialPath() = runTest {
        for (keyfile in listOf(false, true)) {
            lateinit var runtime: File
            var replacement: File? = null
            val input = object : InputStream() {
                override fun read(): Int = error("bulk read expected")
                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    val partial = runtime.listFiles()!!.single { it.name.endsWith(".incomplete") }
                    val retained = File(runtime, "retained-owned-partial")
                    Files.move(partial.toPath(), retained.toPath())
                    partial.writeText("foreign partial replacement")
                    replacement = partial
                    throw IOException("read failed after pathname replacement")
                }
            }
            val fixture = singleFileCopyFixture(input)
            runtime = fixture.destination.parentFile!!
            try {
                val result = if (keyfile) FileCopyService.copyKeyfileToInternalStorage(
                    fixture.context, fixture.uri, 0, publisher = JvmAtomicFilePublisher, source = fixture.source,
                ) else FileCopyService.copyFileToInternalStorage(
                    fixture.context, fixture.uri, "secret.txt", JvmAtomicFilePublisher, {}, {}, fixture.source,
                )
                assertTrue(result.isFailure)
                assertEquals("foreign partial replacement", requireNotNull(replacement).readText())
                assertTrue(File(runtime, "retained-owned-partial").exists())
                assertFalse(File(runtime, if (keyfile) "keyfile_0" else "input_file.txt").exists())
            } finally { fixture.filesDir.deleteRecursively() }
        }
    }

    @Test
    fun copyFileKeepsTheDestinationInvisibleUntilTheCopyIsComplete() = runTest {
        val waitingAfterFirstChunk = CountDownLatch(1)
        val allowInputToFinish = CountDownLatch(1)
        val fixture = singleFileCopyFixture(
            object : InputStream() {
                private var reads = 0

                override fun read(): Int = error("copyTo should use the bulk-read override")

                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    return when (reads++) {
                        0 -> {
                            buffer[offset] = 0x41
                            1
                        }
                        else -> {
                            waitingAfterFirstChunk.countDown()
                            check(allowInputToFinish.await(5, TimeUnit.SECONDS)) {
                                "Test did not release the partial source stream"
                            }
                            -1
                        }
                    }
                }
            },
        )

        try {
            val copy = async(Dispatchers.Default) {
                FileCopyService.copyFileToInternalStorage(
                    context = fixture.context,
                    uri = fixture.uri,
                    originalFileName = "secret.txt",
                    publisher = JvmAtomicFilePublisher,
                    afterAcquire = {},
                    afterPublish = {},
                    source = fixture.source,
                )
            }
            assertTrue(
                "The production copy should pause after writing a partial chunk",
                waitingAfterFirstChunk.await(5, TimeUnit.SECONDS),
            )

            assertFalse("A partial input must never be visible at its final path", fixture.destination.exists())
            val partialFiles = fixture.destination.parentFile!!.listFiles().orEmpty()
                .filter { it.name.endsWith(".incomplete") }
            assertEquals("The in-progress copy should own one temporary file", 1, partialFiles.size)
            assertEquals("The temporary file should contain the first chunk", 1L, partialFiles.single().length())

            allowInputToFinish.countDown()
            val result = copy.await()

            assertTrue("A complete input copy should succeed", result.isSuccess)
            assertEquals(fixture.destination.absolutePath, result.getOrThrow())
            assertArrayEquals(byteArrayOf(0x41), fixture.destination.readBytes())
            assertTrue(
                "A successful copy must remove every temporary file",
                fixture.destination.parentFile!!.listFiles().orEmpty().none { it.name.endsWith(".incomplete") },
            )
        } finally {
            allowInputToFinish.countDown()
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun copyFileCancellationAfterPublicationRemovesTheUnadoptedFinalFile() = runTest {
        val fixture = singleFileCopyFixture(ByteArrayInputStream(byteArrayOf(7, 8, 9)))
        val published = CompletableDeferred<Unit>()

        try {
            val copy = async(Dispatchers.Default) {
                FileCopyService.copyFileToInternalStorage(
                    context = fixture.context,
                    uri = fixture.uri,
                    originalFileName = "secret.txt",
                    publisher = JvmAtomicFilePublisher,
                    afterAcquire = {},
                    afterPublish = {
                        published.complete(Unit)
                        awaitCancellation()
                    },
                    source = fixture.source,
                )
            }
            published.await()
            assertArrayEquals(
                "Only the complete bytes may be visible after atomic publication",
                byteArrayOf(7, 8, 9),
                fixture.destination.readBytes(),
            )

            copy.cancel(CancellationException("cancel before FileCard adoption"))
            try {
                copy.await()
                fail("Cancellation before custody transfer must be rethrown")
            } catch (_: CancellationException) {
                // Expected: the production path must retain cancellation semantics.
            }

            assertFalse("An unadopted final copy must be removed", fixture.destination.exists())
            assertTrue(
                "Cancellation must remove every temporary input",
                fixture.destination.parentFile!!.listFiles().orEmpty().none { it.name.endsWith(".incomplete") },
            )
        } finally {
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun copyFileCancellationDoesNotDeleteAReplacementWithDifferentIdentity() = runTest {
        val fixture = singleFileCopyFixture(ByteArrayInputStream(byteArrayOf(1, 2, 3)))
        val replacementReady = CompletableDeferred<Unit>()
        val replacementBytes = byteArrayOf(9, 8, 7)

        try {
            val copy = async(Dispatchers.Default) {
                FileCopyService.copyFileToInternalStorage(
                    context = fixture.context,
                    uri = fixture.uri,
                    originalFileName = "secret.txt",
                    publisher = JvmAtomicFilePublisher,
                    afterAcquire = {},
                    afterPublish = {
                        val originalIdentity = JvmAtomicFilePublisher.identity(fixture.destination)
                        val escapedOwner = File(fixture.destination.parentFile, "escaped-published-owner")
                        Files.move(fixture.destination.toPath(), escapedOwner.toPath())
                        fixture.destination.writeBytes(replacementBytes)
                        assertNotEquals("Replacement must have an independently distinct identity",
                            originalIdentity, JvmAtomicFilePublisher.identity(fixture.destination))
                        replacementReady.complete(Unit)
                        awaitCancellation()
                    },
                    source = fixture.source,
                )
            }
            replacementReady.await()

            copy.cancel(CancellationException("cancel after pathname replacement"))
            try {
                copy.await()
                fail("Cancellation before custody transfer must be rethrown")
            } catch (_: CancellationException) {
                // Expected.
            }

            assertArrayEquals(
                "Cleanup must not delete bytes owned by a different inode",
                replacementBytes,
                fixture.destination.readBytes(),
            )
            assertArrayEquals(byteArrayOf(1, 2, 3),
                File(fixture.destination.parentFile, "escaped-published-owner").readBytes())
        } finally {
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun copyFileDoesNotReplaceAnExistingFinalPath() = runTest {
        val fixture = singleFileCopyFixture(ByteArrayInputStream(byteArrayOf(4, 5, 6)))
        val existingBytes = byteArrayOf(0x31, 0x32)
        assertTrue("Test setup should create the internal directory", fixture.destination.parentFile!!.mkdirs())
        fixture.destination.writeBytes(existingBytes)

        try {
            val result = FileCopyService.copyFileToInternalStorage(
                context = fixture.context,
                uri = fixture.uri,
                originalFileName = "secret.txt",
                publisher = JvmAtomicFilePublisher,
                afterAcquire = {},
                afterPublish = {},
                source = fixture.source,
            )

            assertTrue("A claimed final path must reject a second owner", result.isFailure)
            assertArrayEquals("The existing owner's bytes must remain unchanged", existingBytes, fixture.destination.readBytes())
            assertTrue(
                "A rejected publication must remove its temporary input",
                fixture.destination.parentFile!!.listFiles().orEmpty().none { it.name.endsWith(".incomplete") },
            )
        } finally {
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun copyFilePublicationErrorAfterMoveRemovesItsFinalButPreservesAReusedStageName() = runTest {
        val fixture = singleFileCopyFixture(ByteArrayInputStream(byteArrayOf(7, 8, 9)))
        var reusedStage: File? = null
        val publisher = object : FileCopyService.AtomicFilePublisher by JvmAtomicFilePublisher {
            override fun publishNoReplace(source: File, target: File, expected: FileCopyService.FileIdentity): InputCopyPublication {
                assertEquals(InputCopyPublication.PUBLISHED, JvmAtomicFilePublisher.publishNoReplace(source, target, expected))
                source.writeText("new owner at old stage name")
                reusedStage = source
                return InputCopyPublication.PUBLISHED_ERROR
            }
        }
        try {
            val result = FileCopyService.copyFileToInternalStorage(
                fixture.context, fixture.uri, "secret.txt", publisher, {},
                { fail("A publication error must never reach the successful handoff") },
                source = fixture.source,
            )
            assertTrue(result.exceptionOrNull() is AppError.FileError.CopyFailed)
            assertFalse("A confirmed moved owner must be removed after its publication error", fixture.destination.exists())
            assertEquals("new owner at old stage name", requireNotNull(reusedStage).readText())
        } finally {
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun copyFileRefusedOrIndeterminatePublicationCannotDeleteASameInodeTarget() = runTest {
        for (publication in listOf(InputCopyPublication.NOT_PUBLISHED, InputCopyPublication.INDETERMINATE)) {
            val bytes = byteArrayOf(7, 8, 9)
            val fixture = singleFileCopyFixture(ByteArrayInputStream(bytes))
            var claimedIdentity: FileCopyService.FileIdentity? = null
            val publisher = object : FileCopyService.AtomicFilePublisher by JvmAtomicFilePublisher {
                override fun publishNoReplace(source: File, target: File, expected: FileCopyService.FileIdentity): InputCopyPublication {
                    // Another owner may already have an alias of the exact source inode.
                    Files.createLink(target.toPath(), source.toPath())
                    claimedIdentity = JvmAtomicFilePublisher.identity(target)
                    return publication
                }
            }
            try {
                val result = FileCopyService.copyFileToInternalStorage(
                    fixture.context, fixture.uri, "secret.txt", publisher, {}, {},
                    source = fixture.source,
                )
                assertTrue("$publication cannot authorize a successful handoff", result.isFailure)
                assertArrayEquals("$publication cannot authorize target deletion", bytes, fixture.destination.readBytes())
                assertEquals(claimedIdentity, JvmAtomicFilePublisher.identity(fixture.destination))
                assertEquals(listOf("input_file.txt"), fixture.destination.parentFile!!.list()!!.toList())
            } finally {
                fixture.filesDir.deleteRecursively()
            }
        }
    }

    @Test
    fun copyFileUnexpectedPublicationExceptionCannotClaimTheTarget() = runTest {
        val bytes = byteArrayOf(7, 8, 9)
        val fixture = singleFileCopyFixture(ByteArrayInputStream(bytes))
        val publisher = object : FileCopyService.AtomicFilePublisher by JvmAtomicFilePublisher {
            override fun publishNoReplace(source: File, target: File, expected: FileCopyService.FileIdentity): InputCopyPublication {
                Files.createLink(target.toPath(), source.toPath())
                throw IOException("native publication disposition unavailable")
            }
        }
        try {
            val result = FileCopyService.copyFileToInternalStorage(
                fixture.context, fixture.uri, "secret.txt", publisher, {}, {},
                source = fixture.source,
            )
            assertTrue(result.isFailure)
            assertArrayEquals("An exception grants no target deletion custody", bytes, fixture.destination.readBytes())
            assertEquals(listOf("input_file.txt"), fixture.destination.parentFile!!.list()!!.toList())
        } finally {
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun copyFileRemovesItsPartialInputWhenTheProviderReadFails() = runTest {
        val readFailure = IOException("provider failed after a plaintext chunk")
        val fixture = singleFileCopyFixture(
            object : InputStream() {
                private var reads = 0

                override fun read(): Int = error("copyTo should use the bulk-read override")

                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    return when (reads++) {
                        0 -> {
                            buffer[offset] = 0x55
                            1
                        }
                        else -> throw readFailure
                    }
                }
            },
        )

        try {
            val result = FileCopyService.copyFileToInternalStorage(
                context = fixture.context,
                uri = fixture.uri,
                originalFileName = "secret.txt",
                publisher = JvmAtomicFilePublisher,
                afterAcquire = {},
                afterPublish = {},
                source = fixture.source,
            )

            assertTrue("The provider read failure must fail the real copy", result.isFailure)
            val error = result.exceptionOrNull()
            assertTrue("The failure should retain the typed app error", error is AppError.FileError.CopyFailed)
            assertEquals(readFailure.message, (error as AppError).technicalMessage)
            assertFalse("A failed copy must not publish a final input", fixture.destination.exists())
            assertTrue(
                "A failed copy must remove every plaintext temporary file",
                fixture.destination.parentFile!!.listFiles().orEmpty().none { it.name.endsWith(".incomplete") },
            )
        } finally {
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun copyFileDropsUnsafeExtensionsInsteadOfUsingThemAsInternalPaths() = runTest {
        val unsafeNames = listOf(
            "report.txt/nested",
            "report.txt\\nested",
            "report.txt/../../escape",
            "report.tx\u0000t",
            "report.tx\nt",
            "report.${"a".repeat(512)}",
        )

        unsafeNames.forEach { originalFileName ->
            val sourceBytes = byteArrayOf(0x21, 0x43)
            val fixture = singleFileCopyFixture(ByteArrayInputStream(sourceBytes))
            val internalDir = fixture.destination.parentFile!!
            val safeDestination = File(internalDir, "input_file")

            try {
                val result = FileCopyService.copyFileToInternalStorage(
                    context = fixture.context,
                    uri = fixture.uri,
                    originalFileName = originalFileName,
                    publisher = JvmAtomicFilePublisher,
                    afterAcquire = {},
                    afterPublish = {},
                    source = fixture.source,
                )

                assertTrue("An unsafe display-name extension must fall back to a safe internal name", result.isSuccess)
                assertEquals(safeDestination.absolutePath, result.getOrThrow())
                assertEquals(internalDir.canonicalFile, safeDestination.canonicalFile.parentFile)
                assertArrayEquals(sourceBytes, safeDestination.readBytes())
                assertEquals(
                    "The untrusted display name must not create a nested or sibling path",
                    listOf("input_file"),
                    internalDir.listFiles().orEmpty().map { it.name }.sorted(),
                )
                assertEquals(
                    "The copy must remain under the one app-private runtime directory",
                    listOf("picocrypt_files"),
                    fixture.filesDir.listFiles().orEmpty().map { it.name }.sorted(),
                )
            } finally {
                fixture.filesDir.deleteRecursively()
            }
        }
    }

    @Test
    fun copyFilePreservesAnOrdinaryAsciiExtension() = runTest {
        val sourceBytes = byteArrayOf(0x50, 0x43, 0x56)
        val fixture = singleFileCopyFixture(ByteArrayInputStream(sourceBytes))

        try {
            val result = FileCopyService.copyFileToInternalStorage(
                context = fixture.context,
                uri = fixture.uri,
                originalFileName = "archive.PCV3",
                publisher = JvmAtomicFilePublisher,
                afterAcquire = {},
                afterPublish = {},
                source = fixture.source,
            )
            val expected = File(fixture.destination.parentFile!!, "input_file.PCV3")

            assertTrue("A compatible extension should still be preserved", result.isSuccess)
            assertEquals(expected.absolutePath, result.getOrThrow())
            assertArrayEquals(sourceBytes, expected.readBytes())
        } finally {
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun copyKeyfileKeepsTheDestinationInvisibleUntilTheCopyIsComplete() = runTest {
        val waitingAfterFirstChunk = CountDownLatch(1)
        val allowInputToFinish = CountDownLatch(1)
        val fixture = keyfileCopyFixture(
            object : InputStream() {
                private var reads = 0

                override fun read(): Int = error("copyTo should use the bulk-read override")

                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    return when (reads++) {
                        0 -> {
                            buffer[offset] = 0x01
                            1
                        }
                        else -> {
                            waitingAfterFirstChunk.countDown()
                            check(allowInputToFinish.await(5, TimeUnit.SECONDS)) {
                                "Test did not release the partial source stream"
                            }
                            -1
                        }
                    }
                }
            },
        )

        try {
            val copy = async(Dispatchers.Default) {
                FileCopyService.copyKeyfileToInternalStorage(
                    fixture.context,
                    fixture.uri,
                    index = 0,
                    source = fixture.source,
                    publisher = JvmAtomicFilePublisher,
                )
            }
            assertTrue(
                "The production copy should pause after writing a partial chunk",
                waitingAfterFirstChunk.await(5, TimeUnit.SECONDS),
            )

            assertFalse("A partial keyfile must never be visible at its final path", fixture.destination.exists())
            val partialFiles = fixture.destination.parentFile!!.listFiles().orEmpty()
                .filter { it.name.endsWith(".incomplete") }
            assertEquals("The in-progress copy should own one temporary file", 1, partialFiles.size)
            assertEquals("The temporary file should contain the first chunk", 1L, partialFiles.single().length())

            allowInputToFinish.countDown()
            val result = copy.await()

            assertTrue("A complete keyfile copy should succeed", result.isSuccess)
            assertEquals(fixture.destination.absolutePath, result.getOrThrow())
            assertArrayEquals(byteArrayOf(1), fixture.destination.readBytes())
            assertTrue(
                "A successful copy must remove every temporary file",
                fixture.destination.parentFile!!.listFiles().orEmpty().none { it.name.endsWith(".incomplete") },
            )
        } finally {
            allowInputToFinish.countDown()
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun copyKeyfileRemovesPartialFilesWhenReadingFails() = runTest {
        val readFailure = IOException("source failed after the first chunk")
        val fixture = keyfileCopyFixture(
            object : InputStream() {
                private var reads = 0

                override fun read(): Int = error("copyTo should use the bulk-read override")

                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    return when (reads++) {
                        0 -> {
                            buffer[offset] = 0x5A
                            1
                        }
                        else -> throw readFailure
                    }
                }
            },
        )

        try {
            val result = FileCopyService.copyKeyfileToInternalStorage(
                fixture.context,
                fixture.uri,
                index = 0,
                source = fixture.source,
                publisher = JvmAtomicFilePublisher,
            )

            assertTrue("The controlled source failure must fail the production copy", result.isFailure)
            val error = result.exceptionOrNull()
            assertTrue("The copy failure should retain the typed app error", error is AppError.FileError.CopyFailed)
            assertEquals(readFailure.message, (error as AppError).technicalMessage)
            assertFalse("A failed copy must not expose a partial keyfile", fixture.destination.exists())
            assertTrue(
                "A failed copy must remove every temporary file",
                fixture.destination.parentFile!!.listFiles().orEmpty().none { it.name.endsWith(".incomplete") },
            )
        } finally {
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun copyKeyfileLeavesNoFileWhenCancelledAfterAllBytesAreRead() = runTest {
        val waitingAtEndOfInput = CountDownLatch(1)
        val allowInputToFinish = CountDownLatch(1)
        val fixture = keyfileCopyFixture(
            object : InputStream() {
                private var reads = 0

                override fun read(): Int = error("copyTo should use the bulk-read override")

                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    return when (reads++) {
                        0 -> {
                            buffer[offset] = 0x33
                            1
                        }
                        else -> {
                            waitingAtEndOfInput.countDown()
                            check(allowInputToFinish.await(5, TimeUnit.SECONDS)) {
                                "Test did not release the source stream"
                            }
                            -1
                        }
                    }
                }
            },
        )

        try {
            val copy = async(Dispatchers.Default) {
                FileCopyService.copyKeyfileToInternalStorage(
                    fixture.context,
                    fixture.uri,
                    index = 0,
                    source = fixture.source,
                    publisher = JvmAtomicFilePublisher,
                )
            }
            assertTrue(
                "The production copy should reach the final blocking read",
                waitingAtEndOfInput.await(5, TimeUnit.SECONDS),
            )

            val cancellation = CancellationException("cancel after the bytes were copied")
            copy.cancel(cancellation)
            allowInputToFinish.countDown()

            try {
                copy.await()
                fail("The cancelled production copy must rethrow CancellationException")
            } catch (actual: CancellationException) {
                assertEquals(cancellation.message, actual.message)
            }

            assertFalse("Cancellation must not leave an unregistered keyfile", fixture.destination.exists())
            assertTrue(
                "Cancellation must remove every temporary keyfile",
                fixture.destination.parentFile!!.listFiles().orEmpty().none { it.name.endsWith(".incomplete") },
            )
        } finally {
            allowInputToFinish.countDown()
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun cancellationAfterPublishRemovesOnlyTheCurrentOwnersTarget() = runTest {
        val fixture = keyfileCopyFixture(ByteArrayInputStream(byteArrayOf(7, 8, 9)))
        val published = CompletableDeferred<Unit>()
        val unrelatedKeyfile = File(fixture.destination.parentFile, "keyfile_1")
        assertTrue("Test setup should create the keyfile directory", unrelatedKeyfile.parentFile!!.mkdirs())
        unrelatedKeyfile.writeBytes(byteArrayOf(4, 5, 6))

        try {
            val copy = async(Dispatchers.Default) {
                FileCopyService.copyKeyfileToInternalStorage(
                    fixture.context,
                    fixture.uri,
                    index = 0,
                    afterAcquire = {},
                    afterPublish = {
                        published.complete(Unit)
                        awaitCancellation()
                    },
                    source = fixture.source,
                    publisher = JvmAtomicFilePublisher,
                )
            }
            published.await()
            assertArrayEquals(
                "The complete file should have been atomically published before cancellation",
                byteArrayOf(7, 8, 9),
                fixture.destination.readBytes(),
            )

            val cancellation = CancellationException("cancel after atomic publish")
            copy.cancel(cancellation)
            try {
                copy.await()
                fail("The post-publish cancellation must be rethrown")
            } catch (actual: CancellationException) {
                assertEquals(cancellation.message, actual.message)
            }

            assertFalse("Post-publish cancellation must remove its own target", fixture.destination.exists())
            assertArrayEquals(
                "Post-publish cleanup must not delete another keyfile owner",
                byteArrayOf(4, 5, 6),
                unrelatedKeyfile.readBytes(),
            )
            assertTrue(
                "Post-publish cleanup must remove its owned temporary path",
                fixture.destination.parentFile!!.listFiles().orEmpty().none { it.name.endsWith(".incomplete") },
            )
        } finally {
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun copyKeyfileDoesNotOverwriteAnExistingOwnedPath() = runTest {
        val fixture = keyfileCopyFixture(ByteArrayInputStream(byteArrayOf(9, 9, 9)))
        val ownedBytes = byteArrayOf(1, 2, 3)
        assertTrue("Test setup should create the keyfile directory", fixture.destination.parentFile!!.mkdirs())
        fixture.destination.writeBytes(ownedBytes)

        try {
            val result = FileCopyService.copyKeyfileToInternalStorage(
                fixture.context,
                fixture.uri,
                index = 0,
                source = fixture.source,
                publisher = JvmAtomicFilePublisher,
            )

            assertTrue("A claimed keyfile slot must reject a second owner", result.isFailure)
            assertArrayEquals("The first owner's bytes must remain unchanged", ownedBytes, fixture.destination.readBytes())
            assertTrue(
                "A rejected copy must not leave a temporary file",
                fixture.destination.parentFile!!.listFiles().orEmpty().none { it.name.endsWith(".incomplete") },
            )
        } finally {
            fixture.filesDir.deleteRecursively()
        }
    }

    @Test
    fun concurrentCopiesCannotBothClaimTheSameKeyfileSlot() = runTest {
        val filesDir = createTempDirectory("picocrypt-concurrent-keyfile-copy").toFile()
        val context = mockk<Context>()
        val resolver = mockk<android.content.ContentResolver>()
        val firstUri = mockk<Uri>()
        val secondUri = mockk<Uri>()
        val firstBytes = byteArrayOf(0x11)
        val secondBytes = byteArrayOf(0x22)
        val firstAcquired = CompletableDeferred<Unit>()
        val allowFirstToCopy = CompletableDeferred<Unit>()
        val events = java.util.concurrent.ConcurrentLinkedQueue<String>()
        every { context.filesDir } returns filesDir
        every { context.contentResolver } returns resolver
        every { context.getString(R.string.error_copy_failed) } returns "Copy failed"
        every { resolver.openInputStream(firstUri) } returns ByteArrayInputStream(firstBytes)
        every { resolver.openInputStream(secondUri) } returns ByteArrayInputStream(secondBytes)

        try {
            val firstCopy = async(Dispatchers.Default) {
                FileCopyService.copyKeyfileToInternalStorage(
                    context = context,
                    uri = firstUri,
                    index = 0,
                    source = stagingSource(firstUri, ByteArrayInputStream(firstBytes)),
                    publisher = JvmAtomicFilePublisher,
                    afterAcquire = {
                        events.add("first acquired")
                        firstAcquired.complete(Unit)
                        allowFirstToCopy.await()
                    },
                    afterPublish = { events.add("first published") },
                )
            }
            firstAcquired.await()
            val secondCopy = async(Dispatchers.Default, start = CoroutineStart.UNDISPATCHED) {
                FileCopyService.copyKeyfileToInternalStorage(
                    context = context,
                    uri = secondUri,
                    index = 0,
                    source = stagingSource(secondUri, ByteArrayInputStream(secondBytes)),
                    publisher = JvmAtomicFilePublisher,
                    afterAcquire = { events.add("second acquired") },
                    afterPublish = { events.add("second published") },
                )
            }
            assertEquals(
                "The contender must suspend before acquiring the first owner's slot",
                listOf("first acquired"),
                events.toList(),
            )

            allowFirstToCopy.complete(Unit)
            val copies = listOf(firstCopy, secondCopy).awaitAll()

            assertEquals(
                "The contender may acquire only after the first file was published",
                listOf("first acquired", "first published", "second acquired"),
                events.toList(),
            )
            assertEquals("Exactly one copy may own keyfile_0", 1, copies.count { it.isSuccess })
            assertEquals("The competing copy must fail instead of overwriting", 1, copies.count { it.isFailure })
            val destination = File(filesDir, "picocrypt_files/keyfile_0")
            assertArrayEquals("The first slot owner's bytes must remain intact", firstBytes, destination.readBytes())
            assertTrue(
                "No temporary file may remain after concurrent copies",
                destination.parentFile!!.listFiles().orEmpty().none { it.name.endsWith(".incomplete") },
            )
        } finally {
            allowFirstToCopy.complete(Unit)
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun pcv3OutputPathIsDedicatedWithoutChangingLegacyOutputNames() {
        val filesDir = createTempDirectory("picocrypt-output-paths").toFile()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir

        try {
            assertEquals(
                File(filesDir, "picocrypt_files/pcv3_retained_output").absolutePath,
                FileCopyService.getPcv3RetainedOutputPath(context),
            )
            assertEquals(
                File(filesDir, "picocrypt_files/output_file.pcv").absolutePath,
                FileCopyService.getOutputFilePath(context, inputFilePath = "ignored", isEncrypt = true),
            )
            assertEquals(
                File(filesDir, "picocrypt_files/output_file").absolutePath,
                FileCopyService.getOutputFilePath(context, inputFilePath = "ignored", isEncrypt = false),
            )
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun pcv3PrivateParentCleanInstallCreatesAndValidatesOnlyTheExistingRuntimeDirectory() = runTest {
        val filesDir = createTempDirectory("picocrypt-pcv3-private-parent").toFile()
        val context = mockk<Context>()
        val filesystem = JvmPcv3FilesystemBoundary()
        every { context.filesDir } returns filesDir

        try {
            val parent = FileCopyService.ensurePcv3PrivateParent(context, filesystem)

            assertEquals(File(filesDir, "picocrypt_files").absoluteFile.normalize(), parent)
            assertTrue(parent!!.isDirectory)
            assertEquals("Clean-install creation must sync the filesDir entry", 1, filesystem.syncs)
            assertFalse("R7c must not invent a second archive parent", File(parent, "pcv3_archive").exists())
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun pcv3PrivateParentRejectsSymlinkAndOpenedIdentityReplacement() = runTest {
        val filesDir = createTempDirectory("picocrypt-pcv3-private-parent-link").toFile()
        val outside = createTempDirectory("picocrypt-pcv3-private-parent-outside").toFile()
        val context = mockk<Context>()
        val parent = File(filesDir, "picocrypt_files")
        every { context.filesDir } returns filesDir

        try {
            Files.createSymbolicLink(parent.toPath(), outside.toPath())
            assertNull(
                FileCopyService.ensurePcv3PrivateParent(context, JvmPcv3FilesystemBoundary()),
            )
            assertTrue(Files.isSymbolicLink(parent.toPath()))

            Files.delete(parent.toPath())
            assertTrue(parent.mkdir())
            val replacementBoundary = JvmPcv3FilesystemBoundary().apply {
                openedDirectoryNode = Pcv3FilesystemNode("replacement", Pcv3FilesystemKind.DIRECTORY)
            }
            assertNull(FileCopyService.ensurePcv3PrivateParent(context, replacementBoundary))
            assertTrue(parent.isDirectory)
        } finally {
            Files.deleteIfExists(parent.toPath())
            filesDir.deleteRecursively()
            outside.deleteRecursively()
        }
    }

    @Test
    fun pcv3DispatchCannotInterleaveWithExclusiveStartupCleanup() = runTest {
        val filesDir = createTempDirectory("picocrypt-pcv3-dispatch-target").toFile()
        val context = mockk<Context>()
        val applicationContext = mockk<Context>()
        val mainViewModel = mockk<MainViewModel>()
        val operationViewModel = mockk<OperationViewModel>(relaxed = true)
        val dedicatedTarget = File(filesDir, "picocrypt_files/pcv3_retained_output").absolutePath
        val retainedCleanupStarted = CompletableDeferred<Unit>()
        val allowRetainedCleanup = CompletableDeferred<Unit>()
        every { context.applicationContext } returns applicationContext
        every { applicationContext.filesDir } returns filesDir
        every { mainViewModel.takePcv3Operation(dedicatedTarget) } returns null

        try {
            StartupCleanup.resetForTests()
            val startup = async {
                StartupCleanup.runBeforeUi(
                    context = applicationContext,
                    restoreReceipt = { Pcv3ReceiptRestore.None },
                    ensurePrivateParent = { File(filesDir, "picocrypt_files") },
                    cleanupJournal = { Pcv3JournalCleanupState.ABSENT },
                    cleanupRetainedOutput = {
                        retainedCleanupStarted.complete(Unit)
                        allowRetainedCleanup.await()
                        true
                    },
                    cleanupTransient = { true },
                )
            }
            retainedCleanupStarted.await()

            dispatchPcv3Selection(context, mainViewModel, operationViewModel)
            verify(exactly = 0) { mainViewModel.takePcv3Operation(any()) }

            allowRetainedCleanup.complete(Unit)
            assertTrue(startup.await())
            dispatchPcv3Selection(context, mainViewModel, operationViewModel)

            verify(exactly = 1) { mainViewModel.takePcv3Operation(dedicatedTarget) }
        } finally {
            allowRetainedCleanup.complete(Unit)
            StartupCleanup.resetForTests()
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun openPcv3OutputDescriptorReturnsCallerOwnedOpaqueDescriptor() = runTest {
        val context = mockk<Context>()
        val resolver = mockk<android.content.ContentResolver>()
        val uri = mockk<Uri>()
        val descriptor = mockk<ParcelFileDescriptor>(relaxed = true)
        every { context.contentResolver } returns resolver
        every { uri.path } throws AssertionError("A SAF URI must never become a filesystem path")
        every { uri.toString() } throws AssertionError("A SAF URI must remain opaque")
        every { resolver.openFileDescriptor(uri, "rwt") } returns descriptor

        val result = FileCopyService.openPcv3OutputDescriptor(context, uri) { true }

        assertSame(descriptor, result.getOrThrow())
        verify(exactly = 1) { resolver.openFileDescriptor(uri, "rwt") }
        verify(exactly = 0) { resolver.openOutputStream(any()) }
        verify(exactly = 0) { descriptor.close() }
    }

    @Test
    fun openPcv3OutputDescriptorCancellationWhileProviderBlocksClosesTheEventualDescriptor() = runTest {
        val context = mockk<Context>()
        val resolver = mockk<android.content.ContentResolver>()
        val uri = mockk<Uri>()
        val descriptor = mockk<ParcelFileDescriptor>(relaxed = true)
        val providerEntered = CountDownLatch(1)
        val allowProviderReturn = CountDownLatch(1)
        val cancellation = CancellationException("cancelled while provider open was blocked")
        var delivered: ParcelFileDescriptor? = null
        every { context.contentResolver } returns resolver
        every { resolver.openFileDescriptor(uri, "rwt") } answers {
            providerEntered.countDown()
            check(allowProviderReturn.await(5, TimeUnit.SECONDS)) {
                "Test did not release the blocked provider open"
            }
            descriptor
        }

        val opening = async(Dispatchers.Default, start = CoroutineStart.UNDISPATCHED) {
            val result = FileCopyService.openPcv3OutputDescriptor(context, uri) { true }
            delivered = result.getOrNull()
            result
        }
        try {
            assertTrue(
                "The public provider call must be in progress before cancellation",
                providerEntered.await(5, TimeUnit.SECONDS),
            )
            opening.cancel(cancellation)
            allowProviderReturn.countDown()
            try {
                opening.await()
                fail("Cancellation before result delivery must reach the caller")
            } catch (actual: CancellationException) {
                assertEquals(
                    "Cleanup must preserve the caller's cancellation reason",
                    cancellation.message,
                    actual.message,
                )
            }

            assertNull("A descriptor opened after cancellation must never reach the caller", delivered)
            verify(exactly = 1) { resolver.openFileDescriptor(uri, "rwt") }
            verify(exactly = 1) { descriptor.close() }
        } finally {
            allowProviderReturn.countDown()
        }
    }

    @Test
    fun unsupportedPcv3ProviderClosesDescriptorBeforeRefusingTransfer() = runTest {
        val context = mockk<Context>()
        val resolver = mockk<android.content.ContentResolver>()
        val uri = mockk<Uri>()
        val descriptor = mockk<ParcelFileDescriptor>(relaxed = true)
        every { context.contentResolver } returns resolver
        every { context.getString(R.string.pcv3_output_provider_unsupported) } returns "Choose another destination"
        every { resolver.openFileDescriptor(uri, "rwt") } returns descriptor
        val result = FileCopyService.openPcv3OutputDescriptor(context, uri) { false }
        assertTrue(result.isFailure)
        assertEquals("PCV3_OUTPUT_PROVIDER_UNSUPPORTED", (result.exceptionOrNull() as AppError).technicalMessage)
        verify(exactly = 1) { descriptor.close() }
        verify(exactly = 0) { descriptor.detachFd() }
    }

    @Test
    fun openPcv3OutputDescriptorReturnsTypedFailureWhenProviderReturnsNull() = runTest {
        val context = mockk<Context>()
        val resolver = mockk<android.content.ContentResolver>()
        val uri = mockk<Uri>()
        every { context.contentResolver } returns resolver
        every { context.getString(R.string.error_save_failed) } returns "Save failed"
        every { resolver.openFileDescriptor(uri, "rwt") } returns null

        val result = FileCopyService.openPcv3OutputDescriptor(context, uri) { true }

        val error = result.exceptionOrNull()
        assertTrue(error is AppError.FileError.SaveFailed)
        assertEquals("PCV3_OUTPUT_DESCRIPTOR_OPEN_FAILED", (error as AppError).technicalMessage)
    }

    @Test
    fun openPcv3OutputDescriptorRedactsProviderExceptionDetails() = runTest {
        val context = mockk<Context>()
        val resolver = mockk<android.content.ContentResolver>()
        val uri = mockk<Uri>()
        val providerDetail = "content://secret.authority/document/42 /provider/private/path"
        every { context.contentResolver } returns resolver
        every { context.getString(R.string.error_save_failed) } returns "Save failed"
        every { resolver.openFileDescriptor(uri, "rwt") } throws IOException(providerDetail)

        val result = FileCopyService.openPcv3OutputDescriptor(context, uri) { true }

        val error = result.exceptionOrNull()
        assertTrue(error is AppError.FileError.SaveFailed)
        error as AppError
        assertEquals("Save failed", error.userMessage)
        assertEquals("PCV3_OUTPUT_DESCRIPTOR_OPEN_FAILED", error.technicalMessage)
        assertFalse(error.userMessage.contains("secret.authority"))
        assertFalse(error.technicalMessage.orEmpty().contains("secret.authority"))
        assertFalse(error.technicalMessage.orEmpty().contains("/provider/private/path"))
    }

    @Test
    fun validatePcv3RecoveryDestinationAcceptsOnlyTheExactBoundedDisplayName() = runTest {
        val context = mockk<Context>()
        val resolver = mockk<android.content.ContentResolver>()
        val uri = mockk<Uri>()
        val cursor = mockk<Cursor>()
        every { context.contentResolver } returns resolver
        every { uri.path } throws AssertionError("A SAF URI must never become a filesystem path")
        every { uri.toString() } throws AssertionError("A SAF URI must remain opaque")
        every {
            resolver.query(
                uri,
                match { it.contentEquals(arrayOf(OpenableColumns.DISPLAY_NAME)) },
                null,
                null,
                null,
            )
        } returns cursor
        every { cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME) } returns 0
        every { cursor.moveToFirst() } returns true
        every { cursor.getString(0) } returns "recovered evidence.pcv3-recovery"
        every { cursor.close() } just Runs

        val result = FileCopyService.validatePcv3RecoveryDestination(context, uri)

        assertTrue(result.isSuccess)
        verify(exactly = 1) { cursor.close() }
        verify(exactly = 0) { resolver.openFileDescriptor(any(), any()) }
    }

    @Test
    fun validatePcv3RecoveryDestinationFailsClosedAndRedactsUntrustedProviderData() = runTest {
        val rejectedNames = listOf<String?>(
            "recovered evidence.PCV3-RECOVERY",
            "recovered evidence.pcv3-recovery.tmp",
            "a".repeat(256 - ".pcv3-recovery".length) + ".pcv3-recovery",
            null,
        )

        rejectedNames.forEachIndexed { index, displayName ->
            val context = mockk<Context>()
            val resolver = mockk<android.content.ContentResolver>()
            val uri = mockk<Uri>()
            val cursor = mockk<Cursor>()
            every { context.contentResolver } returns resolver
            every { context.getString(R.string.error_save_failed) } returns "Save failed"
            every {
                resolver.query(
                    uri,
                    match { it.contentEquals(arrayOf(OpenableColumns.DISPLAY_NAME)) },
                    null,
                    null,
                    null,
                )
            } returns cursor
            every { cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME) } returns 0
            every { cursor.moveToFirst() } returns true
            every { cursor.getString(0) } returns displayName
            every { cursor.close() } just Runs

            val result = FileCopyService.validatePcv3RecoveryDestination(context, uri)

            val error = result.exceptionOrNull()
            assertTrue("rejected case $index must retain the typed save error", error is AppError.FileError.SaveFailed)
            assertEquals("PCV3_RECOVERY_DESTINATION_NAME_INVALID", (error as AppError).technicalMessage)
            assertFalse(error.userMessage.contains("recovered evidence"))
            assertFalse(error.technicalMessage.orEmpty().contains("recovered evidence"))
            verify(exactly = 1) { cursor.close() }
            verify(exactly = 0) { resolver.openFileDescriptor(any(), any()) }
        }

        val providerDetail = "content://private.authority/root /provider/private/path"
        val context = mockk<Context>()
        val resolver = mockk<android.content.ContentResolver>()
        val uri = mockk<Uri>()
        every { context.contentResolver } returns resolver
        every { context.getString(R.string.error_save_failed) } returns "Save failed"
        every { resolver.query(uri, any(), null, null, null) } throws IOException(providerDetail)

        val result = FileCopyService.validatePcv3RecoveryDestination(context, uri)

        val error = result.exceptionOrNull()
        assertTrue(error is AppError.FileError.SaveFailed)
        error as AppError
        assertEquals("PCV3_RECOVERY_DESTINATION_NAME_INVALID", error.technicalMessage)
        assertFalse(error.userMessage.contains("private.authority"))
        assertFalse(error.technicalMessage.orEmpty().contains("private.authority"))
        assertFalse(error.technicalMessage.orEmpty().contains("/provider/private/path"))
        verify(exactly = 0) { resolver.openFileDescriptor(any(), any()) }
    }

    @Test
    fun cleanupPcv3RetainedOutputRemovesOnlyTheExactRegularTarget() = runTest {
        val filesDir = createTempDirectory("picocrypt-pcv3-retained-cleanup").toFile()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val retained = File(FileCopyService.getPcv3RetainedOutputPath(context))
        val legacyOutput = File(filesDir, "picocrypt_files/output_file")
        val unknown = File(filesDir, "picocrypt_files/pcv3_retained_output.backup")

        try {
            assertTrue(retained.parentFile!!.mkdirs())
            retained.writeText("clean retained plaintext")
            legacyOutput.writeText("legacy owner")
            unknown.writeText("different owner")

            val result = FileCopyService.cleanupPcv3RetainedOutputAtStartup(
                context,
                JvmAtomicFilePublisher,
            )

            assertTrue("The exact clean retained output should be removed", result)
            assertFalse(retained.exists())
            assertEquals("legacy owner", legacyOutput.readText())
            assertEquals("different owner", unknown.readText())
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupPcv3RetainedOutputRejectsUnexpectedTargetTypesWithoutFollowingThem() = runTest {
        val filesDir = createTempDirectory("picocrypt-pcv3-retained-types").toFile()
        val outsideDir = createTempDirectory("picocrypt-pcv3-retained-outside").toFile()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val retained = File(FileCopyService.getPcv3RetainedOutputPath(context))
        val outside = File(outsideDir, "foreign-plaintext").apply { writeText("must remain") }

        try {
            assertTrue(retained.parentFile!!.mkdirs())
            Files.createSymbolicLink(retained.toPath(), outside.toPath())

            assertFalse(
                FileCopyService.cleanupPcv3RetainedOutputAtStartup(context, JvmAtomicFilePublisher),
            )
            assertTrue("An unexpected symlink entry must remain for explicit recovery", Files.isSymbolicLink(retained.toPath()))
            assertEquals("must remain", outside.readText())

            Files.delete(retained.toPath())
            assertTrue(retained.mkdir())
            File(retained, "nested").writeText("not an owned regular file")

            assertFalse(
                FileCopyService.cleanupPcv3RetainedOutputAtStartup(context, JvmAtomicFilePublisher),
            )
            assertEquals("not an owned regular file", File(retained, "nested").readText())
        } finally {
            if (Files.isSymbolicLink(retained.toPath())) {
                Files.deleteIfExists(retained.toPath())
            } else {
                retained.deleteRecursively()
            }
            filesDir.deleteRecursively()
            outsideDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupPcv3RetainedOutputRejectsCanonicalParentMismatch() = runTest {
        val filesDir = createTempDirectory("picocrypt-pcv3-retained-root").toFile()
        val outsideDir = createTempDirectory("picocrypt-pcv3-retained-root-outside").toFile()
        val internalLink = File(filesDir, "picocrypt_files")
        val outsideRetained = File(outsideDir, "pcv3_retained_output").apply {
            writeText("foreign target")
        }
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        Files.createSymbolicLink(internalLink.toPath(), outsideDir.toPath())

        try {
            assertFalse(
                FileCopyService.cleanupPcv3RetainedOutputAtStartup(context, JvmAtomicFilePublisher),
            )
            assertEquals("foreign target", outsideRetained.readText())
            assertTrue(Files.isSymbolicLink(internalLink.toPath()))
        } finally {
            Files.deleteIfExists(internalLink.toPath())
            filesDir.deleteRecursively()
            outsideDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupPcv3RetainedOutputPreservesAReplacementWhoseIdentityChanged() = runTest {
        val filesDir = createTempDirectory("picocrypt-pcv3-retained-replacement").toFile()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val retained = File(FileCopyService.getPcv3RetainedOutputPath(context))
        assertTrue(retained.parentFile!!.mkdirs())
        retained.writeText("initial owner")
        var identityReads = 0
        val replacingPublisher = object : FileCopyService.AtomicFilePublisher {
            override fun identity(file: File): FileCopyService.FileIdentity? {
                identityReads++
                if (identityReads == 2) {
                    val originalIdentity = JvmAtomicFilePublisher.identity(file)
                    val escapedOwner = File(file.parentFile, "escaped-retained-owner")
                    Files.move(file.toPath(), escapedOwner.toPath())
                    file.writeText("replacement owner")
                    assertNotEquals("Replacement must have an independently distinct identity",
                        originalIdentity, JvmAtomicFilePublisher.identity(file))
                }
                return JvmAtomicFilePublisher.identity(file)
            }

            override fun publishNoReplace(source: File, target: File, expected: FileCopyService.FileIdentity) =
                JvmAtomicFilePublisher.publishNoReplace(source, target, expected)
        }

        try {
            assertFalse(
                FileCopyService.cleanupPcv3RetainedOutputAtStartup(context, replacingPublisher),
            )
            assertEquals("replacement owner", retained.readText())
            assertEquals("initial owner", File(retained.parentFile, "escaped-retained-owner").readText())
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupPcv3RetainedOutputNeverRecursesIntoATypeReplacement() = runTest {
        val filesDir = createTempDirectory("picocrypt-pcv3-retained-type-replacement").toFile()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val retained = File(FileCopyService.getPcv3RetainedOutputPath(context))
        assertTrue(retained.parentFile!!.mkdirs())
        retained.writeText("initial owner")
        var identityReads = 0
        val replacingPublisher = object : FileCopyService.AtomicFilePublisher {
            override fun identity(file: File): FileCopyService.FileIdentity? {
                identityReads++
                if (identityReads == 2) {
                    assertTrue("Test replacement should remove the original inode", file.delete())
                    assertTrue("Test replacement should become a directory", file.mkdir())
                    File(file, "foreign-child").writeText("must remain")
                }
                return JvmAtomicFilePublisher.identity(file)
            }

            override fun publishNoReplace(source: File, target: File, expected: FileCopyService.FileIdentity) =
                JvmAtomicFilePublisher.publishNoReplace(source, target, expected)
        }

        try {
            assertFalse(
                FileCopyService.cleanupPcv3RetainedOutputAtStartup(context, replacingPublisher),
            )
            assertEquals("must remain", File(retained, "foreign-child").readText())
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupPcv3RetainedOutputFailsClosedWhenExactDeletionFails() = runTest {
        val filesDir = createTempDirectory("picocrypt-pcv3-retained-delete-failure").toFile()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val retained = File(FileCopyService.getPcv3RetainedOutputPath(context))
        assertTrue(retained.parentFile!!.mkdirs())
        retained.writeText("must remain on ambiguous deletion")

        try {
            assertTrue(
                "Test setup must make the retained target undeletable",
                retained.parentFile!!.setWritable(false, false),
            )

            assertFalse(
                FileCopyService.cleanupPcv3RetainedOutputAtStartup(context, JvmAtomicFilePublisher),
            )
            assertEquals("must remain on ambiguous deletion", retained.readText())
        } finally {
            retained.parentFile!!.setWritable(true, false)
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupStartupTransientFiles_removesOwnedCopiesButPreservesRetainedOutput() = runTest {
        val filesDir = createTempDirectory("picocrypt-startup-cleanup").toFile()
        val internalDir = File(filesDir, "picocrypt_files")
        val stagingPlaintext = File(internalDir, "staging/folder/plaintext.txt")
        val input = File(internalDir, "input_file.pcv")
        val keyfile = File(internalDir, "keyfile_0")
        val incomplete = File(internalDir, "input_abcd.incomplete")
        val goStage = File(internalDir, ".picocrypt-stage")
        val retainedLegacyOutput = File(internalDir, "output_file")
        val retainedEncryptedOutput = File(internalDir, "output_file.pcv")
        val retainedDirectory = File(internalDir, "pcv3-retained")
        val retainedTreeOutput = File(retainedDirectory, "output")
        val retainedPcv3Output = File(internalDir, "pcv3_retained_output")
        val unknown = File(internalDir, "future-owned-entry")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir

        try {
            assertTrue(stagingPlaintext.parentFile!!.mkdirs())
            stagingPlaintext.writeText("stale staged plaintext")
            input.writeText("stale input copy")
            keyfile.writeText("stale keyfile copy")
            incomplete.writeText("partial copy")
            goStage.writeText("unpublished Go stage")
            retainedLegacyOutput.writeText("uncertain plaintext output")
            retainedEncryptedOutput.writeText("uncertain encrypted output")
            assertTrue(retainedDirectory.mkdir())
            retainedTreeOutput.writeText("unknown retained tree output")
            retainedPcv3Output.writeText("PCV3 retained output")
            unknown.writeText("unknown owner")

            val result = FileCopyService.cleanupStartupTransientFiles(context)

            assertTrue("All proven transient copies should be removed", result)
            assertFalse(stagingPlaintext.exists())
            assertFalse(File(internalDir, "staging").exists())
            assertFalse(input.exists())
            assertFalse(keyfile.exists())
            assertFalse(incomplete.exists())
            assertEquals("unpublished Go stage", goStage.readText())
            assertEquals("uncertain plaintext output", retainedLegacyOutput.readText())
            assertEquals("uncertain encrypted output", retainedEncryptedOutput.readText())
            assertEquals("unknown retained tree output", retainedTreeOutput.readText())
            assertEquals("PCV3 retained output", retainedPcv3Output.readText())
            assertEquals("unknown owner", unknown.readText())
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupStartupTransientFiles_failsClosedForOwnedNameWithUnexpectedType() = runTest {
        val filesDir = createTempDirectory("picocrypt-startup-cleanup-type").toFile()
        val internalDir = File(filesDir, "picocrypt_files")
        val malformedInput = File(internalDir, "input_file.pcv")
        val nested = File(malformedInput, "must-remain")
        val retainedOutput = File(internalDir, "output_file")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir

        try {
            assertTrue(malformedInput.mkdirs())
            nested.writeText("not a proven input file")
            retainedOutput.writeText("uncertain plaintext output")

            val result = FileCopyService.cleanupStartupTransientFiles(context)

            assertFalse("An unexpected entry type must not be reported as safely cleaned", result)
            assertEquals("not a proven input file", nested.readText())
            assertEquals("uncertain plaintext output", retainedOutput.readText())
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupAllFiles_reportsFailureWhenInternalDirectoryCannotBeListed() = runTest {
        val filesDir = createTempDirectory("picocrypt-files-dir").toFile()
        val internalDir = File(filesDir, "picocrypt_files")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir

        assertTrue("Internal directory should be created for test setup", internalDir.mkdirs())

        try {
            assertTrue(
                "Test setup should remove read permission from the internal directory",
                internalDir.setReadable(false, false),
            )
            assertTrue(
                "Test setup should remove execute permission from the internal directory",
                internalDir.setExecutable(false, false),
            )

            val result = FileCopyService.cleanupAllFiles(context)

            assertFalse("Cleanup must fail loud when existing staged files cannot be listed", result)
        } finally {
            internalDir.setReadable(true, false)
            internalDir.setExecutable(true, false)
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupAllFiles_preservesJournalStageTempAndRetainedNamesOwnedByPcv3() = runTest {
        val filesDir = createTempDirectory("picocrypt-cleanup-all-pcv3").toFile()
        val internalDir = File(filesDir, "picocrypt_files")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        assertTrue(internalDir.mkdirs())
        val protected = listOf(
            File(internalDir, ".picocrypt-pcv3-stage.journal"),
            File(internalDir, ".picocrypt-pcv3-stage-private"),
            File(internalDir, ".picocrypt-pcv3-journal-tmp-private"),
            File(internalDir, "pcv3_retained_output"),
        )
        protected.forEachIndexed { index, file -> file.writeText("private-$index") }
        File(internalDir, "legacy-transient").writeText("delete me")

        try {
            assertTrue(FileCopyService.cleanupAllFiles(context))
            protected.forEachIndexed { index, file ->
                assertEquals("private-$index", file.readText())
            }
            assertFalse(File(internalDir, "legacy-transient").exists())
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupAllFiles_unlinksNestedSymlinkWithoutDeletingOutsideData() = runTest {
        val filesDir = createTempDirectory("picocrypt-cleanup-all-link").toFile()
        val outsideDir = createTempDirectory("picocrypt-cleanup-all-outside").toFile()
        val internalDir = File(filesDir, "picocrypt_files")
        val stagingDir = File(internalDir, "staging")
        val outsideFile = File(outsideDir, "foreign.txt")
        val outsideBytes = "must remain outside app storage".toByteArray()
        val link = File(stagingDir, "outside-link")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir

        try {
            assertTrue(stagingDir.mkdirs())
            File(stagingDir, "plaintext.txt").writeText("stale plaintext")
            outsideFile.writeBytes(outsideBytes)
            Files.createSymbolicLink(link.toPath(), outsideDir.toPath())

            val result = FileCopyService.cleanupAllFiles(context)

            assertTrue("Startup cleanup must remove its real app-private tree", result)
            assertTrue("The runtime directory itself remains available", internalDir.isDirectory)
            assertTrue("All runtime entries must be gone", internalDir.listFiles().orEmpty().isEmpty())
            assertTrue("Cleanup must not remove the symlink target", outsideDir.isDirectory)
            assertArrayEquals(
                "Cleanup must preserve outside bytes exactly",
                outsideBytes,
                outsideFile.readBytes(),
            )
        } finally {
            Files.deleteIfExists(link.toPath())
            filesDir.deleteRecursively()
            outsideDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupKeyfiles_reportsFailureWhenInternalPathIsAFile() = runTest {
        val filesDir = createTempDirectory("picocrypt-keyfile-cleanup-path").toFile()
        val internalPath = File(filesDir, "picocrypt_files")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        internalPath.writeBytes(byteArrayOf(1))

        try {
            val result = FileCopyService.cleanupKeyfiles(context)

            assertFalse("Cleanup must fail when its internal path is not a directory", result)
            assertTrue("A non-directory internal path must not be reported as removed", internalPath.exists())
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupKeyfiles_reportsFailureWhenInternalDirectoryCannotBeListed() = runTest {
        val filesDir = createTempDirectory("picocrypt-keyfile-cleanup-unlistable").toFile()
        val internalDir = File(filesDir, "picocrypt_files")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        assertTrue("Internal directory should be created for test setup", internalDir.mkdirs())
        File(internalDir, "keyfile_0").writeBytes(byteArrayOf(1))

        try {
            assertTrue(
                "Test setup should remove read permission from the internal directory",
                internalDir.setReadable(false, false),
            )
            assertTrue(
                "Test setup should remove execute permission from the internal directory",
                internalDir.setExecutable(false, false),
            )
            assertNull(
                "Test setup must make the existing directory unlistable",
                internalDir.listFiles(),
            )

            val result = FileCopyService.cleanupKeyfiles(context)

            assertFalse("Cleanup must fail loud when keyfiles cannot be listed", result)
        } finally {
            internalDir.setReadable(true, false)
            internalDir.setExecutable(true, false)
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupKeyfiles_reportsFailureForMatchingDirectory() = runTest {
        val filesDir = createTempDirectory("picocrypt-keyfile-cleanup-entry").toFile()
        val internalDir = File(filesDir, "picocrypt_files")
        val matchingDirectory = File(internalDir, "keyfile_0")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        assertTrue("Matching directory should be created for test setup", matchingDirectory.mkdirs())

        try {
            val result = FileCopyService.cleanupKeyfiles(context)

            assertFalse("Cleanup must fail when a keyfile path is not a regular file", result)
            assertTrue("Cleanup must not claim the matching directory was removed", matchingDirectory.exists())
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupKeyfiles_rejectsLiveInternalDirectorySymlinkWithoutDeletingTarget() = runTest {
        val filesDir = createTempDirectory("picocrypt-keyfile-cleanup-root").toFile()
        val outsideDir = createTempDirectory("picocrypt-keyfile-cleanup-outside").toFile()
        val internalLink = File(filesDir, "picocrypt_files")
        val outsideKeyfile = File(outsideDir, "keyfile_0").apply { writeBytes(byteArrayOf(1)) }
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        Files.createSymbolicLink(internalLink.toPath(), outsideDir.toPath())

        try {
            val result = FileCopyService.cleanupKeyfiles(context)

            assertFalse("Cleanup must reject a symlinked internal root", result)
            assertTrue("Cleanup must not delete a keyfile outside app storage", outsideKeyfile.exists())
            assertTrue(
                "The rejected root symlink must remain visible",
                Files.isSymbolicLink(internalLink.toPath()),
            )
        } finally {
            Files.deleteIfExists(internalLink.toPath())
            filesDir.deleteRecursively()
            outsideDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupKeyfiles_rejectsDanglingInternalDirectorySymlink() = runTest {
        val filesDir = createTempDirectory("picocrypt-keyfile-cleanup-dangling").toFile()
        val internalLink = File(filesDir, "picocrypt_files")
        val missingTarget = File(filesDir, "missing-target")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        Files.createSymbolicLink(internalLink.toPath(), missingTarget.toPath())

        try {
            val result = FileCopyService.cleanupKeyfiles(context)

            assertFalse("Cleanup must fail loud for a dangling internal root symlink", result)
            assertTrue(
                "The dangling root symlink must not be mistaken for an absent path",
                Files.isSymbolicLink(internalLink.toPath()),
            )
        } finally {
            Files.deleteIfExists(internalLink.toPath())
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupOperationFilesBeforeStart_preservesEveryGoOwnedStageLikeEntry() = runTest {
        val filesDir = createTempDirectory("picocrypt-operation-cleanup").toFile()
        val outsideDir = createTempDirectory("picocrypt-operation-cleanup-outside").toFile()
        val internalDir = File(filesDir, "picocrypt_files")
        val stageResidue = File(internalDir, ".picocrypt-owned-stage")
        val prefixLookalike = File(internalDir, ".picocrypt_stage")
        val embeddedLookalike = File(internalDir, "backup.picocrypt-owned-stage")
        val matchingDirectory = File(internalDir, ".picocrypt-directory")
        val outsideTarget = File(outsideDir, "outside-target")
        val matchingSymlink = File(internalDir, ".picocrypt-symlink")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        assertTrue("Internal runtime directory should be created", internalDir.mkdirs())
        stageResidue.writeBytes(byteArrayOf(1, 2, 3))
        prefixLookalike.writeBytes(byteArrayOf(4))
        embeddedLookalike.writeBytes(byteArrayOf(5))
        assertTrue("Matching directory should be created", matchingDirectory.mkdir())
        outsideTarget.writeBytes(byteArrayOf(6, 7))
        Files.createSymbolicLink(matchingSymlink.toPath(), outsideTarget.toPath())

        try {
            val result = FileCopyService.cleanupOperationFilesBeforeStart(context)

            assertTrue("Unrelated legacy cleanup may complete without claiming Go stages", result)
            assertArrayEquals(byteArrayOf(1, 2, 3), stageResidue.readBytes())
            assertTrue("A prefix lookalike must be preserved", prefixLookalike.exists())
            assertTrue("An embedded prefix lookalike must be preserved", embeddedLookalike.exists())
            assertTrue("A matching directory must not be treated as a Go stage file", matchingDirectory.isDirectory)
            assertTrue("A matching symlink must remain untouched", Files.isSymbolicLink(matchingSymlink.toPath()))
            assertArrayEquals(
                "Cleanup must not follow a matching symlink outside app runtime storage",
                byteArrayOf(6, 7),
                outsideTarget.readBytes(),
            )
        } finally {
            Files.deleteIfExists(matchingSymlink.toPath())
            filesDir.deleteRecursively()
            outsideDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupOperationFilesBeforeStart_propagatesIncompleteCleanupFailure() = runTest {
        val filesDir = createTempDirectory("picocrypt-incomplete-cleanup-failure").toFile()
        val internalDir = File(filesDir, "picocrypt_files")
        val staleIncomplete = File(internalDir, "foreign-output.incomplete")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        assertTrue("Internal runtime directory should be created", internalDir.mkdirs())
        staleIncomplete.writeBytes(byteArrayOf(1))

        try {
            assertTrue(
                "Test setup should make the runtime directory read-only",
                internalDir.setWritable(false, false),
            )

            val result = FileCopyService.cleanupOperationFilesBeforeStart(context)

            assertFalse("A failed incomplete-file deletion must fail the aggregate cleanup", result)
            assertTrue("The undeletable incomplete file should demonstrate the real failure", staleIncomplete.exists())
        } finally {
            internalDir.setWritable(true, false)
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupOperationFilesBeforeStart_neverClaimsGoStageDeletionAuthority() = runTest {
        val filesDir = createTempDirectory("picocrypt-stage-cleanup-failure").toFile()
        val internalDir = File(filesDir, "picocrypt_files")
        val staleStage = File(internalDir, ".picocrypt-undeletable-stage")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        assertTrue("Internal runtime directory should be created", internalDir.mkdirs())
        staleStage.writeBytes(byteArrayOf(1))

        try {
            val result = FileCopyService.cleanupOperationFilesBeforeStart(context)

            assertTrue("The Kotlin cleanup result must not depend on deleting a Go-owned stage", result)
            assertArrayEquals(byteArrayOf(1), staleStage.readBytes())
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun cleanupOperationFilesBeforeStart_rejectsSymlinkedInternalDirectory() = runTest {
        val filesDir = createTempDirectory("picocrypt-operation-cleanup-root").toFile()
        val outsideDir = createTempDirectory("picocrypt-operation-cleanup-root-outside").toFile()
        val internalLink = File(filesDir, "picocrypt_files")
        val outsideResidue = File(outsideDir, ".picocrypt-outside-stage").apply {
            writeBytes(byteArrayOf(9))
        }
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        Files.createSymbolicLink(internalLink.toPath(), outsideDir.toPath())

        try {
            val result = FileCopyService.cleanupOperationFilesBeforeStart(context)

            assertFalse("Cleanup must reject a symlinked internal runtime root", result)
            assertArrayEquals(
                "A rejected runtime root must not remove data outside app storage",
                byteArrayOf(9),
                outsideResidue.readBytes(),
            )
            assertTrue("The rejected root symlink must remain", Files.isSymbolicLink(internalLink.toPath()))
        } finally {
            Files.deleteIfExists(internalLink.toPath())
            filesDir.deleteRecursively()
            outsideDir.deleteRecursively()
        }
    }

    private fun stagingSource(uri: Uri, input: InputStream): AndroidStagingSource {
        val source = mockk<AndroidStagingSource>()
        every { source.open(uri) } returns input
        every { source.close(input) } answers { input.close() }
        every { source.cancel() } answers { input.close() }
        return source
    }

    private fun keyfileCopyFixture(input: InputStream): KeyfileCopyFixture {
        val filesDir = createTempDirectory("picocrypt-keyfile-copy").toFile()
        val context = mockk<Context>()
        val uri = mockk<Uri>()
        val resolver = mockk<android.content.ContentResolver>()
        every { context.filesDir } returns filesDir
        every { context.contentResolver } returns resolver
        every { context.getString(R.string.error_copy_failed) } returns "Copy failed"
        every { resolver.openInputStream(uri) } returns input

        val internalDir = File(filesDir, "picocrypt_files")
        return KeyfileCopyFixture(
            context = context,
            uri = uri,
            filesDir = filesDir,
            source = stagingSource(uri, input),
            destination = File(internalDir, "keyfile_0"),
        )
    }

    private fun singleFileCopyFixture(input: InputStream): SingleFileCopyFixture {
        val filesDir = createTempDirectory("picocrypt-single-file-copy").toFile()
        val context = mockk<Context>()
        val uri = mockk<Uri>()
        val resolver = mockk<android.content.ContentResolver>()
        every { context.filesDir } returns filesDir
        every { context.contentResolver } returns resolver
        every { context.getString(R.string.error_copy_failed) } returns "Copy failed"
        every { resolver.openInputStream(uri) } returns input

        val internalDir = File(filesDir, "picocrypt_files")
        return SingleFileCopyFixture(
            context = context,
            uri = uri,
            filesDir = filesDir,
            source = stagingSource(uri, input),
            destination = File(internalDir, "input_file.txt"),
        )
    }

    private data class KeyfileCopyFixture(
        val context: Context,
        val uri: Uri,
        val filesDir: File,
        val source: AndroidStagingSource,
        val destination: File,
    )

    private data class SingleFileCopyFixture(
        val context: Context,
        val uri: Uri,
        val filesDir: File,
        val source: AndroidStagingSource,
        val destination: File,
    )

    private class JvmPcv3FilesystemBoundary : Pcv3FilesystemBoundary {
        var syncs = 0
        var openedDirectoryNode: Pcv3FilesystemNode? = null

        override fun lstat(file: File): Pcv3FilesystemNode? {
            val path = file.toPath()
            if (!Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return null
            val attributes = Files.readAttributes(
                path,
                java.nio.file.attribute.BasicFileAttributes::class.java,
                java.nio.file.LinkOption.NOFOLLOW_LINKS,
            )
            val kind = when {
                attributes.isRegularFile -> Pcv3FilesystemKind.REGULAR
                attributes.isDirectory -> Pcv3FilesystemKind.DIRECTORY
                else -> Pcv3FilesystemKind.OTHER
            }
            return Pcv3FilesystemNode(attributes.fileKey().toString(), kind)
        }

        override fun openedFileNode(file: File, descriptor: FileDescriptor): Pcv3FilesystemNode? =
            lstat(file)

        override fun syncFile(descriptor: FileDescriptor) = Unit

        override fun createDirectory(directory: File) {
            Files.createDirectory(directory.toPath())
        }

        override fun openDirectoryNoFollow(directory: File): Pcv3DirectoryHandle {
            val opened = openedDirectoryNode ?: lstat(directory)
                ?: throw IOException("directory missing")
            return object : Pcv3DirectoryHandle {
                override fun node(): Pcv3FilesystemNode = opened

                override fun sync() {
                    syncs++
                }

                override fun close() = Unit
            }
        }
    }

    private object JvmAtomicFilePublisher : FileCopyService.AtomicFilePublisher {
        override fun identity(file: File): FileCopyService.FileIdentity? {
            val path = file.toPath()
            if (!Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return null
            check(Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                "Owned test path is not a regular file"
            }
            return FileCopyService.FileIdentity(
                device = Files.getAttribute(path, "unix:dev", java.nio.file.LinkOption.NOFOLLOW_LINKS) as Long,
                inode = Files.getAttribute(path, "unix:ino", java.nio.file.LinkOption.NOFOLLOW_LINKS) as Long,
            )
        }

        override fun publishNoReplace(source: File, target: File, expected: FileCopyService.FileIdentity): InputCopyPublication {
            if (identity(source) != expected) return InputCopyPublication.NOT_PUBLISHED
            try {
                Files.createLink(target.toPath(), source.toPath())
            } catch (_: java.nio.file.FileAlreadyExistsException) {
                return InputCopyPublication.NOT_PUBLISHED
            }
            Files.delete(source.toPath())
            return InputCopyPublication.PUBLISHED
        }
    }
}
