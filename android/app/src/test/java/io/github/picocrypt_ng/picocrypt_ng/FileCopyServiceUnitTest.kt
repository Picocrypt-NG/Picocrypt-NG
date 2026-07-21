package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import io.mockk.every
import io.mockk.mockk
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
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
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class FileCopyServiceUnitTest {
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
            destination = File(internalDir, "keyfile_0"),
        )
    }

    private data class KeyfileCopyFixture(
        val context: Context,
        val uri: Uri,
        val filesDir: File,
        val destination: File,
    )
}
