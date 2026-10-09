package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.content.ContextWrapper
import android.os.Bundle
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProviderCopyBoundaryTest {
    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun inputRefusesActualBytesBeyondFreshDiskBudget() = diskBudgetRefusal(false)

    @Test
    fun keyfileRefusesActualBytesBeyondFreshDiskBudget() = diskBudgetRefusal(true)

    private fun diskBudgetRefusal(keyfile: Boolean) = runBlocking {
        run {
            provider("reset")
            val root = File(context.filesDir, "copy-budget-${if (keyfile) "key" else "input"}").apply { mkdirs() }
            val runtime = File(root, "picocrypt_files").apply { mkdirs() }
            val sentinel = File(runtime, "foreign").apply { writeText("unrelated bytes") }
            val budgetRoot = object : File(root.path) {
                override fun getUsableSpace(): Long = StagingService.SPACE_MARGIN_BYTES + 65536 -
                    runtime.listFiles().orEmpty().filter { it.name != "foreign" }.sumOf { it.length() }
            }
            val limited = object : ContextWrapper(context) { override fun getFilesDir(): File = budgetRoot }
            try {
                val result = if (keyfile) FileCopyService.copyKeyfileToInternalStorage(limited, CopyBoundaryProvider.URI, 0)
                    else FileCopyService.copyFileToInternalStorage(limited, CopyBoundaryProvider.URI, "plain.txt")
                assertTrue("Provider actual bytes must refuse before exhausting headroom (keyfile=$keyfile)", result.isFailure)
                assertEquals(listOf("foreign"), runtime.list()!!.toList())
                assertEquals("unrelated bytes", sentinel.readText())
                assertTrue(provider("state").getBoolean("sourcePreserved"))
            } finally { root.deleteRecursively(); provider("cleanup") }
        }
    }

    @Test
    fun inputCancelsRealPipeReadWithoutProviderEof() = cancelPipeRead(false)

    @Test
    fun keyfileCancelsRealPipeReadWithoutProviderEof() = cancelPipeRead(true)

    private fun cancelPipeRead(keyfile: Boolean, boundedOffset: Boolean = false) = runBlocking {
        run {
            provider("reset", Bundle().apply {
                putBoolean("blockRead", true)
                putBoolean("boundedPipe", boundedOffset)
                putLong("assetOffset", if (boundedOffset) 13 else 0)
            })
            val root = File(context.filesDir, "copy-cancel-${if (keyfile) "key" else "input"}").apply { mkdirs() }
            val isolated = object : ContextWrapper(context) { override fun getFilesDir(): File = root }
            val runtime = File(root, "picocrypt_files").apply { mkdirs() }
            val sentinel = File(runtime, "foreign").apply { writeText("untouched") }
            val copying = async(Dispatchers.IO) {
                if (keyfile) FileCopyService.copyKeyfileToInternalStorage(isolated, CopyBoundaryProvider.URI, 0)
                else FileCopyService.copyFileToInternalStorage(isolated, CopyBoundaryProvider.URI, "plain.txt")
            }
            try {
                awaitState("pipeOpened")
                // The provider keeps its write end open and sends neither bytes nor EOF.
                SystemClock.sleep(100)
                copying.cancel()
                val deadline = SystemClock.uptimeMillis() + 2000
                while (!copying.isCompleted && SystemClock.uptimeMillis() < deadline) SystemClock.sleep(10)
                assertTrue("Cancellation must settle a real pipe read without manual provider EOF (keyfile=$keyfile)", copying.isCompleted)
                copying.join()
                awaitState("readerClosed")
                assertEquals(listOf("foreign"), runtime.list()!!.toList())
                assertEquals("untouched", sentinel.readText())
                // A second production call must acquire the same mutex and settle.
                provider("reset")
                withTimeout(3000) {
                    val next = if (keyfile) FileCopyService.copyKeyfileToInternalStorage(isolated, CopyBoundaryProvider.URI, 0)
                        else FileCopyService.copyFileToInternalStorage(isolated, CopyBoundaryProvider.URI, "plain.txt")
                    assertArrayEquals(CopyBoundaryProvider.body(), File(next.getOrThrow()).readBytes())
                }
            } finally {
                // Teardown only: the settlement assertion above must pass while this FD is open.
                provider("cleanup")
                copying.cancel()
                copying.join()
                root.deleteRecursively()
            }
        }
    }

    @Test
    fun sameSourceCanCloseThenOpenAnotherProviderDescriptor() {
        provider("reset")
        val source = AndroidStagingSource(context)
        try {
            repeat(2) {
                val input = source.open(CopyBoundaryProvider.URI)
                try { assertArrayEquals(CopyBoundaryProvider.body(), input.readBytes()) }
                finally { source.close(input) }
            }
        } finally { source.cancel(); provider("cleanup") }
    }

    @Test
    fun boundedPipeEndingBeforeAssetOffsetPublishesNothing() = runBlocking {
        for (keyfile in listOf(false, true)) {
            provider("reset", Bundle().apply {
                putBoolean("boundedPipe", true); putLong("assetOffset", 13); putBoolean("shortPrefix", true)
            })
            val root = File(context.filesDir, "copy-short-prefix-${if (keyfile) "key" else "input"}").apply { mkdirs() }
            val isolated = object : ContextWrapper(context) { override fun getFilesDir(): File = root }
            try {
                val result = if (keyfile) FileCopyService.copyKeyfileToInternalStorage(isolated, CopyBoundaryProvider.URI, 0)
                    else FileCopyService.copyFileToInternalStorage(isolated, CopyBoundaryProvider.URI, "plain.txt")
                assertTrue("A provider ending before its asset offset cannot produce a selected asset", result.isFailure)
                assertTrue(File(root, "picocrypt_files").list().isNullOrEmpty())
                assertTrue(provider("state").getBoolean("sourcePreserved"))
            } finally { provider("cleanup"); root.deleteRecursively() }
        }
    }

    @Test
    fun boundedPipeStopsAtDeclaredLengthWhileProviderWriterRemainsOpen() = copyBoundedPipe(0)

    @Test
    fun zeroLengthBoundedPipeCompletesWithoutReadinessOrProviderEof() = copyBoundedPipe(0, 0)

    @Test
    fun boundedPipePositiveOffsetSelectsExactAssetBytes() = copyBoundedPipe(13)

    @Test
    fun bothCopyRoutesCancelWhileWaitingForBoundedPipeOffset() {
        cancelPipeRead(false, true)
        cancelPipeRead(true, true)
    }

    private fun copyBoundedPipe(offset: Long, length: Long = 100003) = runBlocking {
        for (keyfile in listOf(false, true)) {
            provider("reset", Bundle().apply { putBoolean("boundedPipe", true); putLong("assetOffset", offset); putLong("assetLength", length) })
            val root = File(context.filesDir, "copy-bounded-${if (keyfile) "key" else "input"}").apply { mkdirs() }
            val isolated = object : ContextWrapper(context) { override fun getFilesDir(): File = root }
            val copying = async(Dispatchers.IO) {
                if (keyfile) FileCopyService.copyKeyfileToInternalStorage(isolated, CopyBoundaryProvider.URI, 0)
                else FileCopyService.copyFileToInternalStorage(isolated, CopyBoundaryProvider.URI, "plain.txt")
            }
            try {
                val deadline = SystemClock.uptimeMillis() + 2000
                while (!copying.isCompleted && SystemClock.uptimeMillis() < deadline) SystemClock.sleep(10)
                assertTrue("Declared asset EOF must complete without provider EOF (offset=$offset keyfile=$keyfile)", copying.isCompleted)
                val copied = File(copying.await().getOrThrow())
                assertArrayEquals(CopyBoundaryProvider.body().copyOfRange(offset.toInt(), (offset + length).toInt()), copied.readBytes())
                assertTrue(provider("state").getBoolean("sourcePreserved"))
                assertFalse(copied.parentFile!!.list()!!.any { it.endsWith(".incomplete") })
            } finally {
                // Teardown closes the held writer only after the completion assertion.
                provider("cleanup")
                copying.cancel()
                copying.join()
                root.deleteRecursively()
            }
        }
    }

    @Test
    fun keyfileCancellationPreservesForeignReplacementAfterPublication() = runBlocking {
        provider("reset")
        val root = File(context.filesDir, "keyfile-cancel-replacement").apply { mkdirs() }
        val isolated = object : ContextWrapper(context) { override fun getFilesDir(): File = root }
        val published = CompletableDeferred<Unit>()
        val runtime = File(root, "picocrypt_files")
        val target = File(runtime, "keyfile_0")
        val relocated = File(runtime, "retained-owner")
        val copying = async(Dispatchers.IO) {
            FileCopyService.copyKeyfileToInternalStorage(isolated, CopyBoundaryProvider.URI, 0,
                afterAcquire = {}, afterPublish = {
                    assertTrue(target.renameTo(relocated))
                    target.writeText("foreign replacement")
                    published.complete(Unit)
                    awaitCancellation()
                })
        }
        try {
            published.await()
            copying.cancel()
            copying.join()
            assertEquals("foreign replacement", target.readText())
            assertArrayEquals(CopyBoundaryProvider.body(), relocated.readBytes())
            assertTrue(provider("state").getBoolean("sourcePreserved"))
        } finally { copying.cancel(); copying.join(); root.deleteRecursively(); provider("cleanup") }
    }

    @Test
    fun bothCopyRoutesPreserveFinitePipeBytes() = copyExactBytes(Bundle().apply { putBoolean("finitePipe", true) }, CopyBoundaryProvider.body())

    @Test
    fun bothCopyRoutesRespectAssetDescriptorOffsetAndLength() = copyExactBytes(
        Bundle().apply { putBoolean("slice", true) }, CopyBoundaryProvider.body().copyOfRange(13, 100016),
    )

    @Test
    fun bothCopyRoutesCopyFiniteProviderBytesExactly() = copyExactBytes(null, CopyBoundaryProvider.body())

    private fun copyExactBytes(extras: Bundle?, expected: ByteArray) = runBlocking {
        provider("reset", extras)
        val root = File(context.filesDir, "copy-exact").apply { mkdirs() }
        val isolated = object : ContextWrapper(context) { override fun getFilesDir(): File = root }
        try {
            val input = FileCopyService.copyFileToInternalStorage(isolated, CopyBoundaryProvider.URI, "plain.txt").getOrThrow()
            val key = FileCopyService.copyKeyfileToInternalStorage(isolated, CopyBoundaryProvider.URI, 0).getOrThrow()
            assertArrayEquals(expected, File(input).readBytes())
            assertArrayEquals(expected, File(key).readBytes())
            assertTrue(provider("state").getBoolean("sourcePreserved"))
            assertFalse(File(root, "picocrypt_files").list()!!.any { it.endsWith(".incomplete") })
        } finally { root.deleteRecursively(); provider("cleanup") }
    }

    private fun awaitState(key: String) {
        val deadline = SystemClock.uptimeMillis() + 3000
        while (!provider("state").getBoolean(key) && SystemClock.uptimeMillis() < deadline) SystemClock.sleep(10)
        assertTrue("Provider state $key was not reached", provider("state").getBoolean(key))
    }

    private fun provider(method: String, extras: Bundle? = null): Bundle =
        requireNotNull(context.contentResolver.call(CopyBoundaryProvider.URI, method, null, extras))
}
