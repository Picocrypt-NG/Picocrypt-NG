package io.github.picocrypt_ng.picocrypt_ng

import android.content.ContentResolver
import android.content.Context
import android.content.res.Resources
import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import io.github.picocrypt_ng.picocrypt_ng.ui.components.applyStagedSelection
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.unmockkConstructor
import io.mockk.unmockkObject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.FilterInputStream
import java.io.InputStream
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.createTempDirectory

class StagingResourceBoundsTest {
    @Test
    fun `cancelled copy and cancelled waiter cannot erase a newer staging owner`() = runBlocking {
        val root = createTempDirectory(prefix = "staging_serial").toFile()
        val first = File(root, "first").apply { writeText("first source") }
        val second = File(root, "second").apply { writeText("new source") }
        val fixture = fixture(root, first)
        val entered = CountDownLatch(1)
        val closed = CountDownLatch(1)
        val release = CountDownLatch(1)
        val secondOpened = CountDownLatch(1)
        val calls = AtomicInteger()
        val active = java.util.concurrent.atomic.AtomicReference<InputStream?>()
        val firstJob = Job()
        val waiterJob = Job()
        val freshJob = Job()
        every { anyConstructed<AndroidStagingSource>().describe(fixture.uri, any()) } returns
            StagingSourceEntry(null, "same.txt", false, false, first.length())
        every { anyConstructed<AndroidStagingSource>().open(fixture.uri) } answers {
            val input = if (calls.incrementAndGet() == 1) object : FilterInputStream(first.inputStream()) {
                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    entered.countDown()
                    check(release.await(10, TimeUnit.SECONDS))
                    return super.read(buffer, offset, length)
                }
                override fun close() {
                    super.close()
                    closed.countDown()
                }
            } else {
                secondOpened.countDown()
                second.inputStream()
            }
            active.set(input)
            input
        }
        every { anyConstructed<AndroidStagingSource>().close(any()) } answers {
            val input = firstArg<InputStream>()
            input.close()
            active.compareAndSet(input, null)
            Unit
        }
        every { anyConstructed<AndroidStagingSource>().cancel() } answers {
            active.get()?.close()
            Unit
        }
        try {
            val copying = CoroutineScope(Dispatchers.Default + firstJob).async {
                StagingService.copyFilesToStaging(fixture.context, listOf(fixture.uri), 1)
            }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertFalse("a public cleanup cannot acquire an active copy's tree", StagingService.wipeStaging(fixture.context))
            val waiting = CoroutineScope(Dispatchers.Default + waiterJob).async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
                StagingService.copyFilesToStaging(fixture.context, listOf(fixture.uri), 2)
            }
            waiterJob.cancel()
            waiting.join()
            assertEquals("cancelled waiters cannot open or replace anything", 1, calls.get())
            assertTrue(File(root, "picocrypt_files/staging/same.txt").exists())
            firstJob.cancel()
            assertTrue("cancel reaches the owned input descriptor", closed.await(5, TimeUnit.SECONDS))
            val fresh = CoroutineScope(Dispatchers.Default + freshJob).async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
                StagingService.copyFilesToStaging(fixture.context, listOf(fixture.uri), 3)
            }
            assertEquals("new copy waits for the old reader's settlement", 1L, secondOpened.count)
            release.countDown()
            copying.join()
            val selection = fresh.await().getOrThrow()
            assertEquals("new source", File(selection.inputFiles.single()).readText())
            assertEquals("first source", first.readText())
            assertEquals("new source", second.readText())
            assertTrue(StagingService.wipeStaging(fixture.context))
        } finally {
            release.countDown()
            firstJob.cancel()
            waiterJob.cancel()
            freshJob.cancel()
            firstJob.join()
            waiterJob.join()
            freshJob.join()
            unmockkConstructor(AndroidStagingSource::class)
            root.deleteRecursively()
        }
    }

    @Test
    fun `cancel preserves cleanup failure and wipes its owned copy buffer`() =
        assertCancelledCleanup(cancelDuringCleanup = false)

    @Test
    fun `cancel arriving during failed cleanup still reports the retained plaintext`() =
        assertCancelledCleanup(cancelDuringCleanup = true)

    private fun assertCancelledCleanup(cancelDuringCleanup: Boolean) = runBlocking {
        val root = createTempDirectory(prefix = "staging_cancel_cleanup").toFile()
        val original = File(root, "original").apply { writeBytes(ByteArray(128 * 1024) { 0x51 }) }
        val fixture = fixture(root, original)
        val parent = File(root, "picocrypt_files")
        val stage = File(parent, "staging")
        val owner = Job()
        val viewModel = MainViewModel(mockk(), SavedStateHandle())
        var borrowed: ByteArray? = null
        var reads = 0
        if (cancelDuringCleanup) {
            mockkObject(NoFollowFileTree)
            every { NoFollowFileTree.delete(root, stage) } answers {
                if (stage.exists()) owner.cancel()
                callOriginal()
            }
        }
        every { anyConstructed<AndroidStagingSource>().open(fixture.uri) } answers {
            object : FilterInputStream(original.inputStream()) {
                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    val count = super.read(buffer, offset, length)
                    borrowed = buffer
                    if (++reads == 1) return count
                    assertTrue(stage.setWritable(false, false))
                    assertTrue(parent.setWritable(false, false))
                    if (cancelDuringCleanup) throw IOException("Source read failed before cancellation")
                    owner.cancel()
                    return count
                }
            }
        }
        try {
            val operation = CoroutineScope(Dispatchers.Default + owner).async {
                applyStagedSelection(viewModel, "Unknown error") {
                    StagingService.copyFilesToStaging(fixture.context, listOf(fixture.uri), 1)
                }
            }
            val failure = try {
                operation.await()
                throw AssertionError("cancelled copy returned")
            } catch (cancelled: CancellationException) { cancelled }
            operation.join()
            // Coroutine stack recovery may wrap the original cancellation in cause.
            val cleanup = generateSequence<Throwable>(failure) { it.cause }
                .flatMap { it.suppressed.asSequence() }
                .filterIsInstance<AppError.FileError.DeleteFailed>().firstOrNull()
            val retained = stage.listFiles()!!.single().readBytes()
            assertTrue("cleanup diagnostic must survive and reach the UI: attached=${cleanup != null}, surfaced=${viewModel.errorMessage.value != null}, retained=${retained.size}",
                cleanup != null && viewModel.errorMessage.value is AppError.FileError.DeleteFailed)
            assertSame("the UI must receive the actual cleanup diagnostic", cleanup, viewModel.errorMessage.value)
            assertTrue("an interrupted copy leaves real partial plaintext when unlink fails", retained.isNotEmpty() && retained.size < original.length())
            assertTrue(retained.all { it == 0x51.toByte() })
            assertTrue("the native copy buffer must be wiped before returning", requireNotNull(borrowed).all { it == 0.toByte() })
            assertTrue(original.readBytes().all { it == 0x51.toByte() })
        } finally {
            parent.setWritable(true, false)
            stage.setWritable(true, false)
            owner.cancel()
            owner.join()
            if (cancelDuringCleanup) unmockkObject(NoFollowFileTree)
            unmockkConstructor(AndroidStagingSource::class)
            root.deleteRecursively()
        }
    }

    @Test
    fun `tree metadata is enumerated once and virtual sources are not staged`() = runBlocking {
        val root = createTempDirectory(prefix = "staging_tree").toFile()
        val original = File(root, "original").apply { writeText("exact source body") }
        val fixture = treeFixture(root, original, mapOf(
            "root" to listOf(
                StagingSourceEntry("one", "one.txt", false, false, original.length()),
                StagingSourceEntry("sub", "nested", true, false, null),
                StagingSourceEntry("virtual", "virtual", false, true, Long.MAX_VALUE),
            ),
            "sub" to listOf(StagingSourceEntry("two", "two.txt", false, false, original.length())),
        ))
        try {
            val selection = StagingService.copyTreeToStaging(fixture.base.context, fixture.tree).getOrThrow()
            assertEquals(listOf("root", "sub"), fixture.queries)
            assertEquals(listOf("folder/nested/two.txt", "folder/one.txt"),
                selection.inputFiles.map { File(it).relativeTo(File(selection.stagingRoot)).invariantSeparatorsPath }.sorted())
            selection.inputFiles.forEach { assertEquals("exact source body", File(it).readText()) }
            assertEquals(listOf(File(selection.stagingRoot, "folder").path), selection.onlyFolders)
            assertTrue(StagingService.wipeStaging(fixture.base.context))
            assertEquals("exact source body", original.readText())
        } finally {
            unmockkConstructor(AndroidStagingSource::class)
            root.deleteRecursively()
        }
    }

    @Test
    fun `sanitized folder aliases are refused before either source is copied`() = runBlocking {
        val root = createTempDirectory(prefix = "staging_collision").toFile()
        val original = File(root, "original").apply { writeText("untouched") }
        val fixture = treeFixture(root, original, mapOf("root" to listOf(
            StagingSourceEntry("first", "a..b", false, false, 9),
            StagingSourceEntry("second", "ab", false, false, 9),
        )))
        try {
            assertTrue(StagingService.copyTreeToStaging(fixture.base.context, fixture.tree).isFailure)
            assertEquals(0, fixture.opens.get())
            assertFalse(File(root, "picocrypt_files/staging").exists())
            assertEquals("untouched", original.readText())
        } finally {
            unmockkConstructor(AndroidStagingSource::class)
            root.deleteRecursively()
        }
    }

    @Test
    fun `provider directory cycle is rejected without a second query or plaintext writes`() = runBlocking {
        val root = createTempDirectory(prefix = "staging_cycle").toFile()
        val original = File(root, "original").apply { writeText("untouched") }
        val fixture = treeFixture(root, original, mapOf("root" to listOf(
            StagingSourceEntry("root", "again", true, false, null),
        )))
        try {
            assertTrue(StagingService.copyTreeToStaging(fixture.base.context, fixture.tree).isFailure)
            assertEquals(listOf("root"), fixture.queries)
            assertEquals(0, fixture.opens.get())
            assertFalse(File(root, "picocrypt_files/staging").exists())
        } finally {
            unmockkConstructor(AndroidStagingSource::class)
            root.deleteRecursively()
        }
    }

    @Test
    fun `JSON escaped selection size is enforced before staging`() = runBlocking {
        val root = createTempDirectory(prefix = "staging_wire").toFile()
        val original = File(root, "original").apply { writeText("untouched") }
        val opens = AtomicInteger()
        val fixture = fixture(root, original) { opens.incrementAndGet() }
        val names = AtomicInteger()
        every { anyConstructed<AndroidStagingSource>().describe(fixture.uri, any()) } answers {
            StagingSourceEntry(null, "\u0001".repeat(240) + names.incrementAndGet(), false, false, original.length())
        }
        try {
            val result = StagingService.copyFilesToStaging(fixture.context, List(2048) { fixture.uri }, 1)
            assertEquals("PCV3_RESOURCE_LIMIT", (result.exceptionOrNull() as? Pcv3BridgeFailure)?.code)
            assertEquals(0, opens.get())
            assertFalse(File(root, "picocrypt_files/staging").exists())
        } finally {
            unmockkConstructor(AndroidStagingSource::class)
            root.deleteRecursively()
        }
    }

    @Test
    fun `URI encoding work is admitted before constructing a long file document URI`() = runBlocking {
        val root = createTempDirectory(prefix = "staging_uri").toFile()
        val original = File(root, "original").apply { writeText("untouched") }
        val hugeId = "id".repeat(4 * 1024 * 1024)
        val fixture = treeFixture(root, original, mapOf("root" to listOf(
            StagingSourceEntry(hugeId, "small-name", false, false, 9),
        )))
        val constructions = AtomicInteger()
        every { anyConstructed<AndroidStagingSource>().documentUri(fixture.tree, hugeId) } answers {
            constructions.incrementAndGet()
            fixture.base.uri
        }
        try {
            val result = StagingService.copyTreeToStaging(fixture.base.context, fixture.tree)
            assertEquals("PCV3_RESOURCE_LIMIT", (result.exceptionOrNull() as? Pcv3BridgeFailure)?.code)
            assertEquals(0, constructions.get())
            assertEquals(0, fixture.opens.get())
            assertFalse(File(root, "picocrypt_files/staging").exists())
        } finally {
            unmockkConstructor(AndroidStagingSource::class)
            root.deleteRecursively()
        }
    }

    @Test
    fun `unrepresentable storage requirement cannot authorize staging`() {
        assertFalse(StagingService.hasSpaceFor(Long.MAX_VALUE / 2, 0))
        assertFalse(StagingService.hasSpaceFor(Long.MAX_VALUE, Long.MAX_VALUE))
        assertFalse(StagingService.hasSpaceFor(-1, Long.MAX_VALUE))
        assertEquals(Long.MAX_VALUE, StagingService.requiredBytes(Long.MAX_VALUE))
        assertTrue(StagingService.hasSpaceFor(0, StagingService.SPACE_MARGIN_BYTES))
    }

    @Test
    fun `selection impossible to transport is refused before opening or staging sources`() = runBlocking {
        val root = createTempDirectory(prefix = "staging_count").toFile()
        val original = File(root, "original").apply { writeText("unchanged source") }
        val opens = AtomicInteger()
        val fixture = fixture(root, original) { opens.incrementAndGet() }
        try {
            val result = StagingService.copyFilesToStaging(fixture.context, List(4097) { fixture.uri }, 1)
            assertTrue("the existing4096-path transport boundary must be enforced before copying", result.isFailure)
            assertEquals("an impossible selection must not open source streams", 0, opens.get())
            assertFalse(File(root, "picocrypt_files/staging").exists())
            assertEquals("unchanged source", original.readText())
        } finally {
            unmockkConstructor(AndroidStagingSource::class)
            root.deleteRecursively()
        }
    }

    @Test
    fun `cancellation during real source copy cannot leave an undelivered plaintext tree`() = runBlocking {
        val root = createTempDirectory(prefix = "staging_cancel").toFile()
        val bytes = ByteArray(2 * 1024 * 1024) { (it % 251).toByte() }
        val original = File(root, "original").apply { writeBytes(bytes) }
        val owner = Job()
        val reads = AtomicInteger()
        val fixture = fixture(root, original)
        every { anyConstructed<AndroidStagingSource>().open(fixture.uri) } answers {
            object : FilterInputStream(original.inputStream()) {
                override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                    val count = super.read(buffer, offset, length)
                    if (count > 0 && reads.incrementAndGet() == 1) owner.cancel()
                    return count
                }
            }
        }
        try {
            val result = CoroutineScope(Dispatchers.Default + owner).async {
                StagingService.copyFilesToStaging(fixture.context, listOf(fixture.uri), 1)
            }
            try {
                result.await()
                throw AssertionError("cancelled selection unexpectedly returned")
            } catch (_: CancellationException) {
                // Inspect after the IO worker has settled its actual file copy.
            }
            result.join()
            assertTrue("the cancellation must occur inside the source copy", reads.get() > 0)
            assertFalse("undelivered staged plaintext must be removed", File(root, "picocrypt_files/staging").exists())
            assertArrayEquals(bytes, original.readBytes())
        } finally {
            owner.cancel()
            unmockkConstructor(AndroidStagingSource::class)
            root.deleteRecursively()
        }
    }

    private data class Fixture(val context: Context, val uri: Uri)
    private data class TreeFixture(val base: Fixture, val tree: Uri, val queries: MutableList<String>, val opens: AtomicInteger)

    private fun treeFixture(root: File, original: File, children: Map<String, List<StagingSourceEntry>>): TreeFixture {
        val base = fixture(root, original)
        val tree = mockk<Uri>()
        val rootUri = mockk<Uri>()
        val queries = mutableListOf<String>()
        val opens = AtomicInteger()
        every { anyConstructed<AndroidStagingSource>().treeDocumentId(tree) } returns "root"
        every { anyConstructed<AndroidStagingSource>().documentUri(tree, any()) } answers {
            if (secondArg<String>() == "root") rootUri else base.uri
        }
        every { anyConstructed<AndroidStagingSource>().describe(rootUri, false) } returns
            StagingSourceEntry("root", "folder", true, false, null)
        every { anyConstructed<AndroidStagingSource>().forEachChild(tree, any(), any()) } answers {
            val id = secondArg<String>()
            queries.add(id)
            val visit = thirdArg<(StagingSourceEntry) -> Unit>()
            children[id].orEmpty().forEach(visit)
        }
        every { anyConstructed<AndroidStagingSource>().open(any()) } answers {
            opens.incrementAndGet()
            original.inputStream()
        }
        return TreeFixture(base, tree, queries, opens)
    }

    /** IPC metadata is controlled; source streams and staging/cleanup use real files. */
    private fun fixture(root: File, original: File, onOpen: () -> Unit = {}): Fixture {
        val context = mockk<Context>()
        val resources = mockk<Resources>()
        val resolver = mockk<ContentResolver>()
        val uri = mockk<Uri>()
        val names = AtomicInteger()
        every { context.filesDir } returns root
        every { context.contentResolver } returns resolver
        every { context.resources } returns resources
        every { context.getString(any()) } returns "public staging test message"
        every { context.getString(any(), *anyVararg()) } returns "public staging test message"
        every { resources.getQuantityString(any(), any(), *anyVararg()) } returns "public selection"
        every { uri.toString() } returns "content://public-staging/source"
        mockkConstructor(AndroidStagingSource::class)
        every { anyConstructed<AndroidStagingSource>().observation() } returns
            Pcv3AndroidResourceObservation(8L shl 30, 6L shl 30, 128L shl 20, 64L shl 20, true, false)
        every { anyConstructed<AndroidStagingSource>().uriWorkingBytes(any()) } returns 512L
        every { anyConstructed<AndroidStagingSource>().describe(uri, any()) } answers {
            val name = "source-${names.incrementAndGet()}.txt"
            StagingSourceEntry(null, name, false, false, original.length())
        }
        every { anyConstructed<AndroidStagingSource>().open(uri) } answers {
            onOpen()
            original.inputStream()
        }
        every { anyConstructed<AndroidStagingSource>().close(any()) } answers { firstArg<java.io.InputStream>().close() }
        every { anyConstructed<AndroidStagingSource>().cancel() } returns Unit
        return Fixture(context, uri)
    }
}
