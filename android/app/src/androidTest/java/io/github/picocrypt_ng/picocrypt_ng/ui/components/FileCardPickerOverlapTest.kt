package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.app.Application
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.DocumentsContract
import android.system.Os
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.core.app.ActivityOptionsCompat
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.BoundedSafDocumentsProvider
import io.github.picocrypt_ng.picocrypt_ng.FileCopyService
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.SelectionKind
import io.github.picocrypt_ng.picocrypt_ng.StagingService
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Delayed real provider I/O keeps all three production picker callbacks in overlap. */
@RunWith(AndroidJUnit4::class)
class FileCardPickerOverlapTest {
    @get:Rule val compose = createComposeRule()
    private val app: Application get() = ApplicationProvider.getApplicationContext()

    @Test fun singleCopyRejectsOverlappingFolderAndMultiCallbacks() = exercise(SelectionKind.SINGLE_FILE)
    @Test fun folderCopyRejectsOverlappingSingleAndMultiCallbacks() = exercise(SelectionKind.FOLDER)
    @Test fun multiCopyRejectsOverlappingSingleAndFolderCallbacks() = exercise(SelectionKind.MULTI_FILE)

    @Test fun singleFilePublicationRefusesAConcurrentTargetAndPreservesBothOwners() = runBlocking {
        assertTrue(FileCopyService.cleanupAllFiles(app))
        provider("reset")
        provider("seed-source")
        provider("block-source", "root/a.txt")
        val copying = async(Dispatchers.IO) {
            FileCopyService.copyFileToInternalStorage(app, document("root/a.txt"), "a.txt")
        }
        var primaryFailure: Throwable? = null
        try {
            withTimeout(5_000) {
                while (!provider("source-state").getBoolean("blocked")) delay(10)
            }
            // The real copy owns its temporary inode and is waiting for the
            // source FD. A different owner wins the documented final pathname.
            val directory = File(FileCopyService.getInternalStoragePath(app))
            val winner = File(directory, "input_file.txt")
            assertTrue("the competing owner must create a previously absent target", winner.createNewFile())
            val winnerBytes = "another operation's complete private input".toByteArray()
            winner.writeBytes(winnerBytes)
            val winnerIdentity = Os.lstat(winner.path).let { it.st_dev to it.st_ino }
            provider("release-source")
            val result = withTimeout(10_000) { copying.await() }
            assertTrue("publication must refuse a target created during the source read", result.isFailure)
            assertArrayEquals(winnerBytes, winner.readBytes())
            assertEquals("failure cleanup must not unlink or replace the winner", winnerIdentity,
                Os.lstat(winner.path).let { it.st_dev to it.st_ino })
            assertEquals("the refused copy must remove every owned temporary file", listOf("input_file.txt"),
                requireNotNull(directory.list()).sorted())
            assertEquals(1, provider("source-state").getInt("opens"))
            assertEquals("a", readSource("root/a.txt"))
            assertEquals("b", readSource("root/sub/b.txt"))
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                provider("release-source")
                withContext(NonCancellable) {
                    withTimeout(10_000) { copying.cancelAndJoin() }
                    assertTrue(FileCopyService.cleanupAllFiles(app))
                    assertTrue(provider("cleanup").getBoolean("cleaned"))
                }
            } catch (cleanup: Throwable) {
                primaryFailure?.addSuppressed(cleanup) ?: throw cleanup
            }
        }
    }

    @Test fun slowSingleFileMetadataDoesNotBlockMainThread() {
        assertTrue(runBlocking { FileCopyService.cleanupAllFiles(app) })
        provider("reset")
        provider("seed-source")
        provider("block-metadata", "root/a.txt")
        val main = MainViewModel(app, SavedStateHandle())
        val registry = PickerRegistry()
        val owner = object : ActivityResultRegistryOwner { override val activityResultRegistry = registry }
        val visible = mutableStateOf(true)
        var primaryFailure: Throwable? = null
        val frameFailure = AtomicReference<Throwable?>()
        var frameDriver: Thread? = null
        try {
            compose.setContent {
                if (visible.value) {
                    CompositionLocalProvider(LocalActivityResultRegistryOwner provides owner) { ChooseFile(main) }
                }
            }
            compose.onNodeWithText(app.getString(R.string.choose_file)).performClick()
            compose.onNodeWithText(app.getString(R.string.choose_single_file)).performClick()
            val handler = Handler(Looper.getMainLooper())
            handler.post { registry.deliver(SelectionKind.SINGLE_FILE, document("root/a.txt")) }
            // A deferred selection needs a Compose frame to launch its effect.
            // Drive frames separately so a defective Main-thread callback cannot
            // block the test thread that must release the remote query gate.
            frameDriver = Thread({
                try { compose.waitForIdle() } catch (failure: Throwable) { frameFailure.set(failure) }
            }, "metadata-test-compose-frames").apply { isDaemon = true; start() }
            val deadline = SystemClock.uptimeMillis() + 5_000
            while (!provider("source-state").getBoolean("metadataBlocked")) {
                frameFailure.get()?.let { throw it }
                assertTrue("single-file metadata query must reach the real provider", SystemClock.uptimeMillis() < deadline)
                SystemClock.sleep(10)
            }
            val heartbeat = CountDownLatch(1)
            handler.post { heartbeat.countDown() }
            assertTrue("provider metadata IPC must not block the queued Main heartbeat", heartbeat.await(1, TimeUnit.SECONDS))
            assertEquals("metadata gate must remain held until after the heartbeat", 0, provider("source-state").getInt("opens"))
            provider("release-metadata")
            frameDriver.join(10_000)
            assertFalse("Compose frame driver must settle after query release", frameDriver.isAlive)
            frameFailure.get()?.let { throw it }
            compose.waitUntil(timeoutMillis = 10_000) {
                main.errorMessage.value != null || main.formState.value.copiedFilePath.isNotBlank()
            }
            assertNull(main.errorMessage.value?.technicalMessage, main.errorMessage.value)
            assertEquals("a", File(main.formState.value.copiedFilePath).readText())
            assertEquals("a", readSource("root/a.txt"))
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                provider("release-metadata")
                frameDriver?.join(10_000)
                assertFalse("test must not leave a frame driver running", frameDriver?.isAlive == true)
                frameFailure.get()?.let { throw it }
                compose.runOnIdle { visible.value = false }
                compose.waitForIdle()
                runBlocking {
                    withTimeout(10_000) {
                        privateServiceOwnershipMutex(StagingService, "stagingMutex").withLock { }
                        privateServiceOwnershipMutex(FileCopyService, "inputCopyMutex").withLock { }
                    }
                    assertTrue(FileCopyService.cleanupAllFiles(app))
                }
                assertTrue(provider("cleanup").getBoolean("cleaned"))
            } catch (cleanup: Throwable) {
                primaryFailure?.addSuppressed(cleanup) ?: throw cleanup
            }
        }
    }

    private fun exercise(first: SelectionKind) {
        assertTrue(runBlocking { FileCopyService.cleanupAllFiles(app) })
        provider("reset")
        provider("seed-source")
        provider("block-source", "root/a.txt")
        val previous = File(app.filesDir, "picocrypt_files/staging/previous.txt")
        assertTrue(previous.parentFile!!.mkdirs())
        previous.writeText("old staged plaintext")
        val store = ViewModelStore()
        val main = ViewModelProvider(store, object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T = MainViewModel(app, SavedStateHandle()) as T
        })[MainViewModel::class.java]
        main.updateFormData(main.formState.value.copy(selectedFilename = "previous selection", selectionKind = SelectionKind.MULTI_FILE,
            inputFiles = listOf(previous.path), onlyFiles = listOf(previous.path)))
        val registry = PickerRegistry()
        val owner = object : ActivityResultRegistryOwner { override val activityResultRegistry = registry }
        val visible = mutableStateOf(true)
        var primaryFailure: Throwable? = null
        try {
            compose.setContent {
                if (visible.value) {
                    CompositionLocalProvider(LocalActivityResultRegistryOwner provides owner) { ChooseFile(main) }
                }
            }
            // Launch each registered picker before delivering its result, just as
            // delayed platform callbacks may coexist across activity transitions.
            for (label in listOf(R.string.choose_single_file, R.string.choose_multiple_files, R.string.choose_folder)) {
                compose.onNodeWithText("previous selection").performClick()
                compose.onNodeWithText(app.getString(label)).performClick()
            }
            compose.runOnIdle {
                registry.deliver(first, result(first, "root/a.txt"))
                assertTrue("accepted callback must invalidate the old runnable form synchronously", main.formState.value.inputFiles.isEmpty())
                assertEquals("", main.formState.value.copiedFilePath)
            }
            compose.waitUntil(timeoutMillis = 10_000) { provider("source-state").getBoolean("blocked") }
            assertFalse("the previous owner must be cleaned before the new source opens", previous.exists())
            compose.runOnIdle {
                for (kind in SelectionKind.entries.filter { it != first }) registry.deliver(kind, result(kind, "root/sub/b.txt"))
            }
            assertEquals("overlapping callbacks must not open a second source", 1, provider("source-state").getInt("opens"))
            provider("release-source")
            compose.waitUntil(timeoutMillis = 10_000) {
                main.errorMessage.value != null || main.formState.value.let {
                    it.selectionKind == first && (it.inputFiles.isNotEmpty() || it.copiedFilePath.isNotBlank())
                }
            }
            compose.waitForIdle()
            assertNull(main.errorMessage.value?.technicalMessage, main.errorMessage.value)
            val selected = main.formState.value
            assertEquals(first, selected.selectionKind)
            val files = if (first == SelectionKind.SINGLE_FILE) listOf(File(selected.copiedFilePath))
                else selected.inputFiles.map(::File)
            assertEquals(if (first == SelectionKind.FOLDER) 2 else 1, files.size)
            assertEquals(if (first == SelectionKind.FOLDER) setOf("a", "b") else setOf("a"), files.map { it.readText() }.toSet())
            assertEquals(files.size, provider("source-state").getInt("opens"))
            assertEquals("a", readSource("root/a.txt"))
            assertEquals("b", readSource("root/sub/b.txt"))
            assertFalse(previous.exists())
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                provider("release-source")
                compose.runOnIdle { visible.value = false; store.clear() }
                compose.waitForIdle()
                // Compose idle does not join IO or NonCancellable cleanup. Drain
                // service write ownership; this does not join every UI coroutine.
                runBlocking {
                    withTimeout(10_000) {
                        privateServiceOwnershipMutex(StagingService, "stagingMutex").withLock { }
                        privateServiceOwnershipMutex(FileCopyService, "inputCopyMutex").withLock { }
                    }
                    assertTrue(FileCopyService.cleanupAllFiles(app))
                }
                assertTrue(provider("cleanup").getBoolean("cleaned"))
            } catch (cleanup: Throwable) {
                primaryFailure?.addSuppressed(cleanup) ?: throw cleanup
            }
        }
    }

    private fun result(kind: SelectionKind, id: String): Any = when (kind) {
        SelectionKind.FOLDER -> BoundedSafDocumentsProvider.tree
        SelectionKind.MULTI_FILE -> listOf(document(id))
        SelectionKind.SINGLE_FILE -> document(id)
    }

    private fun document(id: String): Uri = DocumentsContract.buildDocumentUriUsingTree(BoundedSafDocumentsProvider.tree, id)
    private fun readSource(id: String): String = requireNotNull(app.contentResolver.openInputStream(document(id))).bufferedReader().use { it.readText() }
    private fun provider(method: String, arg: String? = null): Bundle {
        if (method == "reset") BoundedSafDocumentsProvider.grantAccessForTest(app)
        return requireNotNull(app.contentResolver.call(BoundedSafDocumentsProvider.AUTHORITY, "bounded-test-$method", arg, null))
    }
    private fun privateServiceOwnershipMutex(owner: Any, name: String): Mutex = owner.javaClass.getDeclaredField(name).let {
        it.isAccessible = true
        it.get(owner) as Mutex
    }

    private class PickerRegistry : ActivityResultRegistry() {
        private val pending = mutableMapOf<SelectionKind, Int>()
        override fun <I, O> onLaunch(requestCode: Int, contract: ActivityResultContract<I, O>, input: I, options: ActivityOptionsCompat?) {
            val kind = when (contract) {
                is ActivityResultContracts.GetContent -> SelectionKind.SINGLE_FILE
                is ActivityResultContracts.OpenDocumentTree -> SelectionKind.FOLDER
                is ActivityResultContracts.OpenMultipleDocuments -> SelectionKind.MULTI_FILE
                else -> error("Unexpected picker")
            }
            check(pending.put(kind, requestCode) == null)
        }
        fun deliver(kind: SelectionKind, result: Any) { check(dispatchResult(checkNotNull(pending.remove(kind)), result)) }
    }
}
