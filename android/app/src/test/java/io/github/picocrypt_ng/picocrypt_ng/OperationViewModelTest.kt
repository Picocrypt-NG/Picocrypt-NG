package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import io.github.picocrypt_ng.picocrypt_ng.testutils.MainDispatcherRule
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import java.io.File
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.createTempDirectory

/**
 * Unit tests for OperationViewModel.
 * 
 * Note: OperationViewModel uses OperationManager which interacts with GoBridge.
 * Full integration testing requires instrumented tests. These unit tests focus
 * on the ViewModel's polling lifecycle and state management.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OperationViewModelTest {
    
    @get:Rule
    val instantTaskExecutorRule = InstantTaskExecutorRule()

    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()

    private lateinit var mockContext: Context
    private lateinit var testFilesDir: File
    private lateinit var viewModel: OperationViewModel
    
    @Before
    fun setUp() {
        testFilesDir = createTempDirectory("pcv3-view-model").toFile()
        mockContext = mockk<Context>(relaxed = true)
        every { mockContext.filesDir } returns testFilesDir
        viewModel = OperationViewModel()
        resetOperationState()
    }
    
    @After
    fun tearDown() {
        if (::viewModel.isInitialized) {
            runTest(mainDispatcherRule.testDispatcher) {
                viewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
            }
        }
        resetOperationState()
        if (::testFilesDir.isInitialized) testFilesDir.deleteRecursively()
    }
    
    @Test
    fun `operationState exposes OperationManager currentOperation`() = runTest(mainDispatcherRule.testDispatcher) {
        val operationState = viewModel.operationState.first()
        
        // Initially should be null
        assertNull("Operation state should be null initially", operationState)
        
        // Should match OperationManager's state
        val managerState = OperationManager.currentOperation.first()
        assertEquals(managerState, operationState)
    }
    
    @Test
    fun `startDecrypt surfaces a start failure as a terminal error state`() = runTest(mainDispatcherRule.testDispatcher) {
        // Mirror of the encrypt test on the decrypt path.
        mockkObject(OperationManager)
        try {
            val error = AppError.ValidationError.NoFileSelected
            coEvery { OperationManager.startDecrypt(any(), any()) } returns Result.failure(error)
            every { OperationManager.surfaceStartFailure(any(), any()) } answers { callOriginal() }

            viewModel.startDecrypt(mockContext, TestDataBuilders.createDecryptFormData())
            advanceUntilIdle()

            val state = viewModel.operationState.value
            assertNotNull("A start failure must surface as an error state (not silent null)", state)
            assertTrue("Error state must be terminal (done=true)", state!!.done)
            assertNotNull("Error state must carry the error", state.error)
            assertEquals(OperationType.DECRYPT, state.type)
        } finally {
            unmockkObject(OperationManager)
        }
    }
    
    @Test
    fun `cancelOperation delegates once and exposes the native terminal state`() = runTest(mainDispatcherRule.testDispatcher) {
        setOperationState(
            TestDataBuilders.createOperationState(
                id = "op_cancel",
                status = OperationStatusData(OperationStatus.ENCRYPTING_RATE),
                done = false,
            )
        )

        mockkObject(GoBridge)
        try {
            every { GoBridge.cancelOperation("op_cancel") } returns Result.success(
                ProgressState(
                    status = OperationStatusData(OperationStatus.CANCELLED),
                    detail = OperationProgressDetail(OperationProgress.NONE),
                    progress = 0.4f,
                    done = true,
                )
            )

            viewModel.cancelOperation()
            val state = viewModel.operationState.first { it?.done == true }

            verify(exactly = 1) { GoBridge.cancelOperation("op_cancel") }
            assertEquals(OperationStatus.CANCELLED, state?.status?.code)
            assertEquals(0.4f, state?.progress ?: -1f, 0.001f)
            assertTrue("The ViewModel must expose cancellation as terminal", state?.done == true)
        } finally {
            unmockkObject(GoBridge)
        }
    }
    
    @Test
    fun `clearOperation stops polling and clears operation`() = runTest(mainDispatcherRule.testDispatcher) {
        setOperationState(
            OperationState(
                id = "op_123",
                type = OperationType.ENCRYPT,
                inputFile = "/data/test/input_file.txt",
                outputFile = "/data/test/output_file.pcv",
                status = OperationStatusData(OperationStatus.UNKNOWN),
                detail = OperationProgressDetail(OperationProgress.NONE),
                progress = 0.5f,
            )
        )

        viewModel.clearOperation(mockContext, shouldCleanupFiles = false)
        
        advanceUntilIdle()
        
        val operationState = viewModel.operationState.first()
        assertNull("Operation should be cleared", operationState)
    }

    @Test
    fun `queued legacy clear cannot delete a newer selection or reset its operation`() = runTest(mainDispatcherRule.testDispatcher) {
        val source = File(testFilesDir, "picocrypt_files/input_file.pcv")
        val staged = File(testFilesDir, "picocrypt_files/staging/new-selection.txt")
        val newBytes = "new selection must survive stale cleanup".toByteArray()
        mockkObject(GoBridge)
        every { GoBridge.startOperation() } returnsMany listOf(Result.success("old-clear"), Result.success("new-owner"))
        every { GoBridge.startDecrypt(any(), any(), any(), any(), any()) } returns Result.success(Unit)
        try {
            assertTrue(source.parentFile!!.mkdirs())
            source.writeText("old encrypted input")
            assertTrue(OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData(copiedFilePath = source.absolutePath),
            ).isSuccess)
            val existingJobs = viewModel.viewModelScope.coroutineContext[Job]!!.children.toSet()
            viewModel.clearOperation(mockContext)
            val queuedClear = viewModel.viewModelScope.coroutineContext[Job]!!.children.single { it !in existingJobs }

            // Another dismissal wins before the queued callback gets its first turn.
            assertTrue(OperationManager.clearOperation(shouldCleanupFiles = false).isSuccess)
            source.writeBytes(newBytes)
            assertTrue(staged.parentFile!!.mkdirs())
            staged.writeBytes(newBytes)
            val replacementForm = TestDataBuilders.createDecryptFormData(
                copiedFilePath = source.absolutePath,
                password = "new-owner-password",
            )
            // Keep the queued Main callback paused while the real IO-backed start completes.
            assertTrue(runBlocking { OperationManager.startDecrypt(mockContext, replacementForm) }.isSuccess)
            queuedClear.join()

            assertEquals("Delayed clear must remain bound to old-clear", "new-owner", viewModel.operationState.value?.id)
            assertArrayEquals("New input must not be deleted by the stale callback", newBytes, source.readBytes())
            assertArrayEquals("New staging must not be wiped by the stale callback", newBytes, staged.readBytes())
            assertArrayEquals("A stale reset must not clear newer credentials", "new-owner-password".toCharArray(), replacementForm.passwordInput)
        } finally {
            unmockkObject(GoBridge)
        }
    }

    @Test
    fun `delayed legacy save completion cannot clear a replacement operation`() = runTest(mainDispatcherRule.testDispatcher) {
        val source = File(testFilesDir, "picocrypt_files/input_file.pcv")
        val newBytes = "replacement selected after the old save began".toByteArray()
        val saveCompleted = CompletableDeferred<Unit>()
        mockkObject(GoBridge)
        every { GoBridge.startOperation() } returnsMany listOf(Result.success("saving-old"), Result.success("replacement"))
        every { GoBridge.startDecrypt(any(), any(), any(), any(), any()) } returns Result.success(Unit)
        try {
            assertTrue(source.parentFile!!.mkdirs())
            source.writeText("old input")
            assertTrue(OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData(copiedFilePath = source.absolutePath),
            ).isSuccess)
            val savedOperation = requireNotNull(viewModel.operationState.value)
            val delayedCompletion = async(start = CoroutineStart.UNDISPATCHED) {
                saveCompleted.await()
                viewModel.clearOperation(mockContext, expectedOperation = savedOperation)
            }
            assertTrue(OperationManager.clearOperation(shouldCleanupFiles = false).isSuccess)
            source.writeBytes(newBytes)
            assertTrue(OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData(copiedFilePath = source.absolutePath),
            ).isSuccess)
            saveCompleted.complete(Unit)

            assertFalse("The stale save must not authorize clearing the replacement form", delayedCompletion.await())
            runCurrent()
            assertEquals("replacement", viewModel.operationState.value?.id)
            assertArrayEquals(newBytes, source.readBytes())
        } finally {
            saveCompleted.complete(Unit)
            unmockkObject(GoBridge)
        }
    }

    @Test
    fun `stale failed start dismissal cannot own a newer failure with no native ID`() = runTest(mainDispatcherRule.testDispatcher) {
        OperationManager.surfaceStartFailure(OperationType.DECRYPT, AppError.ValidationError.InvalidPassword)
        val oldFailure = requireNotNull(viewModel.operationState.value)
        assertTrue(OperationManager.clearOperation(shouldCleanupFiles = false).isSuccess)
        val staged = File(testFilesDir, "picocrypt_files/staging/replacement.txt")
        assertTrue(staged.parentFile!!.mkdirs())
        staged.writeText("new failed selection")
        OperationManager.surfaceStartFailure(OperationType.DECRYPT, AppError.ValidationError.NoFileSelected)
        val newFailure = requireNotNull(viewModel.operationState.value)

        assertFalse(
            "A previous failure dialog must not own a different failure just because both lack native IDs",
            viewModel.clearOperation(mockContext, expectedOperation = oldFailure),
        )
        runCurrent()
        assertSame(newFailure, viewModel.operationState.value)
        assertEquals("new failed selection", staged.readText())
        assertTrue("The current failure must remain dismissible", viewModel.clearOperation(mockContext))
        viewModel.operationState.first { it == null }
        assertFalse("The current owner's plaintext must be cleaned", staged.exists())
    }

    @Test
    fun `PCV3 poller accepts only its current identity and stops at Final`() = runTest(mainDispatcherRule.testDispatcher) {
        val first = livePcv3("op_current", generation = 7)
        val stale = livePcv3("op_stale", generation = 6)
        val current = livePcv3("op_current", generation = 7, statusCode = "authenticating")
        val terminal = finalPcv3("op_current", generation = 7)
        val route = FakePcv3Operations(
            startResult = Result.success(first),
            refreshResults = ArrayDeque(
                listOf(
                    RefreshStep(Result.success(stale), updateAuthority = false, busy = true),
                    RefreshStep(Result.success(current)),
                    RefreshStep(Result.success(terminal)),
                )
            ),
        )
        val cleaner = RecordingPcv3Cleaner()
        val pcv3ViewModel = OperationViewModel(route, cleaner)
        val password = "password".toCharArray()

        pcv3ViewModel.startPcv3(mockContext, pcv3Transfer(password))
        runCurrent()
        assertEquals(first, pcv3ViewModel.pcv3Presentation.value)
        assertEquals(listOf(listOf("/private/input")), cleaner.deletedPaths)
        assertEquals(
            listOf(Pcv3ReceiptStore.receiptFile(mockContext)),
            route.receiptFiles,
        )

        advanceTimeBy(500)
        runCurrent()
        assertEquals("a stale operation must not replace the current generation", first, pcv3ViewModel.pcv3Presentation.value)

        advanceTimeBy(500)
        runCurrent()
        assertEquals(current, pcv3ViewModel.pcv3Presentation.value)

        advanceTimeBy(500)
        runCurrent()
        assertEquals(terminal, pcv3ViewModel.pcv3Presentation.value)
        val terminalPollCount = route.refreshCalls

        advanceTimeBy(2_000)
        runCurrent()
        assertEquals("a Final presentation terminates the sole cadence", terminalPollCount, route.refreshCalls)
        assertTrue("the transferred password is cleared by the owner", password.all { it == '\u0000' })
        pcv3ViewModel.dismissPcv3("op_stale", generation = 6)
        pcv3ViewModel.dismissPcv3("op_current", generation = 7)
        runCurrent()
        assertEquals(1, route.dismissCalls)
        assertNull("only the exact terminal ticket dismisses the result", pcv3ViewModel.pcv3Presentation.value)
        pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
    }

    @Test
    fun `PCV3 poller pauses without a background duplicate and restored state never polls`() = runTest(mainDispatcherRule.testDispatcher) {
        val live = livePcv3("op_resume", generation = 9)
        val route = FakePcv3Operations(
            startResult = Result.success(live),
            refreshResults = ArrayDeque(
                listOf(
                    RefreshStep(
                        Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE")),
                        updateAuthority = false,
                        busy = true,
                    ),
                    RefreshStep(Result.success(finalPcv3("op_resume", generation = 9))),
                )
            ),
        )
        val pcv3ViewModel = OperationViewModel(route, RecordingPcv3Cleaner())

        pcv3ViewModel.startPcv3(mockContext, pcv3Transfer("password".toCharArray()))
        runCurrent()
        pcv3ViewModel.pausePolling()

        advanceTimeBy(2_000)
        runCurrent()
        assertEquals(0, route.refreshCalls)

        pcv3ViewModel.resumePolling()
        runCurrent()
        assertEquals("a refresh failure is not a locally invented terminal state", live, pcv3ViewModel.pcv3Presentation.value)
        assertEquals(1, route.refreshCalls)
        advanceTimeBy(500)
        runCurrent()
        assertTrue(pcv3ViewModel.pcv3Presentation.value is Pcv3Presentation.Final)
        val finalPollCount = route.refreshCalls
        advanceTimeBy(2_000)
        runCurrent()
        assertEquals("a Final presentation terminates polling", finalPollCount, route.refreshCalls)
        pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()

        val restoredRoute = FakePcv3Operations(
            startResult = Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE")),
            initialPresentation = restoredPcv3("op_1700000000000000000_7", generation = 10),
        )
        val restoredViewModel = OperationViewModel(restoredRoute, RecordingPcv3Cleaner())
        advanceTimeBy(2_000)
        runCurrent()
        assertTrue(restoredViewModel.pcv3Presentation.value is Pcv3Presentation.Restored)
        assertEquals("a deny-only Restored presentation has no refresh authority", 0, restoredRoute.refreshCalls)
        restoredViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
    }

    @Test
    fun `PCV3 action ticket rejects a stale rendered callback before manager invocation`() = runTest(mainDispatcherRule.testDispatcher) {
        val route = FakePcv3Operations(startResult = Result.success(livePcv3("op_action", generation = 4)))
        val pcv3ViewModel = OperationViewModel(route, RecordingPcv3Cleaner())
        pcv3ViewModel.startPcv3(mockContext, pcv3Transfer("password".toCharArray()))
        runCurrent()

        pcv3ViewModel.cancelPcv3("op_previous", 3)
        pcv3ViewModel.selectPcv3ConsentRole("op_action", 3, "primary")
        pcv3ViewModel.confirmPcv3Consent("op_previous", 4)
        pcv3ViewModel.refusePcv3Consent("op_action", 5)
        pcv3ViewModel.closePcv3Archive("op_previous", 3)
        pcv3ViewModel.dismissPcv3("op_action", 4)
        runCurrent()

        assertEquals(0, route.cancelCalls)
        assertEquals(0, route.selectRoleCalls)
        assertEquals(0, route.confirmCalls)
        assertEquals(0, route.refuseCalls)
        assertEquals(0, route.closeArchiveCalls)
        assertEquals("a live ticket has no terminal-dismiss authority", 0, route.dismissCalls)
        pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
    }

    @Test
    fun `PCV3 archive picker tombstone rejects stale callbacks and excludes output tickets`() =
        runTest(mainDispatcherRule.testDispatcher) {
            val original = archivePcv3("op-archive-a", generation = 40)
            val replacementOutput = outputPcv3("op-output-b", generation = 41)
            val replacementArchive = archivePcv3("op-archive-b", generation = 42)
            val route = FakePcv3Operations(
                startResult = Result.failure(Pcv3BridgeFailure("unused")),
                initialPresentation = original,
            )
            val opaqueRoot = mockk<Uri>().also { uri ->
                every { uri.toString() } throws AssertionError("URI string conversion")
                every { uri.path } throws AssertionError("URI path conversion")
            }
            var exportedRoot: Uri? = null
            route.exportArchiveAction = { operationId, generation, root ->
                assertEquals(replacementArchive.operationId, operationId)
                assertEquals(replacementArchive.generation, generation)
                exportedRoot = root
                Result.success(Unit)
            }
            val pcv3ViewModel = OperationViewModel(route, RecordingPcv3Cleaner())
            try {
                assertFalse(pcv3ViewModel.beginPcv3Archive(original.operationId, original.generation - 1))
                assertTrue(pcv3ViewModel.beginPcv3Archive(original.operationId, original.generation))

                route.publish(replacementOutput)
                runCurrent()
                assertNull(
                    "the outstanding archive picker is an ABA tombstone for a newer output",
                    pcv3ViewModel.beginPcv3Save(
                        replacementOutput.operationId,
                        replacementOutput.generation,
                    ),
                )
                pcv3ViewModel.completePcv3Archive(mockContext, opaqueRoot)
                runCurrent()
                assertEquals("the stale callback has zero native effect", 0, route.exportArchiveCalls)

                assertEquals(
                    "decrypted-output",
                    pcv3ViewModel.beginPcv3Save(
                        replacementOutput.operationId,
                        replacementOutput.generation,
                    ),
                )
                pcv3ViewModel.completePcv3Save(mockContext, null)
                runCurrent()

                route.publish(replacementArchive)
                runCurrent()
                assertTrue(
                    pcv3ViewModel.beginPcv3Archive(
                        replacementArchive.operationId,
                        replacementArchive.generation,
                    ),
                )
                pcv3ViewModel.completePcv3Archive(mockContext, null)
                runCurrent()
                assertEquals("a null callback has zero native effect", 0, route.exportArchiveCalls)

                assertTrue(
                    pcv3ViewModel.beginPcv3Archive(
                        replacementArchive.operationId,
                        replacementArchive.generation,
                    ),
                )
                assertFalse(
                    "one picker ticket cannot be replaced before its callback",
                    pcv3ViewModel.beginPcv3Archive(
                        replacementArchive.operationId,
                        replacementArchive.generation,
                    ),
                )
                pcv3ViewModel.completePcv3Archive(mockContext, opaqueRoot)
                pcv3ViewModel.completePcv3Archive(mockContext, opaqueRoot)
                runCurrent()

                assertEquals(1, route.exportArchiveCalls)
                assertSame(opaqueRoot, exportedRoot)
            } finally {
                pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
            }
        }

    @Test
    fun `cancelled suspended PCV3 start clears password and every transferred path once`() =
        runTest(mainDispatcherRule.testDispatcher) {
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val route = FakePcv3Operations(
                startResult = Result.success(livePcv3("op_cancel_start", generation = 11)),
                startEntered = entered,
                startRelease = release,
            )
            val cleaner = RecordingPcv3Cleaner()
            val pcv3ViewModel = OperationViewModel(route, cleaner)
            val password = "cancel-secret".toCharArray()
            val transfer = pcv3Transfer(
                password = password,
                keyfiles = listOf("/private/key-a", "/private/key-a", "/private/key-b"),
            )
            pcv3ViewModel.startPcv3(mockContext, transfer)
            entered.await()
            assertTrue("source replacement stays disabled before native start returns", pcv3ViewModel.pcv3Busy.value)

            pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()

            assertTrue(password.all { it == '\u0000' })
            assertEquals(
                listOf(listOf("/private/key-a", "/private/key-b", "/private/input")),
                cleaner.deletedPaths,
            )
            assertFalse("cancelled start no longer owns a mutable selection", pcv3ViewModel.pcv3Busy.value)
        }

    @Test
    fun `failed PCV3 start keeps private drain busy and one cadence reaches terminal release`() =
        runTest(mainDispatcherRule.testDispatcher) {
            val terminal = finalPcv3("op_drain", generation = 12)
            val route = FakePcv3Operations(
                startResult = Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_RELEASE_DENIED")),
                busyAfterStart = true,
                refreshResults = ArrayDeque(listOf(RefreshStep(Result.success(terminal)))),
            )
            val pcv3ViewModel = OperationViewModel(route, RecordingPcv3Cleaner())
            pcv3ViewModel.startPcv3(mockContext, pcv3Transfer("password".toCharArray()))
            runCurrent()
            assertTrue("private Draining state keeps replacement disabled", pcv3ViewModel.pcv3Busy.value)
            assertNull("private authority is never projected while draining", pcv3ViewModel.pcv3Presentation.value)
            assertNull("private cleanup is not replaced by a locally invented terminal error", pcv3ViewModel.pcv3Error.value)

            advanceTimeBy(500)
            runCurrent()

            assertEquals(1, route.refreshCalls)
            assertEquals(terminal, pcv3ViewModel.pcv3Presentation.value)
            assertFalse(pcv3ViewModel.pcv3Busy.value)
            val terminalPollCount = route.refreshCalls
            advanceTimeBy(2_000)
            runCurrent()
            assertEquals(terminalPollCount, route.refreshCalls)
            pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
        }

    @Test
    fun `transferred resource cleanup failure preserves native terminal result and surfaces cleanup error`() =
        runTest(mainDispatcherRule.testDispatcher) {
            val terminal = finalPcv3("op_cleanup_warning", generation = 13)
            val route = FakePcv3Operations(startResult = Result.success(terminal))
            val pcv3ViewModel = OperationViewModel(route, RecordingPcv3Cleaner(result = false))
            pcv3ViewModel.startPcv3(mockContext, pcv3Transfer("password".toCharArray()))
            runCurrent()

            assertSame("native terminal meaning must not be replaced", terminal, pcv3ViewModel.pcv3Presentation.value)
            assertTrue(pcv3ViewModel.pcv3Error.value is AppError.FileError.DeleteFailed)
            assertFalse(pcv3ViewModel.pcv3Busy.value)
            pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
        }

    @Test
    fun `failed PCV3 start surfaces its primary error before the transferred resource cleanup error`() =
        runTest(mainDispatcherRule.testDispatcher) {
            val route = FakePcv3Operations(
                startResult = Result.failure(Pcv3BridgeFailure("PCV3_BRIDGE_FAILURE")),
            )
            val pcv3ViewModel = OperationViewModel(route, RecordingPcv3Cleaner(result = false))

            pcv3ViewModel.startPcv3(mockContext, pcv3Transfer("password".toCharArray()))
            runCurrent()

            assertTrue(
                "the native start failure remains the first user-visible result",
                pcv3ViewModel.pcv3Error.value is AppError.OperationError.GenericOperation,
            )
            pcv3ViewModel.clearPcv3Error()
            assertTrue(
                "plaintext or keyfile cleanup uncertainty is not silently discarded",
                pcv3ViewModel.pcv3Error.value is AppError.FileError.DeleteFailed,
            )
            pcv3ViewModel.clearPcv3Error()
            assertNull(pcv3ViewModel.pcv3Error.value)
            pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
        }
    
    @Test
    fun `startForegroundServiceSafely swallows a background-start IllegalStateException`() {
        // On Android 12+ starting a foreground service from the background throws
        // ForegroundServiceStartNotAllowedException (an IllegalStateException subclass).
        // Because the service start happens AFTER the suspending op-start, the app may
        // have backgrounded in that window. The Go operation is already running, so we
        // must keep going (poll for progress) rather than crash the coroutine.
        mockkObject(OperationForegroundService.Companion)
        try {
            every { OperationForegroundService.start(any()) } throws
                IllegalStateException("ForegroundServiceStartNotAllowedException")

            // Must not rethrow.
            viewModel.startForegroundServiceSafely(mockContext)

            verify { OperationForegroundService.start(any()) }
        } finally {
            unmockkObject(OperationForegroundService.Companion)
        }
    }

    @Test
    fun `PCV3 native owner receives its Android reader and foreground host before transferred input cleanup`() =
        runTest(mainDispatcherRule.testDispatcher) {
            val events = mutableListOf<String>()
            every { mockContext.applicationContext } returns mockContext
            val route = FakePcv3Operations(
                startResult = Result.success(livePcv3("op_host", generation = 21)),
                events = events,
            )
            val cleaner = RecordingPcv3Cleaner(events = events)
            val host = Pcv3ForegroundHost { context ->
                assertSame(mockContext, context)
                events += "foreground-host"
            }
            val pcv3ViewModel = OperationViewModel(route, cleaner, host)

            pcv3ViewModel.startPcv3(mockContext, pcv3Transfer("password".toCharArray()))
            runCurrent()

            assertEquals(
                listOf("native-start", "resource-reader", "foreground-host", "transferred-cleanup"),
                events,
            )
            assertTrue(route.resourceReader is Pcv3AndroidResourceObservationReader)

            pcv3ViewModel.pausePolling()
            pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
            assertEquals("UI teardown has no authority to stop the service-owned pump", 1, events.count { it == "foreground-host" })
        }

    @Test
    fun `save rejection retains output for retry and preserves deferred input cleanup error`() =
        runTest(mainDispatcherRule.testDispatcher) {
            mockkObject(FileCopyService)
            val uri = mockk<Uri>()
            val live = outputPcv3("save-rejected-with-cleanup", generation = 49).copy(isCreation = true)
            val route = FakePcv3Operations(startResult = Result.success(live))
            val viewModel = OperationViewModel(route, RecordingPcv3Cleaner(result = false))
            try {
                viewModel.startPcv3(mockContext, pcv3Transfer("password".toCharArray()))
                runCurrent()
                assertTrue(viewModel.pcv3Error.value is AppError.FileError.DeleteFailed)
                coEvery { FileCopyService.openPcv3OutputDescriptor(mockContext, uri) } returns
                    Result.failure(AppError.FileError.SaveFailed(messageResId = R.string.pcv3_output_provider_unsupported))
                assertNotNull(viewModel.beginPcv3Save(live.operationId, live.generation))
                viewModel.completePcv3Save(mockContext, uri)
                runCurrent()
                assertTrue(viewModel.pcv3Error.value is AppError.FileError.SaveFailed)
                assertSame(live, viewModel.pcv3Presentation.value)
                assertEquals(0, route.saveOutputCalls)
                assertNotNull("another destination remains available", viewModel.beginPcv3Save(live.operationId, live.generation))
                viewModel.completePcv3Save(mockContext, null)
                viewModel.clearPcv3Error()
                assertTrue("save feedback must not erase sensitive input cleanup uncertainty",
                    viewModel.pcv3Error.value is AppError.FileError.DeleteFailed)
            } finally {
                viewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
                unmockkObject(FileCopyService)
            }
        }

    @Test
    fun `PCV3 save picker begins only for an exact live output tuple and uses fixed safe names`() =
        runTest(mainDispatcherRule.testDispatcher) {
            data class Case(
                val outcome: String,
                val completionClass: String,
                val artifact: Pcv3ArtifactMetadataView?,
                val expectedName: String,
                val forceProvenance: String? = null,
                val warnings: List<String>? = null,
            )

            val cases = listOf(
                Case("success", "clean", null, "decrypted-output"),
                Case(
                    "success",
                    "warning",
                    null,
                    "decrypted-output",
                    warnings = listOf("cleanup-incomplete"),
                ),
                Case(
                    "authenticated-degraded",
                    "warning",
                    null,
                    "decrypted-output",
                    forceProvenance = "verified",
                ),
                Case("force-partial", "warning", artifactMetadata("partial"), "decrypted-output.pcv3-recovery"),
                Case(
                    "force-unverified",
                    "warning",
                    artifactMetadata("unverified-forensic"),
                    "decrypted-output.pcv3-recovery",
                ),
            )

            cases.forEachIndexed { index, case ->
                val operationId = "op-save-name-$index"
                val route = FakePcv3Operations(
                    startResult = Result.failure(Pcv3BridgeFailure("unused")),
                    initialPresentation = outputPcv3(
                        operationId = operationId,
                        generation = index.toLong() + 30,
                        outcome = case.outcome,
                        completionClass = case.completionClass,
                        artifactMetadata = case.artifact,
                        forceProvenance = case.forceProvenance,
                        warnings = case.warnings,
                    ),
                )
                val pcv3ViewModel = OperationViewModel(route, RecordingPcv3Cleaner())
                try {
                    assertEquals(
                        case.expectedName,
                        pcv3ViewModel.beginPcv3Save(operationId, index.toLong() + 30),
                    )
                    assertNull("a second picker cannot replace the outstanding ticket", pcv3ViewModel.beginPcv3Save(operationId, index.toLong() + 30))
                    pcv3ViewModel.completePcv3Save(mockContext, null)
                    runCurrent()
                    assertEquals(0, route.saveOutputCalls)
                } finally {
                    pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
                }
            }

            val malformedForce = outputPcv3(
                operationId = "op-force-without-inspection",
                generation = 41,
                outcome = "force-partial",
                completionClass = "warning",
                artifactMetadata = null,
            )
            val malformedRoute = FakePcv3Operations(
                startResult = Result.failure(Pcv3BridgeFailure("unused")),
                initialPresentation = malformedForce,
            )
            val malformedViewModel = OperationViewModel(malformedRoute, RecordingPcv3Cleaner())
            assertNull(
                "a Force-looking scalar without the core-vetted artifact tuple grants no picker",
                malformedViewModel.beginPcv3Save(malformedForce.operationId, malformedForce.generation),
            )
            val invalidDegraded = outputPcv3(
                operationId = "op-invalid-degraded-provenance",
                generation = 411,
                outcome = "authenticated-degraded",
                completionClass = "warning",
                forceProvenance = "unverified",
            )
            malformedRoute.publish(invalidDegraded)
            assertNull(
                "an unverified degraded scalar without a vetted Force artifact grants no output action",
                malformedViewModel.beginPcv3Save(invalidDegraded.operationId, invalidDegraded.generation),
            )
            malformedViewModel.discardPcv3Output(invalidDegraded.operationId, invalidDegraded.generation)
            runCurrent()
            assertEquals(0, malformedRoute.discardOutputCalls)

            val restored = restoredPcv3("op-restored-no-output", generation = 42)
            malformedRoute.publish(restored)
            assertNull(
                "a restored receipt is deny-only and cannot recreate output authority",
                malformedViewModel.beginPcv3Save(restored.operationId, restored.generation),
            )
            malformedViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
        }

    @Test
    fun `PCV3 ViewModel denies Save and Discard for every non-none diagnostic`() =
        runTest(mainDispatcherRule.testDispatcher) {
            listOf(
                "resource-busy",
                "resource-insufficient",
                "resource-unknown",
                "PRIVATE diagnostic",
            ).forEachIndexed { index, diagnostic ->
                val live = outputPcv3(
                    operationId = "op-diagnostic-denied-$index",
                    generation = 420L + index,
                    diagnostic = diagnostic,
                )
                val route = FakePcv3Operations(
                    startResult = Result.failure(Pcv3BridgeFailure("unused")),
                    initialPresentation = live,
                )
                val diagnosticViewModel = OperationViewModel(route, RecordingPcv3Cleaner())
                try {
                    assertNull(
                        "diagnostic=$diagnostic cannot mint a Save picker ticket",
                        diagnosticViewModel.beginPcv3Save(live.operationId, live.generation),
                    )
                    diagnosticViewModel.discardPcv3Output(live.operationId, live.generation)
                    runCurrent()
                    assertEquals(
                        "diagnostic=$diagnostic cannot consume the live handle through Discard",
                        0,
                        route.discardOutputCalls,
                    )
                } finally {
                    diagnosticViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
                }
            }
        }

    @Test
    fun `PCV3 ViewModel denies output actions for invalid semantic stages`() =
        runTest(mainDispatcherRule.testDispatcher) {
            val clean = outputPcv3("op-invalid-clean-stage", generation = 440)
            val degraded = outputPcv3(
                operationId = "op-invalid-degraded-stage",
                generation = 441,
                outcome = "authenticated-degraded",
                completionClass = "warning",
                forceProvenance = "verified",
            )
            val recovery = outputPcv3(
                operationId = "op-invalid-force-stage",
                generation = 442,
                outcome = "force-partial",
                completionClass = "warning",
                artifactMetadata = artifactMetadata("partial"),
            )
            val invalidStages = listOf(
                clean.copy(
                    snapshot = clean.snapshot.copy(
                        semantic = clean.snapshot.semantic.copy(stage = "PRIVATE stage"),
                    ),
                ),
                degraded.copy(
                    snapshot = degraded.snapshot.copy(
                        semantic = degraded.snapshot.semantic.copy(stage = "none"),
                    ),
                ),
                degraded.copy(
                    snapshot = degraded.snapshot.copy(
                        semantic = degraded.snapshot.semantic.copy(stage = "record-auth"),
                    ),
                ),
                recovery.copy(
                    snapshot = recovery.snapshot.copy(
                        semantic = recovery.snapshot.semantic.copy(stage = "credential-policy"),
                    ),
                ),
                recovery.copy(
                    snapshot = recovery.snapshot.copy(
                        semantic = recovery.snapshot.semantic.copy(stage = "PRIVATE stage"),
                    ),
                ),
            )

            invalidStages.forEach { live ->
                val route = FakePcv3Operations(
                    startResult = Result.failure(Pcv3BridgeFailure("unused")),
                    initialPresentation = live,
                )
                val invalidViewModel = OperationViewModel(route, RecordingPcv3Cleaner())
                try {
                    runCurrent()
                    assertNull(
                        "stage=${live.snapshot.semantic.stage} cannot mint a Save ticket",
                        invalidViewModel.beginPcv3Save(live.operationId, live.generation),
                    )
                    invalidViewModel.discardPcv3Output(live.operationId, live.generation)
                    runCurrent()
                    assertEquals(0, route.discardOutputCalls)
                } finally {
                    invalidViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
                }
            }
        }

    @Test
    fun `PCV3 ViewModel permits explicit Discard for retained decrypted output`() =
        runTest(mainDispatcherRule.testDispatcher) {
            val decryptedOutputs = listOf(
                outputPcv3("op-clean-discard-denied", generation = 430),
                outputPcv3(
                    operationId = "op-degraded-discard-denied",
                    generation = 431,
                    outcome = "authenticated-degraded",
                    completionClass = "warning",
                    forceProvenance = "verified",
                ),
            )
            decryptedOutputs.forEach { live ->
                val route = FakePcv3Operations(
                    startResult = Result.failure(Pcv3BridgeFailure("unused")),
                    initialPresentation = live,
                )
                val decryptedViewModel = OperationViewModel(route, RecordingPcv3Cleaner())
                try {
                    decryptedViewModel.discardPcv3Output(live.operationId, live.generation)
                    runCurrent()
                    assertEquals(
                        "retained plaintext must be explicitly discardable",
                        1,
                        route.discardOutputCalls,
                    )
                    assertEquals(
                        "decrypted-output",
                        decryptedViewModel.beginPcv3Save(live.operationId, live.generation),
                    )
                    decryptedViewModel.completePcv3Save(mockContext, null)
                    runCurrent()
                } finally {
                    decryptedViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
                }
            }
        }

    @Test
    fun `PCV3 stale picker callback cannot consume a newer generation ticket`() =
        runTest(mainDispatcherRule.testDispatcher) {
            mockkObject(FileCopyService)
            val staleUri = mockk<Uri>()
            val original = outputPcv3("op-save-stale-before", generation = 51)
            val replacement = outputPcv3("op-replacement", generation = 52)
            val route = FakePcv3Operations(
                startResult = Result.failure(Pcv3BridgeFailure("unused")),
                initialPresentation = original,
            )
            val pcv3ViewModel = OperationViewModel(route, RecordingPcv3Cleaner())
            try {
                assertEquals(
                    "decrypted-output",
                    pcv3ViewModel.beginPcv3Save(original.operationId, original.generation),
                )
                route.publish(replacement)
                runCurrent()
                assertNull(
                    "a stale picker ticket remains a one-result tombstone and blocks an ABA replacement",
                    pcv3ViewModel.beginPcv3Save(
                        replacement.operationId,
                        replacement.generation,
                    ),
                )

                pcv3ViewModel.completePcv3Save(mockContext, staleUri)
                runCurrent()
                coVerify(exactly = 0) {
                    FileCopyService.openPcv3OutputDescriptor(mockContext, staleUri)
                }
                assertEquals(0, route.saveOutputCalls)

                assertEquals(
                    "decrypted-output",
                    pcv3ViewModel.beginPcv3Save(
                        replacement.operationId,
                        replacement.generation,
                    ),
                )
                pcv3ViewModel.completePcv3Save(mockContext, null)
                runCurrent()
            } finally {
                pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
                unmockkObject(FileCopyService)
            }
        }

    @Test
    fun `PCV3 discard retains the outstanding picker tombstone until its callback`() =
        runTest(mainDispatcherRule.testDispatcher) {
            mockkObject(FileCopyService)
            val staleUri = mockk<Uri>()
            val original = outputPcv3(
                operationId = "op-save-then-discard",
                generation = 521,
                outcome = "force-partial",
                completionClass = "warning",
                artifactMetadata = artifactMetadata("partial"),
            )
            val replacement = outputPcv3("op-after-discard", generation = 522)
            val route = FakePcv3Operations(
                startResult = Result.failure(Pcv3BridgeFailure("unused")),
                initialPresentation = original,
            )
            val pcv3ViewModel = OperationViewModel(route, RecordingPcv3Cleaner())
            try {
                assertEquals(
                    "decrypted-output.pcv3-recovery",
                    pcv3ViewModel.beginPcv3Save(original.operationId, original.generation),
                )
                pcv3ViewModel.discardPcv3Output(original.operationId, original.generation)
                runCurrent()
                assertEquals(1, route.discardOutputCalls)

                route.publish(replacement)
                runCurrent()
                assertNull(
                    "Discard must not expose a newer ticket to the outstanding A callback",
                    pcv3ViewModel.beginPcv3Save(
                        replacement.operationId,
                        replacement.generation,
                    ),
                )

                pcv3ViewModel.completePcv3Save(mockContext, staleUri)
                runCurrent()
                coVerify(exactly = 0) {
                    FileCopyService.openPcv3OutputDescriptor(mockContext, staleUri)
                }
                assertEquals("the stale callback cannot invoke Save", 0, route.saveOutputCalls)

                assertEquals(
                    "decrypted-output",
                    pcv3ViewModel.beginPcv3Save(
                        replacement.operationId,
                        replacement.generation,
                    ),
                )
                pcv3ViewModel.completePcv3Save(mockContext, null)
                runCurrent()
            } finally {
                pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
                unmockkObject(FileCopyService)
            }
        }

    @Test
    fun `PCV3 save picker ticket is one shot and closes only a descriptor not transferred to the exact generation`() =
        runTest(mainDispatcherRule.testDispatcher) {
            mockkObject(FileCopyService)
            val uri = mockk<Uri>()
            val staleAfterUri = mockk<Uri>()
            val forceUri = mockk<Uri>()
            val blockedUri = mockk<Uri>()
            val failureUri = mockk<Uri>()
            val cancellationUri = mockk<Uri>()
            val currentDescriptor = mockk<ParcelFileDescriptor>(relaxed = true)
            val staleDescriptor = mockk<ParcelFileDescriptor>(relaxed = true)
            val forceDescriptor = mockk<ParcelFileDescriptor>(relaxed = true)
            val blockedDescriptor = mockk<ParcelFileDescriptor>(relaxed = true)
            val failureDescriptor = mockk<ParcelFileDescriptor>(relaxed = true)
            val cancellationDescriptor = mockk<ParcelFileDescriptor>(relaxed = true)
            val ownedViewModels = mutableListOf<OperationViewModel>()
            try {
                val current = outputPcv3(
                    operationId = "op-save-current",
                    generation = 50,
                    outcome = "success",
                    completionClass = "warning",
                    warnings = listOf("cleanup-incomplete"),
                )
                val currentRoute = FakePcv3Operations(
                    startResult = Result.failure(Pcv3BridgeFailure("unused")),
                    initialPresentation = current,
                )
                val currentViewModel = OperationViewModel(currentRoute, RecordingPcv3Cleaner())
                ownedViewModels += currentViewModel
                coEvery { FileCopyService.openPcv3OutputDescriptor(mockContext, uri) } returns
                    Result.success(currentDescriptor)

                assertEquals("decrypted-output", currentViewModel.beginPcv3Save(current.operationId, current.generation))
                currentViewModel.completePcv3Save(mockContext, null)
                runCurrent()
                coVerify(exactly = 0) { FileCopyService.openPcv3OutputDescriptor(mockContext, uri) }
                assertEquals("picker cancellation consumes no native capability", 0, currentRoute.saveOutputCalls)

                assertEquals("decrypted-output", currentViewModel.beginPcv3Save(current.operationId, current.generation))
                currentViewModel.completePcv3Save(mockContext, uri)
                currentViewModel.completePcv3Save(mockContext, uri)
                runCurrent()
                assertEquals(1, currentRoute.saveOutputCalls)
                assertSame(currentDescriptor, currentRoute.savedDestinations.single())
                verify(exactly = 0) { currentDescriptor.close() }

                val recoveryArtifact = outputPcv3(
                    operationId = "op-discard-recovery-artifact",
                    generation = 500,
                    outcome = "force-partial",
                    completionClass = "warning",
                    artifactMetadata = artifactMetadata("partial"),
                )
                val recoveryArtifactRoute = FakePcv3Operations(
                    startResult = Result.failure(Pcv3BridgeFailure("unused")),
                    initialPresentation = recoveryArtifact,
                )
                val recoveryArtifactViewModel = OperationViewModel(
                    recoveryArtifactRoute,
                    RecordingPcv3Cleaner(),
                )
                ownedViewModels += recoveryArtifactViewModel
                recoveryArtifactViewModel.discardPcv3Output(
                    recoveryArtifact.operationId,
                    recoveryArtifact.generation,
                )
                runCurrent()
                assertEquals(1, recoveryArtifactRoute.discardOutputCalls)

                val openEntered = CompletableDeferred<Unit>()
                val allowOpen = CompletableDeferred<Unit>()
                val blocked = outputPcv3("op-save-blocked-open", generation = 501)
                val blockedRoute = FakePcv3Operations(
                    startResult = Result.failure(Pcv3BridgeFailure("unused")),
                    initialPresentation = blocked,
                )
                val blockedViewModel = OperationViewModel(blockedRoute, RecordingPcv3Cleaner())
                ownedViewModels += blockedViewModel
                coEvery { FileCopyService.openPcv3OutputDescriptor(mockContext, blockedUri) } coAnswers {
                    openEntered.complete(Unit)
                    allowOpen.await()
                    Result.success(blockedDescriptor)
                }
                assertEquals(
                    "decrypted-output",
                    blockedViewModel.beginPcv3Save(blocked.operationId, blocked.generation),
                )
                blockedViewModel.completePcv3Save(mockContext, blockedUri)
                runCurrent()
                openEntered.await()
                assertNull(
                    "an in-flight provider open must not mint a second picker ticket",
                    blockedViewModel.beginPcv3Save(blocked.operationId, blocked.generation),
                )
                allowOpen.complete(Unit)
                runCurrent()
                assertEquals(1, blockedRoute.saveOutputCalls)

                val staleAfter = outputPcv3("op-save-stale-after", generation = 53)
                val staleAfterRoute = FakePcv3Operations(
                    startResult = Result.failure(Pcv3BridgeFailure("unused")),
                    initialPresentation = staleAfter,
                )
                val staleAfterViewModel = OperationViewModel(staleAfterRoute, RecordingPcv3Cleaner())
                ownedViewModels += staleAfterViewModel
                coEvery { FileCopyService.openPcv3OutputDescriptor(mockContext, staleAfterUri) } coAnswers {
                    staleAfterRoute.publish(outputPcv3("op-replaced-after-open", generation = 54))
                    Result.success(staleDescriptor)
                }
                assertEquals(
                    "decrypted-output",
                    staleAfterViewModel.beginPcv3Save(staleAfter.operationId, staleAfter.generation),
                )
                staleAfterViewModel.completePcv3Save(mockContext, staleAfterUri)
                runCurrent()
                assertEquals(0, staleAfterRoute.saveOutputCalls)
                verify(exactly = 1) { staleDescriptor.close() }

                val events = mutableListOf<String>()
                val force = outputPcv3(
                    operationId = "op-save-force",
                    generation = 55,
                    outcome = "force-unverified",
                    completionClass = "warning",
                    artifactMetadata = artifactMetadata("unverified-forensic"),
                )
                val forceRoute = FakePcv3Operations(
                    startResult = Result.failure(Pcv3BridgeFailure("unused")),
                    initialPresentation = force,
                    events = events,
                )
                val forceViewModel = OperationViewModel(forceRoute, RecordingPcv3Cleaner())
                ownedViewModels += forceViewModel
                coEvery { FileCopyService.validatePcv3RecoveryDestination(mockContext, forceUri) } coAnswers {
                    events += "validate-name"
                    Result.success(Unit)
                }
                coEvery { FileCopyService.openPcv3OutputDescriptor(mockContext, forceUri) } coAnswers {
                    events += "open-descriptor"
                    Result.success(forceDescriptor)
                }

                assertEquals(
                    "decrypted-output.pcv3-recovery",
                    forceViewModel.beginPcv3Save(force.operationId, force.generation),
                )
                forceViewModel.completePcv3Save(mockContext, forceUri)
                runCurrent()
                assertEquals(
                    listOf("validate-name", "open-descriptor", "save-output"),
                    events,
                )
                assertSame(forceDescriptor, forceRoute.savedDestinations.single())
                coVerify(exactly = 0) { FileCopyService.saveFileToUri(any(), any(), any(), any()) }

                val postNativeFailure = outputPcv3("op-save-native-failure", generation = 56)
                val postNativeFailureRoute = FakePcv3Operations(
                    startResult = Result.failure(Pcv3BridgeFailure("unused")),
                    initialPresentation = postNativeFailure,
                ).apply {
                    saveOutputAction = {
                        Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_FAILURE"))
                    }
                }
                val postNativeFailureViewModel = OperationViewModel(
                    postNativeFailureRoute,
                    RecordingPcv3Cleaner(),
                )
                ownedViewModels += postNativeFailureViewModel
                coEvery { FileCopyService.openPcv3OutputDescriptor(mockContext, failureUri) } returns
                    Result.success(failureDescriptor)
                assertEquals(
                    "decrypted-output",
                    postNativeFailureViewModel.beginPcv3Save(
                        postNativeFailure.operationId,
                        postNativeFailure.generation,
                    ),
                )
                postNativeFailureViewModel.completePcv3Save(mockContext, failureUri)
                runCurrent()
                assertEquals(1, postNativeFailureRoute.saveOutputCalls)
                verify(exactly = 0) { failureDescriptor.close() }
                verify(exactly = 0) { failureDescriptor.detachFd() }

                val exactCancellation = CancellationException("exact post-native cancellation")
                val postNativeCancellation = outputPcv3("op-save-native-cancellation", generation = 57)
                val postNativeCancellationRoute = FakePcv3Operations(
                    startResult = Result.failure(Pcv3BridgeFailure("unused")),
                    initialPresentation = postNativeCancellation,
                ).apply {
                    saveOutputAction = { throw exactCancellation }
                }
                val postNativeCancellationViewModel = OperationViewModel(
                    postNativeCancellationRoute,
                    RecordingPcv3Cleaner(),
                )
                ownedViewModels += postNativeCancellationViewModel
                coEvery { FileCopyService.openPcv3OutputDescriptor(mockContext, cancellationUri) } returns
                    Result.success(cancellationDescriptor)
                assertEquals(
                    "decrypted-output",
                    postNativeCancellationViewModel.beginPcv3Save(
                        postNativeCancellation.operationId,
                        postNativeCancellation.generation,
                    ),
                )
                postNativeCancellationViewModel.completePcv3Save(mockContext, cancellationUri)
                runCurrent()
                assertEquals(1, postNativeCancellationRoute.saveOutputCalls)
                assertSame(exactCancellation, postNativeCancellationRoute.saveCancellation)
                verify(exactly = 0) { cancellationDescriptor.close() }
                verify(exactly = 0) { cancellationDescriptor.detachFd() }
            } finally {
                ownedViewModels.forEach { it.viewModelScope.coroutineContext[Job]?.cancelAndJoin() }
                unmockkObject(FileCopyService)
            }
        }

    @Test
    fun `PCV3 creation save claims the created-volume target and reaches the native save`() =
        runTest(mainDispatcherRule.testDispatcher) {
            mockkObject(FileCopyService)
            val uri = mockk<Uri>()
            val descriptor = mockk<ParcelFileDescriptor>(relaxed = true)
            val creation = outputPcv3(
                operationId = "op-save-created-volume",
                generation = 60,
                outcome = "success",
                completionClass = "clean",
            ).copy(isCreation = true)
            val route = FakePcv3Operations(
                startResult = Result.failure(Pcv3BridgeFailure("unused")),
                initialPresentation = creation,
            )
            val viewModel = OperationViewModel(route, RecordingPcv3Cleaner())
            try {
                coEvery { FileCopyService.openPcv3OutputDescriptor(mockContext, uri) } returns
                    Result.success(descriptor)

                assertEquals(
                    "created-volume.pcv",
                    viewModel.beginPcv3Save(creation.operationId, creation.generation),
                )
                viewModel.completePcv3Save(mockContext, uri)
                runCurrent()
                assertEquals(
                    "the creation claim must project the created-volume target, not a decrypted output",
                    1,
                    route.saveOutputCalls,
                )
                assertSame(descriptor, route.savedDestinations.single())
                verify(exactly = 0) { descriptor.close() }
            } finally {
                viewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
                unmockkObject(FileCopyService)
            }
        }

    @Test
    fun `PCV3 artifact pages preserve decimal evidence and delayed work cannot outlive its exact ticket`() =
        runTest(mainDispatcherRule.testDispatcher) {
            val max = "18446744073709551615"
            val last = "18446744073709551614"
            val metadata = artifactMetadata("partial").copy(
                plaintextLength = max,
                rangeCount = max,
                verifiedCount = last,
                unverifiedCount = "0",
                missingCount = "1",
            )
            val final = finalPcv3(
                operationId = "op-artifact-final",
                generation = 60,
                snapshot = outputSnapshot("force-partial", "warning"),
                artifactMetadata = metadata,
            )
            val route = FakePcv3Operations(
                startResult = Result.failure(Pcv3BridgeFailure("unused")),
                initialPresentation = final,
            )
            val pageZero = Pcv3ArtifactPageView(
                offsetDecimal = "0",
                ranges = listOf(Pcv3ArtifactRangeView("0", "0", "17", "verified")),
            )
            route.artifactLoader = { _, _, offset, limit ->
                assertEquals("0", offset)
                assertEquals(128, limit)
                Result.success(pageZero)
            }
            val pcv3ViewModel = OperationViewModel(route, RecordingPcv3Cleaner())

            pcv3ViewModel.inspectPcv3Artifact(final.operationId, final.generation)
            assertEquals(Pcv3ArtifactDetailsUiState.Loading, pcv3ViewModel.pcv3ArtifactDetails.value)
            runCurrent()
            assertEquals(
                Pcv3ArtifactDetailsUiState.Ready(metadata, pageZero),
                pcv3ViewModel.pcv3ArtifactDetails.value,
            )

            val lastPage = Pcv3ArtifactPageView(
                offsetDecimal = last,
                ranges = listOf(Pcv3ArtifactRangeView(last, max, max, "missing")),
            )
            route.artifactLoader = { id, generation, offset, limit ->
                assertEquals(final.operationId, id)
                assertEquals(final.generation, generation)
                assertEquals(last, offset)
                assertEquals(128, limit)
                Result.success(lastPage)
            }
            pcv3ViewModel.loadPcv3ArtifactPage(final.operationId, final.generation, last)
            assertEquals(Pcv3ArtifactDetailsUiState.Loading, pcv3ViewModel.pcv3ArtifactDetails.value)
            runCurrent()
            assertEquals(
                Pcv3ArtifactDetailsUiState.Ready(metadata, lastPage),
                pcv3ViewModel.pcv3ArtifactDetails.value,
            )

            route.artifactLoader = { _, _, _, _ ->
                Result.failure(Pcv3BridgeFailure("provider-private-detail"))
            }
            pcv3ViewModel.loadPcv3ArtifactPage(final.operationId, final.generation, "0")
            assertEquals(Pcv3ArtifactDetailsUiState.Loading, pcv3ViewModel.pcv3ArtifactDetails.value)
            runCurrent()
            assertEquals(
                Pcv3ArtifactDetailsUiState.Failed("PCV3_ARTIFACT_INSPECTION_UNAVAILABLE"),
                pcv3ViewModel.pcv3ArtifactDetails.value,
            )
            pcv3ViewModel.closePcv3ArtifactInspection(final.operationId, final.generation)
            assertEquals(Pcv3ArtifactDetailsUiState.Closed, pcv3ViewModel.pcv3ArtifactDetails.value)
            assertEquals(0, route.discardOutputCalls)
            assertEquals(0, route.dismissCalls)

            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val live = outputPcv3(
                operationId = "op-artifact-live",
                generation = 61,
                outcome = "force-partial",
                completionClass = "warning",
                artifactMetadata = metadata,
            )
            val concurrentRoute = FakePcv3Operations(
                startResult = Result.failure(Pcv3BridgeFailure("unused")),
                initialPresentation = live,
            )
            concurrentRoute.artifactLoader = { _, _, _, _ ->
                entered.complete(Unit)
                release.await()
                Result.success(pageZero)
            }
            val concurrentViewModel = OperationViewModel(concurrentRoute, RecordingPcv3Cleaner())
            pcv3ViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()

            concurrentViewModel.inspectPcv3Artifact(live.operationId, live.generation)
            runCurrent()
            entered.await()
            assertEquals(Pcv3ArtifactDetailsUiState.Loading, concurrentViewModel.pcv3ArtifactDetails.value)
            concurrentViewModel.discardPcv3Output(live.operationId, live.generation)
            assertEquals(
                "an output action invalidates passive detail publication before native dispatch",
                Pcv3ArtifactDetailsUiState.Closed,
                concurrentViewModel.pcv3ArtifactDetails.value,
            )
            runCurrent()
            release.complete(Unit)
            runCurrent()
            assertEquals(1, concurrentRoute.discardOutputCalls)
            assertEquals(
                "a delayed page cannot publish across the output action ticket",
                Pcv3ArtifactDetailsUiState.Closed,
                concurrentViewModel.pcv3ArtifactDetails.value,
            )

            val race = finalPcv3(
                operationId = "op-artifact-page-race",
                generation = 63,
                snapshot = outputSnapshot("force-partial", "warning"),
                artifactMetadata = artifactMetadata("partial"),
            )
            val raceRoute = FakePcv3Operations(
                startResult = Result.failure(Pcv3BridgeFailure("unused")),
                initialPresentation = race,
            )
            val raceViewModel = OperationViewModel(raceRoute, RecordingPcv3Cleaner())
            val delayedFailureEntered = CompletableDeferred<Unit>()
            val releaseDelayedFailure = CompletableDeferred<Unit>()
            val newerPage = Pcv3ArtifactPageView(
                offsetDecimal = "1",
                ranges = listOf(Pcv3ArtifactRangeView("1", "17", "17", "missing")),
            )
            raceRoute.artifactLoader = { _, _, offset, _ ->
                when (offset) {
                    "0" -> {
                        delayedFailureEntered.complete(Unit)
                        releaseDelayedFailure.await()
                        Result.failure(Pcv3BridgeFailure("private-old-failure"))
                    }
                    "1" -> Result.success(newerPage)
                    else -> error("unexpected offset")
                }
            }
            raceViewModel.loadPcv3ArtifactPage(race.operationId, race.generation, "0")
            runCurrent()
            delayedFailureEntered.await()
            raceViewModel.loadPcv3ArtifactPage(race.operationId, race.generation, "1")
            runCurrent()
            assertEquals(
                Pcv3ArtifactDetailsUiState.Ready(race.artifactMetadata!!, newerPage),
                raceViewModel.pcv3ArtifactDetails.value,
            )
            releaseDelayedFailure.complete(Unit)
            runCurrent()
            assertEquals(
                "a delayed A failure cannot overwrite the newer B page",
                Pcv3ArtifactDetailsUiState.Ready(race.artifactMetadata, newerPage),
                raceViewModel.pcv3ArtifactDetails.value,
            )

            val delayedSuccessEntered = CompletableDeferred<Unit>()
            val releaseDelayedSuccess = CompletableDeferred<Unit>()
            raceRoute.artifactLoader = { _, _, offset, _ ->
                when (offset) {
                    "0" -> {
                        delayedSuccessEntered.complete(Unit)
                        releaseDelayedSuccess.await()
                        Result.success(pageZero)
                    }
                    "1" -> Result.failure(Pcv3BridgeFailure("private-new-failure"))
                    else -> error("unexpected offset")
                }
            }
            raceViewModel.loadPcv3ArtifactPage(race.operationId, race.generation, "0")
            runCurrent()
            delayedSuccessEntered.await()
            raceViewModel.loadPcv3ArtifactPage(race.operationId, race.generation, "1")
            runCurrent()
            assertEquals(
                Pcv3ArtifactDetailsUiState.Failed("PCV3_ARTIFACT_INSPECTION_UNAVAILABLE"),
                raceViewModel.pcv3ArtifactDetails.value,
            )
            releaseDelayedSuccess.complete(Unit)
            runCurrent()
            assertEquals(
                "a delayed A success cannot overwrite the newer B failure",
                Pcv3ArtifactDetailsUiState.Failed("PCV3_ARTIFACT_INSPECTION_UNAVAILABLE"),
                raceViewModel.pcv3ArtifactDetails.value,
            )
            raceViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()

            val restored = restoredPcv3("op-artifact-restored", generation = 62)
            concurrentRoute.publish(restored)
            concurrentViewModel.inspectPcv3Artifact(restored.operationId, restored.generation)
            concurrentViewModel.discardPcv3Output(restored.operationId, restored.generation)
            runCurrent()
            assertEquals("restored receipt exposes no passive native handle", 1, concurrentRoute.artifactPageCalls)
            assertEquals("restored receipt exposes no output action", 1, concurrentRoute.discardOutputCalls)
            concurrentViewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
        }

    private fun resetOperationState() {
        setOperationState(null)
    }

    private fun setOperationState(state: OperationState?) {
        val field = OperationManager::class.java.getDeclaredField("_currentOperation")
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val flow = field.get(OperationManager) as MutableStateFlow<OperationState?>
        flow.value = state
    }


    @Test
    fun `archive preparation retains input paths until same native owner is terminal`() = runTest {
        every { mockContext.applicationContext } returns mockContext
        val live = livePcv3("archive-owner", 501, "preparing-input")
        val route = FakePcv3Operations(Result.success(live))
        val cleaner = RecordingPcv3Cleaner()
        val model = OperationViewModel(route, cleaner, Pcv3ForegroundHost { })
        val password = "secret".toCharArray()
        val files = listOf("/private/a", "/private/b")
        model.startPcv3(mockContext, Pcv3OperationTransfer(
            intent = Pcv3OperationIntent(Pcv3FormatIntent.NORMAL, action = Pcv3ActionIntent.CREATE),
            request = Pcv3WriteRequest("write-normal", "password", "none", files[0], "/private/output", emptyList(), "", "standard", false, inputFiles = files),
            password = password,
        ))
        runCurrent()
        assertTrue("paths must survive asynchronous ZIP reads", cleaner.deletedPaths.isEmpty())
        assertTrue("input ownership must not prolong password lifetime", password.all { it == '\u0000' })
        route.publish(outputPcv3("archive-owner", 501))
        runCurrent()
        assertEquals(listOf(files), cleaner.deletedPaths)
        model.pausePolling()
        model.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
    }

    @Test
    fun `PCV3 terminal keeps selection busy until transferred plaintext cleanup finishes`() = runTest(mainDispatcherRule.testDispatcher) {
        every { mockContext.applicationContext } returns mockContext
        val source = File(testFilesDir, "picocrypt_files/staging/owned.txt")
        assertTrue(source.parentFile!!.mkdirs())
        source.writeText("owned plaintext")
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val route = FakePcv3Operations(Result.success(livePcv3("cleanup-owner", 503, "preparing-input")))
        val cleaner = Pcv3TransferredResourceCleaner { context, paths ->
            entered.complete(Unit)
            release.await()
            var complete = true
            paths.forEach { if (!FileCopyService.deleteFile(context, it)) complete = false }
            complete
        }
        val model = OperationViewModel(route, cleaner, Pcv3ForegroundHost { })
        val busyChanges = mutableListOf<Boolean>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
            model.pcv3Busy.collect { busyChanges += it }
        }
        try {
            model.startPcv3(mockContext, Pcv3OperationTransfer(
                intent = Pcv3OperationIntent(Pcv3FormatIntent.NORMAL, action = Pcv3ActionIntent.CREATE),
                request = Pcv3WriteRequest("write-normal", "password", "none", source.absolutePath,
                    "/private/output", emptyList(), "", "standard", false, inputFiles = listOf(source.absolutePath)),
                password = "secret".toCharArray(),
            ))
            busyChanges.clear()
            runCurrent()
            route.publish(finalPcv3("cleanup-owner", 503))
            entered.await()
            runCurrent()
            assertTrue("Native Final must not enable replacement while old plaintext cleanup is pending", model.pcv3Busy.value)
            assertTrue("The real source proves cleanup is still pending", source.exists())

            model.dismissPcv3("cleanup-owner", 503)
            runCurrent()
            assertTrue("Dismissing Final must not release selection ownership before cleanup", model.pcv3Busy.value)
            assertFalse("Final and dismissal must never briefly publish an available selection", false in busyChanges)
            release.complete(Unit)
            model.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
            assertFalse("Transferred plaintext must be deleted before replacement becomes enabled", source.exists())
            assertFalse(model.pcv3Busy.value)
        } finally {
            release.complete(Unit)
            model.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
        }
    }

    @Test
    fun `replacement ViewModel cannot acquire inputs while previous host cleanup survives`() = runTest(mainDispatcherRule.testDispatcher) {
        every { mockContext.applicationContext } returns mockContext
        val source = File(testFilesDir, "picocrypt_files/staging/shared.txt")
        assertTrue(source.parentFile!!.mkdirs())
        source.writeText("old owner plaintext")
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val working = Pcv3SnapshotData(
            "preparing-input", emptyList(), "unknown-outcome", "none", "PCV3_UNKNOWN",
            "none", "none", "none", false, "none", "none", "none", "none", "unknown",
            emptyList(), emptyList(), false,
        )
        val terminal = working.copy(
            statusCode = "none", outcome = "operation-failed", stage = "cancellation",
            code = "PCV3_OPERATION_FAILED", diagnostic = "cancellation", completionClass = "refused",
        )
        val oldSnapshot = AtomicReference(working)
        val nextSnapshot = AtomicReference(working)
        fun nativeOperation(id: String, snapshot: AtomicReference<Pcv3SnapshotData>): Pcv3OperationCapability =
            mockk<Pcv3OperationCapability>().also { operation ->
                every { operation.id } returns id
                every { operation.snapshot() } answers { snapshot.get() }
                every { operation.cancel() } answers { snapshot.set(terminal); terminal }
                every { operation.release() } returns ""
                every { operation.consent() } returns null
                every { operation.archive() } returns null
                every { operation.output() } returns null
                every { operation.artifactInspection() } returns null
                every { operation.resourceChallenge() } returns null
            }
        val oldNative = nativeOperation("old-host", oldSnapshot)
        val nextNative = nativeOperation("replacement-host", nextSnapshot)
        val bridge = GoBridge.pcv3Bridge
        mockkObject(bridge, StartupCleanup, FileCopyService, OperationForegroundService.Companion)
        every { StartupCleanup.allowsPcv3Dispatch() } returns true
        every { OperationForegroundService.start(any()) } returns Unit
        every { bridge.start(any(), any()) } returnsMany listOf(
            Result.success(Pcv3StartData("", oldNative)),
            Result.success(Pcv3StartData("", nextNative)),
        )
        coEvery { FileCopyService.deleteFile(mockContext, source.absolutePath) } coAnswers {
            entered.complete(Unit)
            release.await()
            NoFollowFileTree.delete(testFilesDir, source)
        }
        val request = Pcv3WriteRequest("write-normal", "password", "none", source.absolutePath,
            "/private/output", emptyList(), "", "standard", false, inputFiles = listOf(source.absolutePath))
        val oldModel = OperationViewModel()
        var replacement: OperationViewModel? = null
        try {
            oldModel.startPcv3(mockContext, Pcv3OperationTransfer(
                intent = Pcv3OperationIntent(Pcv3FormatIntent.NORMAL, action = Pcv3ActionIntent.CREATE),
                request = request, password = "old-secret".toCharArray(),
            ))
            OperationManager.currentPcv3Presentation.first { it is Pcv3Presentation.Live }
            oldSnapshot.set(terminal)
            val final = OperationManager.refreshPcv3().getOrThrow() as Pcv3Presentation.Final
            entered.await()
            oldModel.viewModelScope.coroutineContext[Job]!!.cancel()
            val newModel = OperationViewModel().also { replacement = it }
            val replacementInitiallyBusy = newModel.pcv3Busy.value
            assertTrue(OperationManager.dismissPcv3(final.operationId, final.generation))
            val newRequest = request.copy()
            val attempted = OperationManager.startPcv3(newRequest, "new-secret".toCharArray(), Pcv3ReceiptStore.receiptFile(mockContext))
            val rejectedPassword = "rejected-host-secret".toCharArray()
            newModel.startPcv3(mockContext, Pcv3OperationTransfer(
                intent = Pcv3OperationIntent(Pcv3FormatIntent.NORMAL, action = Pcv3ActionIntent.CREATE),
                request = newRequest, password = rejectedPassword,
            ))
            assertTrue("A refused host must clear its password without acquiring file custody", rejectedPassword.all { it == '\u0000' })
            assertEquals("A refused host must not delete the previous owner's input", "old owner plaintext", source.readText())
            assertTrue("Dismissing native Final must retain process-wide input occupancy", newModel.pcv3Busy.value)
            release.complete(Unit)
            oldModel.viewModelScope.coroutineContext[Job]!!.join()

            assertTrue(
                "A replacement VM exposed selection=$replacementInitiallyBusy, native start accepted=${attempted.isSuccess}, source remains=${source.exists()}",
                replacementInitiallyBusy,
            )
            assertTrue("Process owner must refuse an unowned start while old cleanup is pending", attempted.isFailure)
            assertNull("No replacement operation may own paths being deleted by the old host", OperationManager.currentPcv3Presentation.value)
            assertFalse("The old owner must finish deleting its own plaintext", source.exists())
            runCurrent()
            assertFalse("A completed cleanup must allow a fresh selection", newModel.pcv3Busy.value)

            val newBytes = "fresh selection after old cleanup".toByteArray()
            source.writeBytes(newBytes)
            newModel.startPcv3(mockContext, Pcv3OperationTransfer(
                intent = Pcv3OperationIntent(Pcv3FormatIntent.NORMAL, action = Pcv3ActionIntent.CREATE),
                request = newRequest, password = "new-secret".toCharArray(),
            ))
            val live = OperationManager.currentPcv3Presentation.first { it is Pcv3Presentation.Live }
            assertEquals("replacement-host", live?.operationId)
            assertArrayEquals("Late old cleanup must never delete new owned bytes", newBytes, source.readBytes())
        } finally {
            release.complete(Unit)
            OperationManager.cancelPcv3()
            OperationManager.refreshPcv3()
            oldModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
            replacement?.viewModelScope?.coroutineContext?.get(Job)?.cancelAndJoin()
            OperationManager.currentPcv3Presentation.value?.let {
                OperationManager.dismissPcv3(it.operationId, it.generation)
            }
            unmockkObject(bridge, StartupCleanup, FileCopyService, OperationForegroundService.Companion)
        }
    }

    @Test
    fun `cancelled archive host retains paths when native completion cannot be observed`() = runTest {
        every { mockContext.applicationContext } returns mockContext
        val route = FakePcv3Operations(Result.success(livePcv3("archive-uncertain", 502, "preparing-input")))
        val cleaner = RecordingPcv3Cleaner()
        val model = OperationViewModel(route, cleaner, Pcv3ForegroundHost { })
        model.startPcv3(mockContext, Pcv3OperationTransfer(
            intent = Pcv3OperationIntent(Pcv3FormatIntent.NORMAL, action = Pcv3ActionIntent.CREATE),
            request = Pcv3WriteRequest("write-normal", "password", "none", "/private/a", "/private/output", emptyList(), "", "standard", false, inputFiles = listOf("/private/a", "/private/b")),
            password = "secret".toCharArray(),
        ))
        runCurrent()
        model.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
        assertEquals(1, route.cancelCalls)
        assertTrue("unobserved native worker may still be reading", cleaner.deletedPaths.isEmpty())
    }

    private fun pcv3Transfer(
        password: CharArray,
        keyfiles: List<String> = emptyList(),
    ): Pcv3OperationTransfer {
        val hasKeyfiles = keyfiles.isNotEmpty()
        return Pcv3OperationTransfer(
            intent = Pcv3OperationIntent(
                format = Pcv3FormatIntent.NORMAL,
                action = Pcv3ActionIntent.DECRYPT,
                factorPolicy = if (hasKeyfiles) {
                    Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES
                } else {
                    Pcv3FactorPolicyIntent.PASSWORD_ONLY
                },
                keyfileOrder = if (hasKeyfiles) Pcv3KeyfileOrderIntent.SELECTED else null,
            ),
            request = Pcv3Request(
                mode = "read-normal",
                factorPolicy = if (hasKeyfiles) "password-and-keyfiles" else "password",
                keyfileOrder = if (hasKeyfiles) "ordered" else "none",
                source = "/private/input",
                target = "/private/output",
                keyfiles = keyfiles,
            ),
            password = password,
        )
    }

    private fun livePcv3(
        operationId: String,
        generation: Long,
        statusCode: String = "checking-request",
    ) = Pcv3Presentation.Live(
        snapshot = pcv3Snapshot(statusCode = statusCode),
        operationId = operationId,
        generation = generation,
        operationHandle = FakePcv3Operation(operationId),
        consentHandle = null,
        archiveHandle = null,
        consent = null,
    )

    private fun outputPcv3(
        operationId: String,
        generation: Long,
        outcome: String = "success",
        completionClass: String = "clean",
        artifactMetadata: Pcv3ArtifactMetadataView? = null,
        forceProvenance: String? = null,
        warnings: List<String>? = null,
        diagnostic: String = "none",
    ) = Pcv3Presentation.Live(
        snapshot = outputSnapshot(
            outcome,
            completionClass,
            forceProvenance,
            warnings,
            diagnostic,
        ),
        operationId = operationId,
        generation = generation,
        operationHandle = FakePcv3Operation(operationId),
        consentHandle = null,
        archiveHandle = null,
        consent = null,
        outputHandle = mockk(relaxed = true),
        outputPending = true,
        artifactMetadata = artifactMetadata,
    )

    private fun archivePcv3(
        operationId: String,
        generation: Long,
    ) = Pcv3Presentation.Live(
        snapshot = pcv3Snapshot("none").copy(
            semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
            completionClass = "archive-pending",
            archivePending = true,
        ),
        operationId = operationId,
        generation = generation,
        operationHandle = FakePcv3Operation(operationId),
        consentHandle = null,
        archiveHandle = mockk(relaxed = true),
        consent = null,
    )

    private fun finalPcv3(
        operationId: String,
        generation: Long,
        snapshot: Pcv3SnapshotView = cancelledPcv3Snapshot(),
        artifactMetadata: Pcv3ArtifactMetadataView? = null,
    ) = Pcv3Presentation.Final(
        snapshot = snapshot,
        operationId = operationId,
        generation = generation,
        artifactMetadata = artifactMetadata,
    )

    private fun restoredPcv3(operationId: String, generation: Long) = Pcv3Presentation.Restored(
        snapshot = durabilityUncertainPcv3Snapshot(),
        operationId = operationId,
        generation = generation,
        receiptId = "r_00112233445566778899aabbccddeeff",
    )

    private fun pcv3Snapshot(statusCode: String) = Pcv3SnapshotView(
        statusCode = statusCode,
        statusArgs = emptyList(),
        semantic = Pcv3Semantic("unknown-outcome", "none", "PCV3_UNKNOWN"),
        publication = Pcv3Publication(false, "none", "none", "none"),
        forceProvenance = "none",
        d1BootstrapProvenance = "none",
        detailStage = "none",
        diagnostic = "none",
        completionClass = "unknown",
        resultArgs = emptyList(),
        warnings = emptyList(),
        archivePending = false,
        restoredReceipt = "",
    )

    private fun cancelledPcv3Snapshot() = Pcv3SnapshotView(
        statusCode = "none",
        statusArgs = emptyList(),
        semantic = Pcv3Semantic("operation-failed", "cancellation", "PCV3_OPERATION_FAILED"),
        publication = Pcv3Publication(false, "none", "none", "none"),
        forceProvenance = "none",
        d1BootstrapProvenance = "none",
        detailStage = "none",
        diagnostic = "cancellation",
        completionClass = "refused",
        resultArgs = emptyList(),
        warnings = emptyList(),
        archivePending = false,
        restoredReceipt = "",
    )

    private fun durabilityUncertainPcv3Snapshot(): Pcv3SnapshotView {
        val receipt = """{"version":1,"receiptID":"r_00112233445566778899aabbccddeeff","operationID":"op_1700000000000000000_7","outcome":7,"stage":0,"code":7,"forceProvenance":1,"d1BootstrapProvenance":3,"detailStage":13,"publicationAttempted":true,"publicationState":3,"publicationStage":24,"publicationCode":9,"args":[7,11,13,17],"warnings":[6,4],"diagnostic":0}"""
        return Pcv3SnapshotView(
            statusCode = "none",
            statusArgs = emptyList(),
            semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
            publication = Pcv3Publication(
                true,
                "published-durability-uncertain",
                "directory-sync",
                "PCV3_PUBLICATION_DURABILITY_UNCERTAIN",
            ),
            forceProvenance = "verified",
            d1BootstrapProvenance = "matching",
            detailStage = "metadata",
            diagnostic = "none",
            completionClass = "durability-uncertain",
            resultArgs = listOf("7", "11", "13", "17"),
            warnings = listOf("cleanup-incomplete", "durability-uncertain"),
            archivePending = false,
            restoredReceipt = receipt,
        )
    }

    private fun outputSnapshot(
        outcome: String,
        completionClass: String,
        forceProvenance: String? = null,
        warnings: List<String>? = null,
        diagnostic: String = "none",
    ) = Pcv3SnapshotView(
        statusCode = "none",
        statusArgs = emptyList(),
        semantic = Pcv3Semantic(
            outcome = outcome,
            stage = when (outcome) {
                "authenticated-degraded" -> "metadata"
                "force-partial", "force-unverified" -> "record-auth"
                else -> "none"
            },
            code = when (outcome) {
                "success" -> "PCV3_SUCCESS"
                "authenticated-degraded" -> "PCV3_AUTHENTICATED_DEGRADED"
                "force-partial" -> "PCV3_FORCE_PARTIAL"
                "force-unverified" -> "PCV3_FORCE_UNVERIFIED"
                else -> "PCV3_UNKNOWN"
            },
        ),
        publication = Pcv3Publication(
            attempted = true,
            state = "published-durable",
            stage = "none",
            code = "PCV3_PUBLICATION_PUBLISHED_DURABLE",
        ),
        forceProvenance = forceProvenance ?: when (outcome) {
            "force-partial" -> "partial"
            "force-unverified" -> "unverified"
            else -> "none"
        },
        d1BootstrapProvenance = "none",
        detailStage = "none",
        diagnostic = diagnostic,
        completionClass = completionClass,
        resultArgs = emptyList(),
        warnings = warnings ?: when (outcome) {
            "authenticated-degraded", "force-partial", "force-unverified" -> listOf(outcome)
            else -> emptyList()
        },
        archivePending = false,
        restoredReceipt = "",
    )

    private fun artifactMetadata(kind: String) = Pcv3ArtifactMetadataView(
        kind = kind,
        role = "none",
        plaintextLength = "17",
        finalStatus = if (kind == "partial") "missing" else "unverified",
        rangeCount = "2",
        verifiedCount = "1",
        unverifiedCount = if (kind == "partial") "0" else "1",
        missingCount = if (kind == "partial") "1" else "0",
    )

    private class FakePcv3Operation(override val id: String) : Pcv3OperationCapability {
        override fun snapshot() = error("not called by the ViewModel fake")
        override fun consent(): Pcv3ConsentCapability? = null
        override fun archive(): Pcv3ArchiveCapability? = null
        override fun cancel() = error("not called by the ViewModel fake")
        override fun release(): String = ""
    }

    private data class RefreshStep(
        val returned: Result<Pcv3Presentation>,
        val authoritative: Pcv3Presentation? = returned.getOrNull(),
        val updateAuthority: Boolean = true,
        val busy: Boolean = authoritative is Pcv3Presentation.Live,
    )

    private class FakePcv3Operations(
        private val startResult: Result<Pcv3Presentation>,
        private val refreshResults: ArrayDeque<RefreshStep> = ArrayDeque(),
        initialPresentation: Pcv3Presentation? = null,
        private val busyAfterStart: Boolean? = null,
        private val startEntered: CompletableDeferred<Unit>? = null,
        private val startRelease: CompletableDeferred<Unit>? = null,
        private val events: MutableList<String>? = null,
    ) : Pcv3Operations {
        private val presentationFlow = MutableStateFlow(initialPresentation)
        private val busyFlow = MutableStateFlow(initialPresentation is Pcv3Presentation.Live)
        override val presentation: StateFlow<Pcv3Presentation?> = presentationFlow
        override val busy: StateFlow<Boolean> = busyFlow
        var refreshCalls = 0
        var cancelCalls = 0
        var selectRoleCalls = 0
        var confirmCalls = 0
        var refuseCalls = 0
        var closeArchiveCalls = 0
        var exportArchiveCalls = 0
        var dismissCalls = 0
        var saveOutputCalls = 0
        var discardOutputCalls = 0
        var artifactPageCalls = 0
        val receiptFiles = mutableListOf<File>()
        val savedDestinations = mutableListOf<ParcelFileDescriptor>()
        var resourceReader: Pcv3ResourceObservationReader? = null
        var artifactLoader: suspend (String, Long, String, Int) -> Result<Pcv3ArtifactPageView> =
            { _, _, _, _ -> Result.failure(Pcv3BridgeFailure("PCV3_ARTIFACT_INSPECTION_UNAVAILABLE")) }
        var saveOutputAction: suspend (ParcelFileDescriptor) -> Result<Unit> = { Result.success(Unit) }
        var exportArchiveAction: suspend (String, Long, Uri) -> Result<Unit> = { _, _, _ ->
            Result.success(Unit)
        }
        var saveCancellation: CancellationException? = null

        fun publish(presentation: Pcv3Presentation?) {
            presentationFlow.value = presentation
            busyFlow.value = presentation is Pcv3Presentation.Live
        }

        override suspend fun start(
            request: Pcv3StartRequest,
            password: CharArray,
            receiptFile: File,
            inputCustody: Pcv3InputCustody,
        ): Result<Pcv3Presentation> {
            events?.add("native-start")
            receiptFiles += receiptFile
            busyFlow.value = true
            startEntered?.complete(Unit)
            return try {
                startRelease?.await()
                startResult.also { result ->
                    presentationFlow.value = result.getOrNull()
                    busyFlow.value = busyAfterStart ?: (result.getOrNull() is Pcv3Presentation.Live)
                }
            } catch (error: CancellationException) {
                busyFlow.value = false
                throw error
            }
        }

        override suspend fun installResourceObservationReader(reader: Pcv3ResourceObservationReader): Boolean {
            events?.add("resource-reader")
            resourceReader = reader
            return busyFlow.value
        }

        override suspend fun refresh(): Result<Pcv3Presentation> {
            refreshCalls += 1
            val step = if (refreshResults.isEmpty()) null else refreshResults.removeFirst()
            if (step == null) {
                return Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
            }
            if (step.updateAuthority) presentationFlow.value = step.authoritative
            busyFlow.value = step.busy
            return step.returned
        }

        override suspend fun cancel(): Result<Unit> {
            cancelCalls += 1
            return Result.success(Unit)
        }

        override suspend fun selectConsentRole(role: String): Result<Unit> {
            selectRoleCalls += 1
            return Result.success(Unit)
        }

        override suspend fun confirmConsent(): Result<Unit> {
            confirmCalls += 1
            return Result.success(Unit)
        }

        override suspend fun refuseConsent(): Result<Unit> {
            refuseCalls += 1
            return Result.success(Unit)
        }

        override suspend fun closeArchive(): Result<Unit> {
            closeArchiveCalls += 1
            return Result.success(Unit)
        }

        override suspend fun exportArchive(
            context: Context,
            operationId: String,
            generation: Long,
            root: Uri,
        ): Result<Unit> {
            exportArchiveCalls += 1
            return exportArchiveAction(operationId, generation, root)
        }

        override suspend fun saveOutput(
            operationId: String,
            generation: Long,
            destination: ParcelFileDescriptor,
        ): Result<Unit> {
            saveOutputCalls += 1
            savedDestinations += destination
            events?.add("save-output")
            return try {
                saveOutputAction(destination)
            } catch (error: CancellationException) {
                saveCancellation = error
                throw error
            }
        }

        override suspend fun discardOutput(operationId: String, generation: Long): Result<Unit> {
            discardOutputCalls += 1
            events?.add("discard-output")
            return Result.success(Unit)
        }

        override suspend fun loadArtifactPage(
            operationId: String,
            generation: Long,
            offsetDecimal: String,
            limit: Int,
        ): Result<Pcv3ArtifactPageView> {
            artifactPageCalls += 1
            return artifactLoader(operationId, generation, offsetDecimal, limit)
        }

        override suspend fun dismiss(operationId: String, generation: Long): Boolean {
            dismissCalls += 1
            val current = presentationFlow.value
            val accepted = current != null && current.operationId == operationId && current.generation == generation &&
                (current is Pcv3Presentation.Final || current is Pcv3Presentation.Restored)
            if (accepted) presentationFlow.value = null
            return accepted
        }
    }

    private class RecordingPcv3Cleaner(
        private val result: Boolean = true,
        private val events: MutableList<String>? = null,
    ) : Pcv3TransferredResourceCleaner {
        val deletedPaths = mutableListOf<List<String>>()

        override suspend fun delete(context: Context, paths: List<String>): Boolean {
            events?.add("transferred-cleanup")
            deletedPaths += paths
            return result
        }
    }
}
