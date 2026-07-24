package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import io.github.picocrypt_ng.picocrypt_ng.testutils.MainDispatcherRule
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify

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
    private lateinit var viewModel: OperationViewModel
    
    @Before
    fun setUp() {
        mockContext = mockk<Context>(relaxed = true)
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
    fun `startEncrypt surfaces a start failure as a terminal error state`() = runTest(mainDispatcherRule.testDispatcher) {
        // Mock startEncrypt to return failure on the test dispatcher so the
        // onFailure → surfaceStartFailure path runs deterministically.
        // surfaceStartFailure must call the real implementation to update _currentOperation.
        mockkObject(OperationManager)
        try {
            val error = AppError.ValidationError.NoFileSelected
            coEvery { OperationManager.startEncrypt(any(), any()) } returns Result.failure(error)
            every { OperationManager.surfaceStartFailure(any(), any()) } answers { callOriginal() }

            viewModel.startEncrypt(mockContext, TestDataBuilders.createEncryptFormData())
            advanceUntilIdle()

            val state = viewModel.operationState.value
            assertNotNull("A start failure must surface as an error state (not silent null)", state)
            assertTrue("Error state must be terminal (done=true)", state!!.done)
            assertNotNull("Error state must carry the error", state.error)
            assertEquals(OperationType.ENCRYPT, state.type)
        } finally {
            unmockkObject(OperationManager)
        }
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
    fun `pausePolling switches to background mode`() = runTest(mainDispatcherRule.testDispatcher) {
        // pausePolling sets isForeground to false and starts background polling
        viewModel.pausePolling()
        
        advanceUntilIdle()
        
        // Method should not throw
        // Note: We can't easily verify isForeground without exposing it,
        // but we can verify the method executes without error
    }
    
    @Test
    fun `resumePolling switches to foreground mode`() = runTest(mainDispatcherRule.testDispatcher) {
        // First pause
        viewModel.pausePolling()
        advanceUntilIdle()
        
        // Then resume
        viewModel.resumePolling()
        advanceUntilIdle()
        
        // Method should not throw
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
}
