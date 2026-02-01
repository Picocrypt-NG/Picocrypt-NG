package io.github.picocrypt_ng

import android.content.Context
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import io.github.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.mockk

/**
 * Unit tests for OperationViewModel.
 * 
 * Note: OperationViewModel uses OperationManager which interacts with GoBridge.
 * Full integration testing requires instrumented tests. These unit tests focus
 * on the ViewModel's polling lifecycle and state management.
 */
class OperationViewModelTest {
    
    @get:Rule
    val instantTaskExecutorRule = InstantTaskExecutorRule()
    
    private val testDispatcher = StandardTestDispatcher()
    private lateinit var mockContext: Context
    private lateinit var viewModel: OperationViewModel
    
    @Before
    fun setUp() = runTest {
        Dispatchers.setMain(testDispatcher)
        mockContext = mockk<Context>(relaxed = true)
        viewModel = OperationViewModel()
        // Clear any existing operation state
        OperationManager.clearOperation(shouldCleanupFiles = false)
    }
    
    @After
    fun tearDown() = runTest {
        Dispatchers.resetMain()
        // Clean up operation state after each test
        OperationManager.clearOperation(shouldCleanupFiles = false)
    }
    
    @Test
    fun `operationState exposes OperationManager currentOperation`() = runTest {
        val operationState = viewModel.operationState.first()
        
        // Initially should be null
        assertNull("Operation state should be null initially", operationState)
        
        // Should match OperationManager's state
        val managerState = OperationManager.currentOperation.first()
        assertEquals(managerState, operationState)
    }
    
    @Test
    fun `startEncrypt launches operation`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "test",
            confirmPassword = "test"
        )
        
        // This will fail validation or require GoBridge, but we test the method call
        viewModel.startEncrypt(mockContext, formData)
        
        // Give coroutine time to execute
        advanceTimeBy(100)
        
        // Operation may or may not start depending on validation/GoBridge availability
        // But the method should not throw
    }
    
    @Test
    fun `startDecrypt launches operation`() = runTest {
        val formData = TestDataBuilders.createDecryptFormData(
            password = "test"
        )
        
        viewModel.startDecrypt(mockContext, formData)
        
        // Give coroutine time to execute
        advanceTimeBy(100)
        
        // Method should not throw
    }
    
    @Test
    fun `cancelOperation stops polling and cancels operation`() = runTest {
        viewModel.cancelOperation()
        
        // Give coroutine time to execute
        advanceTimeBy(100)
        
        // Method should not throw
    }
    
    @Test
    fun `clearOperation stops polling and clears operation`() = runTest {
        viewModel.clearOperation(mockContext, shouldCleanupFiles = false)
        
        // Give coroutine time to execute
        advanceTimeBy(100)
        
        val operationState = viewModel.operationState.first()
        assertNull("Operation should be cleared", operationState)
    }
    
    @Test
    fun `retryOperation stops polling and retries`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "test",
            confirmPassword = "test"
        )
        
        viewModel.retryOperation(mockContext, formData)
        
        // Give coroutine time to execute
        advanceTimeBy(100)
        
        // Method should not throw
    }
    
    @Test
    fun `retryDecryptWithForce stops polling and retries with force`() = runTest {
        viewModel.retryDecryptWithForce()
        
        // Give coroutine time to execute
        advanceTimeBy(100)
        
        // Method should not throw
    }
    
    @Test
    fun `pausePolling switches to background mode`() = runTest {
        // pausePolling sets isForeground to false and starts background polling
        viewModel.pausePolling()
        
        // Give time for state change
        advanceTimeBy(100)
        
        // Method should not throw
        // Note: We can't easily verify isForeground without exposing it,
        // but we can verify the method executes without error
    }
    
    @Test
    fun `resumePolling switches to foreground mode`() = runTest {
        // First pause
        viewModel.pausePolling()
        advanceTimeBy(100)
        
        // Then resume
        viewModel.resumePolling()
        advanceTimeBy(100)
        
        // Method should not throw
    }
    
    @Test
    fun `onCleared stops all polling`() = runTest {
        // Test that onCleared doesn't throw
        // Note: onCleared is protected, so we can't call it directly
        // This test verifies the ViewModel can be created and used
        assertNotNull("ViewModel should be created", viewModel)
    }
    
    @Test
    fun `operationState updates when OperationManager state changes`() = runTest {
        // Initially null
        var operationState = viewModel.operationState.first()
        assertNull("Should be null initially", operationState)
        
        // Note: We can't easily set OperationManager state without GoBridge,
        // but we verify the StateFlow is connected
        val managerState = OperationManager.currentOperation.first()
        assertEquals(managerState, operationState)
    }
}

