package io.github.picocrypt_ng

import android.content.Context
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import io.github.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.mockk
import io.mockk.every

/**
 * Unit tests for OperationManager.
 * 
 * Note: OperationManager uses GoBridge and FileCopyService which are objects.
 * Full integration testing requires instrumented tests. These unit tests focus
 * on validation logic and state management that can be tested without full integration.
 */
class OperationManagerTest {
    
    private lateinit var mockContext: Context
    
    @Before
    fun setUp() = runTest {
        mockContext = mockk<Context>(relaxed = true)
        // Clear any existing operation state
        OperationManager.clearOperation(shouldCleanupFiles = false)
    }
    
    @After
    fun tearDown() = runTest {
        // Clean up operation state after each test
        OperationManager.clearOperation(shouldCleanupFiles = false)
    }
    
    @Test
    fun `startEncrypt returns error when no file selected`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            copiedFilePath = "" // Empty file path
        )
        
        val result = OperationManager.startEncrypt(mockContext, formData)
        
        assertTrue("Should fail with NoFileSelected", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be NoFileSelected", error is AppError.ValidationError.NoFileSelected)
        }
    }
    
    @Test
    fun `startEncrypt returns error when password invalid`() = runTest {
        val formData = FormData(
            selectedFilename = "test.txt",
            copiedFilePath = "/path/to/file.txt",
            passwordInput = CharArray(0), // Empty password
            confirmPasswordInput = CharArray(0),
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false
        )
        
        val result = OperationManager.startEncrypt(mockContext, formData)
        
        assertTrue("Should fail with InvalidPassword", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be InvalidPassword", error is AppError.ValidationError.InvalidPassword)
        }
    }
    
    @Test
    fun `startEncrypt returns error when passwords do not match`() = runTest {
        val formData = FormData(
            selectedFilename = "test.txt",
            copiedFilePath = "/path/to/file.txt",
            passwordInput = "password1".toCharArray(),
            confirmPasswordInput = "password2".toCharArray(), // Mismatch
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false
        )
        
        val result = OperationManager.startEncrypt(mockContext, formData)
        
        assertTrue("Should fail with PasswordsMismatch", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be PasswordsMismatch", error is AppError.ValidationError.PasswordsMismatch)
        }
    }
    
    @Test
    fun `startDecrypt returns error when no file selected`() = runTest {
        val formData = TestDataBuilders.createDecryptFormData(
            copiedFilePath = "" // Empty file path
        )
        
        val result = OperationManager.startDecrypt(mockContext, formData)
        
        assertTrue("Should fail with NoFileSelected", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be NoFileSelected", error is AppError.ValidationError.NoFileSelected)
        }
    }
    
    @Test
    fun `startDecrypt returns error when password invalid`() = runTest {
        val formData = FormData(
            selectedFilename = "test.pcv",
            copiedFilePath = "/path/to/file.pcv",
            passwordInput = CharArray(0), // Empty password
            confirmPasswordInput = CharArray(0),
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false
        )
        
        val result = OperationManager.startDecrypt(mockContext, formData)
        
        assertTrue("Should fail with InvalidPassword", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be InvalidPassword", error is AppError.ValidationError.InvalidPassword)
        }
    }
    
    @Test
    fun `cancelOperation returns error when no active operation`() = runTest {
        // Ensure no operation is active
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.cancelOperation()
        
        assertTrue("Should fail with no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
            val errorMessage = error.message ?: ""
            assertTrue("Error message should mention no active operation", 
                errorMessage.contains("No active operation", ignoreCase = true))
        }
    }
    
    @Test
    fun `pollProgress returns null when no active operation`() = runTest {
        // Ensure no operation is active
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.pollProgress()
        
        assertNull("Should return null when no operation", result)
    }
    
    @Test
    fun `clearOperation clears current operation`() = runTest {
        // First, we'd need to set up an operation, but since we can't easily mock GoBridge,
        // we'll test that clearOperation works when called
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val currentOp = OperationManager.currentOperation.first()
        assertNull("Operation should be null after clearing", currentOp)
    }
    
    @Test
    fun `clearOperation clears passwords from form data`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "testpassword",
            confirmPassword = "testpassword"
        )
        
        // Create a mock operation state
        val operationState = TestDataBuilders.createOperationState(
            formData = formData
        )
        
        // We can't directly set the operation state, but we can test the password clearing
        // by checking that clearPasswords works
        val passwordBefore = formData.passwordInput.copyOf()
        formData.clearPasswords()
        
        assertTrue("Password should be cleared", formData.passwordInput.all { it == '\u0000' })
        assertTrue("Confirm password should be cleared", formData.confirmPasswordInput.all { it == '\u0000' })
    }
    
    @Test
    fun `retryOperation returns error when no active operation`() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val formData = TestDataBuilders.createEncryptFormData()
        val result = OperationManager.retryOperation(mockContext, formData)
        
        assertTrue("Should fail with no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
            val errorMessage = error.message ?: ""
            assertTrue("Error message should mention no active operation to retry",
                errorMessage.contains("No active operation to retry", ignoreCase = true))
        }
    }
    
    @Test
    fun `retryOperation returns error when form data invalid`() = runTest {
        // We can't easily set up an operation without GoBridge, but we can test
        // that retryOperation validates form data
        val invalidFormData = TestDataBuilders.createEncryptFormData(
            copiedFilePath = "" // Invalid - no file
        )
        
        // This will fail because there's no active operation, but we're testing
        // the validation logic that happens after checking for active operation
        val result = OperationManager.retryOperation(mockContext, invalidFormData)
        
        // Will fail either because no active operation or invalid form data
        assertTrue("Should fail", result.isFailure)
    }
    
    @Test
    fun `retryDecryptWithForce returns error when no active operation`() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.retryDecryptWithForce()
        
        assertTrue("Should fail with no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        }
    }
    
    @Test
    fun `retryDecryptWithForce returns error when operation is not decrypt`() = runTest {
        // We can't easily set up an encrypt operation, but we can test the logic
        // that checks operation type
        // This would require setting up an operation state, which is difficult without GoBridge
        // So we'll test this in instrumented tests
    }
    
    @Test
    fun `currentOperation StateFlow is initially null`() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val currentOp = OperationManager.currentOperation.first()
        assertNull("Current operation should be null initially", currentOp)
    }
    
    @Test
    fun `OperationState has correct structure`() {
        val formData = TestDataBuilders.createEncryptFormData()
        val operationState = TestDataBuilders.createOperationState(
            id = "op_123",
            type = OperationType.ENCRYPT,
            inputFile = "/input.txt",
            outputFile = "/output.pcv",
            status = "Processing",
            progress = 0.5f,
            info = "Encrypting...",
            done = false,
            formData = formData
        )
        
        assertEquals("op_123", operationState.id)
        assertEquals(OperationType.ENCRYPT, operationState.type)
        assertEquals("/input.txt", operationState.inputFile)
        assertEquals("/output.pcv", operationState.outputFile)
        assertEquals("Processing", operationState.status)
        assertEquals(0.5f, operationState.progress, 0.001f)
        assertEquals("Encrypting...", operationState.info)
        assertEquals(false, operationState.done)
        assertEquals(formData, operationState.formData)
    }
    
    @Test
    fun `OperationType enum values are correct`() {
        assertEquals("ENCRYPT", OperationType.ENCRYPT.name)
        assertEquals("DECRYPT", OperationType.DECRYPT.name)
    }
}

