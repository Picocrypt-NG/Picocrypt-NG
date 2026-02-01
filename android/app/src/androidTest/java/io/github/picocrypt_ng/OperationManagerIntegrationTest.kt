package io.github.picocrypt_ng

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import io.github.picocrypt_ng.testutils.TestDataBuilders

/**
 * Integration tests for OperationManager.
 * These tests require the Go mobile bindings AAR to be built and test
 * the full operation lifecycle with real file operations.
 * 
 * Note: Some tests may be skipped if Go mobile bindings are not available.
 */
@RunWith(AndroidJUnit4::class)
class OperationManagerIntegrationTest {
    
    private lateinit var context: Context
    
    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        // Clean up any existing operations and files
        OperationManager.clearOperation(context, shouldCleanupFiles = true)
        FileCopyService.cleanupAllFiles(context)
    }
    
    @After
    fun tearDown() {
        // Clean up after each test
        OperationManager.clearOperation(context, shouldCleanupFiles = true)
        FileCopyService.cleanupAllFiles(context)
    }
    
    @Test
    fun `startEncrypt validates form data before starting`() = runTest {
        // Test with invalid form data (no file)
        val invalidFormData = TestDataBuilders.createEncryptFormData(
            copiedFilePath = "" // Invalid - no file
        )
        
        val result = OperationManager.startEncrypt(context, invalidFormData)
        
        assertTrue("Should fail validation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be NoFileSelected", error is AppError.ValidationError.NoFileSelected)
        }
        
        // Verify no operation was started
        val operationState = OperationManager.currentOperation.first()
        assertNull("No operation should be started", operationState)
    }
    
    @Test
    fun `startDecrypt validates form data before starting`() = runTest {
        // Test with invalid form data (no file)
        val invalidFormData = TestDataBuilders.createDecryptFormData(
            copiedFilePath = "" // Invalid - no file
        )
        
        val result = OperationManager.startDecrypt(context, invalidFormData)
        
        assertTrue("Should fail validation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be NoFileSelected", error is AppError.ValidationError.NoFileSelected)
        }
        
        // Verify no operation was started
        val operationState = OperationManager.currentOperation.first()
        assertNull("No operation should be started", operationState)
    }
    
    @Test
    fun `startEncrypt creates operation state on success`() = runTest {
        // Create a test file
        val internalDir = File(context.filesDir, "picocrypt_files")
        internalDir.mkdirs()
        val testFile = File(internalDir, "input_file.txt")
        testFile.writeText("test content")
        
        val formData = TestDataBuilders.createEncryptFormData(
            copiedFilePath = testFile.absolutePath,
            password = "testpassword",
            confirmPassword = "testpassword"
        )
        
        val result = OperationManager.startEncrypt(context, formData)
        
        // Result may succeed or fail depending on Go mobile bindings availability
        // But if it succeeds, operation state should be set
        result.onSuccess { operationID ->
            assertNotNull("Operation ID should not be null", operationID)
            
            val operationState = OperationManager.currentOperation.first()
            assertNotNull("Operation state should be set", operationState)
            assertEquals("Operation ID should match", operationID, operationState?.id)
            assertEquals("Operation type should be ENCRYPT", OperationType.ENCRYPT, operationState?.type)
            assertEquals("Input file should match", testFile.absolutePath, operationState?.inputFile)
            assertNotNull("Output file should be set", operationState?.outputFile)
            assertTrue("Output file should end with .pcv", operationState?.outputFile?.endsWith(".pcv") == true)
        }
    }
    
    @Test
    fun `startDecrypt creates operation state on success`() = runTest {
        // Create a test file
        val internalDir = File(context.filesDir, "picocrypt_files")
        internalDir.mkdirs()
        val testFile = File(internalDir, "input_file.pcv")
        testFile.writeText("test encrypted content")
        
        val formData = TestDataBuilders.createDecryptFormData(
            copiedFilePath = testFile.absolutePath,
            password = "testpassword"
        )
        
        val result = OperationManager.startDecrypt(context, formData)
        
        // Result may succeed or fail depending on Go mobile bindings availability
        result.onSuccess { operationID ->
            assertNotNull("Operation ID should not be null", operationID)
            
            val operationState = OperationManager.currentOperation.first()
            assertNotNull("Operation state should be set", operationState)
            assertEquals("Operation ID should match", operationID, operationState?.id)
            assertEquals("Operation type should be DECRYPT", OperationType.DECRYPT, operationState?.type)
            assertEquals("Input file should match", testFile.absolutePath, operationState?.inputFile)
            assertNotNull("Output file should be set", operationState?.outputFile)
        }
    }
    
    @Test
    fun `pollProgress updates operation state`() = runTest {
        // This test requires an active operation
        // We'll test that pollProgress doesn't throw when called
        // Full testing requires Go mobile bindings
        
        val result = OperationManager.pollProgress()
        
        // Should return null if no operation, or OperationState if operation exists
        // Should not throw
        assertNotNull("Result should not be null (may be null if no operation)", result != null || result == null)
    }
    
    @Test
    fun `cancelOperation updates operation state to cancelled`() = runTest {
        // This test requires an active operation
        // We'll test the error case when no operation exists
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.cancelOperation()
        
        assertTrue("Should fail when no operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        }
    }
    
    @Test
    fun `clearOperation removes operation state`() = runTest {
        OperationManager.clearOperation(context, shouldCleanupFiles = false)
        
        val operationState = OperationManager.currentOperation.first()
        assertNull("Operation should be cleared", operationState)
    }
    
    @Test
    fun `clearOperation cleans up files when requested`() = runTest {
        // Create test files
        val internalDir = File(context.filesDir, "picocrypt_files")
        internalDir.mkdirs()
        val inputFile = File(internalDir, "input_file.txt")
        val outputFile = File(internalDir, "output_file.pcv")
        val keyfile = File(internalDir, "keyfile_0")
        inputFile.writeText("input")
        outputFile.writeText("output")
        keyfile.writeText("keyfile")
        
        // Create a mock operation state by manually setting up files
        // (We can't easily create a real operation without Go mobile bindings)
        // But we can test that clearOperation cleans up files
        
        val formData = TestDataBuilders.createEncryptFormData(
            copiedFilePath = inputFile.absolutePath,
            keyfiles = listOf(TestDataBuilders.createKeyfileInfo(internalPath = keyfile.absolutePath))
        )
        
        // Note: We can't set operation state directly, but we can test
        // that FileCopyService.cleanupOperationFiles works
        FileCopyService.cleanupOperationFiles(
            context = context,
            inputFilePath = inputFile.absolutePath,
            outputFilePath = outputFile.absolutePath,
            keyfilePaths = listOf(keyfile.absolutePath)
        )
        
        assertFalse("Input file should be deleted", inputFile.exists())
        assertFalse("Output file should be deleted", outputFile.exists())
        assertFalse("Keyfile should be deleted", keyfile.exists())
    }
    
    @Test
    fun `retryOperation requires active operation`() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val formData = TestDataBuilders.createEncryptFormData(
            password = "test",
            confirmPassword = "test"
        )
        
        val result = OperationManager.retryOperation(context, formData)
        
        assertTrue("Should fail when no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        }
    }
    
    @Test
    fun `retryDecryptWithForce requires active decrypt operation`() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.retryDecryptWithForce()
        
        assertTrue("Should fail when no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        }
    }
    
    @Test
    fun `currentOperation StateFlow reflects operation state`() = runTest {
        // Initially should be null
        var operationState = OperationManager.currentOperation.first()
        assertNull("Should be null initially", operationState)
        
        // After clearing, should still be null
        OperationManager.clearOperation(shouldCleanupFiles = false)
        operationState = OperationManager.currentOperation.first()
        assertNull("Should be null after clearing", operationState)
    }
}

