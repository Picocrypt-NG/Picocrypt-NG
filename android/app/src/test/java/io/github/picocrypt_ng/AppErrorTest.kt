package io.github.picocrypt_ng

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for AppError class.
 */
class AppErrorTest {
    
    @Test
    fun `isDataCorruption returns true for DataCorruption error`() {
        val error = AppError.OperationError.DataCorruption(
            userMessage = "Data corrupted",
            technicalMessage = "Corruption detected"
        )
        assertTrue(error.isDataCorruption())
        assertTrue(error.allowsForceDecrypt())
    }
    
    @Test
    fun `isDataCorruption returns false for other error types`() {
        val passwordError = AppError.OperationError.PasswordAuth("Wrong password")
        val fileError = AppError.OperationError.FileNotFound()
        val genericError = AppError.OperationError.GenericOperation("Generic error")
        
        assertFalse(passwordError.isDataCorruption())
        assertFalse(fileError.isDataCorruption())
        assertFalse(genericError.isDataCorruption())
    }
    
    @Test
    fun `isPasswordError returns true for PasswordAuth error`() {
        val error = AppError.OperationError.PasswordAuth(
            userMessage = "Incorrect password",
            technicalMessage = "Authentication failed"
        )
        assertTrue(error.isPasswordError())
        assertTrue(error.allowsPasswordRetry())
    }
    
    @Test
    fun `isPasswordError returns false for other error types`() {
        val corruptionError = AppError.OperationError.DataCorruption("Data corrupted")
        val fileError = AppError.OperationError.FileNotFound()
        val genericError = AppError.OperationError.GenericOperation("Generic error")
        
        assertFalse(corruptionError.isPasswordError())
        assertFalse(fileError.isPasswordError())
        assertFalse(genericError.isPasswordError())
    }
    
    @Test
    fun `allowsForceDecrypt returns true only for DataCorruption`() {
        val corruptionError = AppError.OperationError.DataCorruption("Data corrupted")
        val passwordError = AppError.OperationError.PasswordAuth("Wrong password")
        val fileError = AppError.OperationError.FileNotFound()
        
        assertTrue(corruptionError.allowsForceDecrypt())
        assertFalse(passwordError.allowsForceDecrypt())
        assertFalse(fileError.allowsForceDecrypt())
    }
    
    @Test
    fun `allowsPasswordRetry returns true only for PasswordAuth`() {
        val corruptionError = AppError.OperationError.DataCorruption("Data corrupted")
        val passwordError = AppError.OperationError.PasswordAuth("Wrong password")
        val fileError = AppError.OperationError.FileNotFound()
        
        assertFalse(corruptionError.allowsPasswordRetry())
        assertTrue(passwordError.allowsPasswordRetry())
        assertFalse(fileError.allowsPasswordRetry())
    }
    
    @Test
    fun `fromGoError converts password error correctly`() {
        val errorMessages = listOf(
            "Incorrect password",
            "Password authentication failed",
            "Incorrect keyfile",
            "Authentication failed"
        )
        
        errorMessages.forEach { message ->
            val error = AppError.fromGoError(message, OperationType.DECRYPT)
            assertTrue("Error should be PasswordAuth for: $message", error is AppError.OperationError.PasswordAuth)
            assertTrue("Error should allow password retry", error.allowsPasswordRetry())
        }
    }
    
    @Test
    fun `fromGoError converts data corruption error correctly for decrypt`() {
        val errorMessages = listOf(
            "Data corrupted",
            "Data corruption detected"
        )
        
        errorMessages.forEach { message ->
            val error = AppError.fromGoError(message, OperationType.DECRYPT)
            assertTrue("Error should be DataCorruption for: $message", error is AppError.OperationError.DataCorruption)
            assertTrue("Error should allow force decrypt", error.allowsForceDecrypt())
        }
    }
    
    @Test
    fun `fromGoError does not convert data corruption for encrypt`() {
        val error = AppError.fromGoError("Data corrupted", OperationType.ENCRYPT)
        // Should be generic, not DataCorruption (only applies to decrypt)
        assertFalse("Error should not be DataCorruption for encrypt", error is AppError.OperationError.DataCorruption)
    }
    
    @Test
    fun `fromGoError prioritizes auth error over corruption when both present`() {
        // If error contains both corruption and auth keywords, auth should take priority
        val error = AppError.fromGoError("Data corrupted but password incorrect", OperationType.DECRYPT)
        // Should be PasswordAuth, not DataCorruption
        assertTrue("Error should be PasswordAuth when both keywords present", error is AppError.OperationError.PasswordAuth)
    }
    
    @Test
    fun `fromGoError converts file not found error correctly`() {
        val errorMessages = listOf(
            "File not found",
            "No such file or directory",
            "Cannot find file"
        )
        
        errorMessages.forEach { message ->
            val error = AppError.fromGoError(message, OperationType.DECRYPT)
            assertTrue("Error should be FileNotFound for: $message", error is AppError.OperationError.FileNotFound)
        }
    }
    
    @Test
    fun `fromGoError converts generic error for unknown messages`() {
        val errorMessages = listOf(
            "Unknown error occurred",
            "Something went wrong",
            "Unexpected error"
        )
        
        errorMessages.forEach { message ->
            val error = AppError.fromGoError(message, OperationType.ENCRYPT)
            assertTrue("Error should be GenericOperation for: $message", error is AppError.OperationError.GenericOperation)
        }
    }
    
    @Test
    fun `fromGoError preserves error messages`() {
        val userMessage = "Custom error message"
        val error = AppError.fromGoError(userMessage, OperationType.ENCRYPT)
        assertEquals(userMessage, error.userMessage)
        assertEquals(userMessage, error.technicalMessage)
    }
    
    @Test
    fun `fromException converts file not found exception correctly`() {
        val exception = java.io.FileNotFoundException("File not found: test.txt")
        val error = AppError.fromException(exception)
        
        assertTrue("Error should be FileNotFound", error is AppError.OperationError.FileNotFound)
        assertEquals("File not found: test.txt", error.technicalMessage)
    }
    
    @Test
    fun `fromException converts generic exception correctly`() {
        val exception = RuntimeException("Something went wrong")
        val error = AppError.fromException(exception)
        
        assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        assertEquals("Something went wrong", error.userMessage)
        assertEquals("Something went wrong", error.technicalMessage)
    }
    
    @Test
    fun `fromException handles exception with null message`() {
        val exception = RuntimeException()
        val error = AppError.fromException(exception)
        
        assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        assertEquals("Unknown error occurred", error.userMessage)
    }
    
    @Test
    fun `ValidationError objects have correct messages`() {
        assertEquals("Please select a file", AppError.ValidationError.NoFileSelected.userMessage)
        assertEquals("Please enter a password", AppError.ValidationError.InvalidPassword.userMessage)
        assertEquals("Passwords do not match", AppError.ValidationError.PasswordsMismatch.userMessage)
    }
    
    @Test
    fun `FileError classes have default messages`() {
        val copyError = AppError.FileError.CopyFailed()
        val deleteError = AppError.FileError.DeleteFailed()
        val saveError = AppError.FileError.SaveFailed()
        
        assertEquals("Failed to copy file", copyError.userMessage)
        assertEquals("Failed to delete file", deleteError.userMessage)
        assertEquals("Failed to save file", saveError.userMessage)
    }
    
    @Test
    fun `FileError classes accept custom messages`() {
        val customMessage = "Custom copy error"
        val error = AppError.FileError.CopyFailed(
            userMessage = customMessage,
            technicalMessage = "Technical details"
        )
        
        assertEquals(customMessage, error.userMessage)
        assertEquals("Technical details", error.technicalMessage)
    }
    
    @Test
    fun `OperationError classes accept custom messages`() {
        val customUserMsg = "User-friendly message"
        val customTechMsg = "Technical details"
        
        val corruptionError = AppError.OperationError.DataCorruption(customUserMsg, customTechMsg)
        val passwordError = AppError.OperationError.PasswordAuth(customUserMsg, customTechMsg)
        val fileError = AppError.OperationError.FileNotFound(customUserMsg, customTechMsg)
        val genericError = AppError.OperationError.GenericOperation(customUserMsg, customTechMsg)
        
        assertEquals(customUserMsg, corruptionError.userMessage)
        assertEquals(customTechMsg, corruptionError.technicalMessage)
        assertEquals(customUserMsg, passwordError.userMessage)
        assertEquals(customTechMsg, passwordError.technicalMessage)
        assertEquals(customUserMsg, fileError.userMessage)
        assertEquals(customTechMsg, fileError.technicalMessage)
        assertEquals(customUserMsg, genericError.userMessage)
        assertEquals(customTechMsg, genericError.technicalMessage)
    }
    
    @Test
    fun `fromGoError handles case insensitive matching`() {
        val error1 = AppError.fromGoError("PASSWORD INCORRECT", OperationType.DECRYPT)
        val error2 = AppError.fromGoError("password incorrect", OperationType.DECRYPT)
        val error3 = AppError.fromGoError("Password Incorrect", OperationType.DECRYPT)
        
        assertTrue("Should handle uppercase", error1 is AppError.OperationError.PasswordAuth)
        assertTrue("Should handle lowercase", error2 is AppError.OperationError.PasswordAuth)
        assertTrue("Should handle mixed case", error3 is AppError.OperationError.PasswordAuth)
    }
}


