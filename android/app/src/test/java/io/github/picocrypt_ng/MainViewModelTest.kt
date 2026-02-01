package io.github.picocrypt_ng

import android.app.Application
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import androidx.lifecycle.SavedStateHandle
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import io.github.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.mockk

/**
 * Unit tests for MainViewModel.
 */
class MainViewModelTest {
    
    @get:Rule
    val instantTaskExecutorRule = InstantTaskExecutorRule()
    
    private lateinit var mockApplication: Application
    private lateinit var savedStateHandle: SavedStateHandle
    private lateinit var viewModel: MainViewModel
    
    @Before
    fun setUp() {
        mockApplication = mockk<Application>(relaxed = true)
        savedStateHandle = SavedStateHandle()
        viewModel = MainViewModel(mockApplication, savedStateHandle)
    }
    
    @Test
    fun `formState is initialized with empty defaults`() = runTest {
        val formState = viewModel.formState.first()
        
        assertEquals("", formState.selectedFilename)
        assertEquals("", formState.copiedFilePath)
        assertEquals("", formState.comments)
        assertEquals(0, formState.passwordInput.size)
        assertEquals(0, formState.confirmPasswordInput.size)
        assertEquals(false, formState.reedSolomon)
        assertEquals(false, formState.paranoid)
        assertEquals(false, formState.deniability)
        assertEquals(emptyList<KeyfileInfo>(), formState.keyfileFilenames)
        assertEquals(false, formState.keyfileOrdered)
        assertNull(formState.decryptionInfo)
    }
    
    @Test
    fun `formState restores from SavedStateHandle`() = runTest {
        savedStateHandle["selected_filename"] = "test.txt"
        savedStateHandle["copied_file_path"] = "/path/to/file.txt"
        savedStateHandle["comments"] = "Test comments"
        
        val restoredViewModel = MainViewModel(mockApplication, savedStateHandle)
        val formState = restoredViewModel.formState.first()
        
        assertEquals("test.txt", formState.selectedFilename)
        assertEquals("/path/to/file.txt", formState.copiedFilePath)
        assertEquals("Test comments", formState.comments)
        // Passwords should not be restored
        assertEquals(0, formState.passwordInput.size)
        assertEquals(0, formState.confirmPasswordInput.size)
    }
    
    @Test
    fun `updateFormData updates form state`() = runTest {
        val newFormData = TestDataBuilders.createEncryptFormData(
            selectedFilename = "newfile.txt",
            copiedFilePath = "/new/path.txt",
            comments = "New comments"
        )
        
        viewModel.updateFormData(newFormData)
        
        val formState = viewModel.formState.first()
        assertEquals("newfile.txt", formState.selectedFilename)
        assertEquals("/new/path.txt", formState.copiedFilePath)
        assertEquals("New comments", formState.comments)
    }
    
    @Test
    fun `updateFormData saves to SavedStateHandle`() = runTest {
        val newFormData = TestDataBuilders.createEncryptFormData(
            selectedFilename = "saved.txt",
            copiedFilePath = "/saved/path.txt",
            comments = "Saved comments"
        )
        
        viewModel.updateFormData(newFormData)
        
        assertEquals("saved.txt", savedStateHandle.get<String>("selected_filename"))
        assertEquals("/saved/path.txt", savedStateHandle.get<String>("copied_file_path"))
        assertEquals("Saved comments", savedStateHandle.get<String>("comments"))
    }
    
    @Test
    fun `updateFormData does not save passwords to SavedStateHandle`() = runTest {
        val newFormData = TestDataBuilders.createEncryptFormData(
            password = "secretpassword",
            confirmPassword = "secretpassword"
        )
        
        viewModel.updateFormData(newFormData)
        
        // Passwords should not be in SavedStateHandle
        assertNull(savedStateHandle.get<String>("passwordInput"))
        assertNull(savedStateHandle.get<String>("confirmPasswordInput"))
    }
    
    @Test
    fun `updatePasswords updates password fields`() = runTest {
        val password = "newpassword".toCharArray()
        val confirmPassword = "newpassword".toCharArray()
        
        viewModel.updatePasswords(password, confirmPassword)
        
        val formState = viewModel.formState.first()
        assertTrue("Password should be updated", formState.passwordInput.contentEquals(password))
        assertTrue("Confirm password should be updated", formState.confirmPasswordInput.contentEquals(confirmPassword))
    }
    
    @Test
    fun `updatePasswords clears old password arrays`() = runTest {
        val oldPassword = "oldpassword".toCharArray()
        val oldConfirm = "oldpassword".toCharArray()
        
        viewModel.updatePasswords(oldPassword, oldConfirm)
        
        val newPassword = "newpassword".toCharArray()
        val newConfirm = "newpassword".toCharArray()
        
        // Store references before update
        val formStateBefore = viewModel.formState.first()
        val oldPasswordRef = formStateBefore.passwordInput
        val oldConfirmRef = formStateBefore.confirmPasswordInput
        
        viewModel.updatePasswords(newPassword, newConfirm)
        
        // Old arrays should be cleared
        assertTrue("Old password should be cleared", oldPasswordRef.all { it == '\u0000' })
        assertTrue("Old confirm password should be cleared", oldConfirmRef.all { it == '\u0000' })
    }
    
    @Test
    fun `updatePasswords updates only password when confirmPassword is null`() = runTest {
        val password = "password".toCharArray()
        
        viewModel.updatePasswords(password, null)
        
        val formState = viewModel.formState.first()
        assertTrue("Password should be updated", formState.passwordInput.contentEquals(password))
        // Confirm password should remain unchanged (empty in this case)
        assertEquals(0, formState.confirmPasswordInput.size)
    }
    
    @Test
    fun `updatePasswords updates only confirmPassword when password is null`() = runTest {
        val confirmPassword = "confirm".toCharArray()
        
        viewModel.updatePasswords(null, confirmPassword)
        
        val formState = viewModel.formState.first()
        // Password should remain unchanged (empty in this case)
        assertEquals(0, formState.passwordInput.size)
        assertTrue("Confirm password should be updated", formState.confirmPasswordInput.contentEquals(confirmPassword))
    }
    
    @Test
    fun `clearSensitiveData clears passwords`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "secret",
            confirmPassword = "secret"
        )
        viewModel.updateFormData(formData)
        
        viewModel.clearSensitiveData(clearFiles = false)
        
        val formState = viewModel.formState.first()
        assertEquals(0, formState.passwordInput.size)
        assertEquals(0, formState.confirmPasswordInput.size)
    }
    
    @Test
    fun `clearSensitiveData clears files when clearFiles is true`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            selectedFilename = "test.txt",
            copiedFilePath = "/path/to/file.txt",
            comments = "Comments"
        )
        viewModel.updateFormData(formData)
        
        viewModel.clearSensitiveData(clearFiles = true)
        
        val formState = viewModel.formState.first()
        assertEquals("", formState.selectedFilename)
        assertEquals("", formState.copiedFilePath)
        assertEquals("", formState.comments)
        assertEquals(emptyList<KeyfileInfo>(), formState.keyfileFilenames)
        assertNull(formState.decryptionInfo)
    }
    
    @Test
    fun `clearSensitiveData preserves files when clearFiles is false`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            selectedFilename = "test.txt",
            copiedFilePath = "/path/to/file.txt",
            comments = "Comments"
        )
        viewModel.updateFormData(formData)
        
        viewModel.clearSensitiveData(clearFiles = false)
        
        val formState = viewModel.formState.first()
        assertEquals("test.txt", formState.selectedFilename)
        assertEquals("/path/to/file.txt", formState.copiedFilePath)
        assertEquals("Comments", formState.comments)
    }
    
    @Test
    fun `clearSensitiveData removes from SavedStateHandle when clearFiles is true`() = runTest {
        savedStateHandle["selected_filename"] = "test.txt"
        savedStateHandle["copied_file_path"] = "/path.txt"
        savedStateHandle["comments"] = "Comments"
        
        viewModel.clearSensitiveData(clearFiles = true)
        
        // updateFormData is called at the end, which sets empty strings
        // So we check for empty strings instead of null
        assertEquals("", savedStateHandle.get<String>("selected_filename"))
        assertEquals("", savedStateHandle.get<String>("copied_file_path"))
        assertEquals("", savedStateHandle.get<String>("comments"))
    }
    
    @Test
    fun `resetFormToDefaults resets all fields`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            comments = "Comments",
            reedSolomon = true,
            paranoid = true,
            deniability = true,
            keyfiles = listOf(TestDataBuilders.createKeyfileInfo()),
            keyfileOrdered = true
        )
        viewModel.updateFormData(formData)
        
        viewModel.resetFormToDefaults()
        
        val formState = viewModel.formState.first()
        assertEquals("", formState.comments)
        assertEquals(0, formState.passwordInput.size)
        assertEquals(0, formState.confirmPasswordInput.size)
        assertEquals(false, formState.reedSolomon)
        assertEquals(false, formState.paranoid)
        assertEquals(false, formState.deniability)
        assertEquals(emptyList<KeyfileInfo>(), formState.keyfileFilenames)
        assertEquals(false, formState.keyfileOrdered)
        assertNull(formState.decryptionInfo)
    }
    
    @Test
    fun `setError sets error message`() = runTest {
        val error = AppError.ValidationError.NoFileSelected
        
        viewModel.setError(error)
        
        val errorMessage = viewModel.errorMessage.first()
        assertEquals(error, errorMessage)
    }
    
    @Test
    fun `clearError clears error message`() = runTest {
        val error = AppError.ValidationError.InvalidPassword
        viewModel.setError(error)
        
        viewModel.clearError()
        
        val errorMessage = viewModel.errorMessage.first()
        assertNull("Error should be cleared", errorMessage)
    }
    
    @Test
    fun `errorMessage is initially null`() = runTest {
        val errorMessage = viewModel.errorMessage.first()
        assertNull("Error message should be null initially", errorMessage)
    }
}

