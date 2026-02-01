package io.github.picocrypt_ng

import android.app.Application
import android.content.Context
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * ViewModel for managing form state and UI-related data.
 */
class MainViewModel(
    application: Application,
    private val savedStateHandle: SavedStateHandle
) : AndroidViewModel(application) {
    // Keys for SavedStateHandle (only for process recreation, not persistence)
    private val KEY_SELECTED_FILENAME = "selected_filename"
    private val KEY_COPIED_FILE_PATH = "copied_file_path"
    private val KEY_COMMENTS = "comments"
    
    // Restore saved state or use defaults (no persistence between app runs)
    private val initialFormData = FormData(
        selectedFilename = savedStateHandle.get<String>(KEY_SELECTED_FILENAME) ?: "",
        copiedFilePath = savedStateHandle.get<String>(KEY_COPIED_FILE_PATH) ?: "",
        comments = savedStateHandle.get<String>(KEY_COMMENTS) ?: "",
        passwordInput = CharArray(0), // Never save passwords - use empty CharArray
        confirmPasswordInput = CharArray(0), // Never save passwords - use empty CharArray
        reedSolomon = false, // Always default, no persistence
        paranoid = false, // Always default, no persistence
        deniability = false, // Always default, no persistence
        keyfileFilenames = emptyList(), // Always default, no persistence
        keyfileOrdered = false, // Always default, no persistence
        decryptionInfo = null // Never save decryption info (transient)
    )
    
    private val _formState = MutableStateFlow(initialFormData)
    
    val formState: StateFlow<FormData> = _formState.asStateFlow()
    
    // Error state for non-operation errors (file operations, etc.)
    private val _errorMessage = MutableStateFlow<AppError?>(null)
    val errorMessage: StateFlow<AppError?> = _errorMessage.asStateFlow()
    
    /**
     * Sets an error message to be displayed to the user.
     */
    fun setError(error: AppError) {
        _errorMessage.value = error
    }
    
    /**
     * Clears the current error message.
     */
    fun clearError() {
        _errorMessage.value = null
    }
    
    /**
     * Updates the form data with new values.
     * Only saves minimal fields to SavedStateHandle for process recreation.
     * Advanced settings and keyfile settings are NOT persisted.
     */
    fun updateFormData(newData: FormData) {
        _formState.value = newData
        
        // Only save minimal fields to SavedStateHandle for process recreation
        // Do NOT persist advanced settings or keyfile settings
        savedStateHandle[KEY_SELECTED_FILENAME] = newData.selectedFilename
        savedStateHandle[KEY_COPIED_FILE_PATH] = newData.copiedFilePath
        savedStateHandle[KEY_COMMENTS] = newData.comments
        // Note: passwordInput, confirmPasswordInput, decryptionInfo, advanced settings, 
        // and keyfile settings are NOT saved
    }
    
    /**
     * Updates password fields atomically to prevent race conditions.
     * Uses StateFlow.update() to ensure thread-safe updates.
     * 
     * @param password New password as CharArray, or null to keep current
     * @param confirmPassword New confirm password as CharArray, or null to keep current
     */
    fun updatePasswords(password: CharArray? = null, confirmPassword: CharArray? = null) {
        _formState.update { current ->
            // Store references to old password arrays for clearing
            val oldPassword = current.passwordInput
            val oldConfirm = current.confirmPasswordInput
            
            // Create new FormData with updated passwords (using copyOf to create new arrays)
            val updated = current.copy(
                passwordInput = password?.copyOf() ?: current.passwordInput,
                confirmPasswordInput = confirmPassword?.copyOf() ?: current.confirmPasswordInput
            )
            
            // Clear old password arrays if they're being replaced
            // We clear the old arrays since we've created new copies
            if (password != null) {
                oldPassword.fill('\u0000')
            }
            if (confirmPassword != null) {
                oldConfirm.fill('\u0000')
            }
            
            updated
        }
        
        // Update SavedStateHandle (passwords are not saved, but other fields might have changed)
        val updated = _formState.value
        savedStateHandle[KEY_SELECTED_FILENAME] = updated.selectedFilename
        savedStateHandle[KEY_COPIED_FILE_PATH] = updated.copiedFilePath
        savedStateHandle[KEY_COMMENTS] = updated.comments
    }
    
    /**
     * Clears sensitive fields from FormData while preserving convenience settings.
     * Explicitly zeros password arrays for security.
     * @param clearFiles If true, also clears file selections and keyfiles
     */
    fun clearSensitiveData(clearFiles: Boolean = true) {
        val current = _formState.value
        
        // Clear and zero password arrays
        current.clearPasswords()
        
        // Always clear passwords (create new empty arrays)
        var cleared = current.copy(
            passwordInput = CharArray(0),
            confirmPasswordInput = CharArray(0)
        )
        
        // Conditionally clear files
        if (clearFiles) {
            cleared = cleared.copy(
                selectedFilename = "",
                copiedFilePath = "",
                comments = "",
                keyfileFilenames = emptyList(),
                decryptionInfo = null
            )
            
            // Also clear from SavedStateHandle
            savedStateHandle.remove<String>(KEY_SELECTED_FILENAME)
            savedStateHandle.remove<String>(KEY_COPIED_FILE_PATH)
            savedStateHandle.remove<String>(KEY_COMMENTS)
        }
        
        _formState.value = cleared
        // Update SavedStateHandle with new values
        updateFormData(cleared)
    }
    
    /**
     * Resets the form to default values. Used when a new file is selected.
     * Clears all fields including comments, passwords, advanced settings, and keyfiles.
     * Explicitly zeros password arrays for security.
     */
    fun resetFormToDefaults() {
        val current = _formState.value
        
        // Clear and zero existing password arrays
        current.clearPasswords()
        
        val reset = current.copy(
            comments = "",
            passwordInput = CharArray(0),
            confirmPasswordInput = CharArray(0),
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false,
            decryptionInfo = null
        )
        _formState.value = reset
        // Update SavedStateHandle
        updateFormData(reset)
    }
}

