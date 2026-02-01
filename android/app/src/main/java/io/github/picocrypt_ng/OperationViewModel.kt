package io.github.picocrypt_ng

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/**
 * ViewModel for managing encryption/decryption operations and centralized progress polling.
 */
class OperationViewModel : ViewModel() {
    // Expose OperationManager's state as our own
    val operationState: StateFlow<OperationState?> = OperationManager.currentOperation
    
    private var pollingJob: Job? = null
    private var backgroundPollingJob: Job? = null
    private var isForeground = true
    
    /**
     * Starts an encryption operation and begins polling progress.
     */
    fun startEncrypt(context: Context, formData: FormData) {
        viewModelScope.launch {
            val result = OperationManager.startEncrypt(context, formData)
            result.onSuccess {
                startPolling()
            }
        }
    }
    
    /**
     * Starts a decryption operation and begins polling progress.
     */
    fun startDecrypt(context: Context, formData: FormData) {
        viewModelScope.launch {
            val result = OperationManager.startDecrypt(context, formData)
            result.onSuccess {
                startPolling()
            }
        }
    }
    
    /**
     * Cancels the current operation and stops polling.
     */
    fun cancelOperation() {
        viewModelScope.launch {
            stopPolling()
            OperationManager.cancelOperation()
        }
    }
    
    /**
     * Clears the current operation and stops polling.
     * @param context Android context for file cleanup
     * @param shouldCleanupFiles If true, deletes input, output, and keyfiles from internal storage.
     */
    fun clearOperation(context: Context? = null, shouldCleanupFiles: Boolean = true) {
        viewModelScope.launch {
            stopPolling()
            OperationManager.clearOperation(context, shouldCleanupFiles)
        }
    }
    
    /**
     * Retries an operation with the same files and options but allows password to be re-entered.
     */
    fun retryOperation(context: Context, formData: FormData) {
        viewModelScope.launch {
            stopPolling()
            val result = OperationManager.retryOperation(context, formData)
            result.onSuccess {
                startPolling()
            }
        }
    }
    
    /**
     * Retries decryption with force decrypt enabled.
     */
    fun retryDecryptWithForce() {
        viewModelScope.launch {
            stopPolling()
            val result = OperationManager.retryDecryptWithForce()
            result.onSuccess {
                startPolling()
            }
        }
    }
    
    /**
     * Pauses polling when app goes to background.
     * Switches to background polling mode (slower frequency) to keep state updated for notifications.
     */
    fun pausePolling() {
        isForeground = false
        stopPolling() // Stop foreground polling
        startBackgroundPolling() // Start background polling for notifications
    }
    
    /**
     * Resumes polling when app returns to foreground.
     * Immediately polls once to catch up on state, then resumes interval polling if operation is still active.
     */
    fun resumePolling() {
        isForeground = true
        stopBackgroundPolling() // Stop background polling
        
        // Immediate poll and wait for it to complete before checking state
        viewModelScope.launch {
            OperationManager.pollProgress()
            
            // Check state after poll completes
            val currentOp = operationState.value
            if (currentOp != null && !currentOp.done) {
                startPolling() // Resume foreground polling
            }
            // If done, don't start polling - UI will show final state via StateFlow
        }
    }
    
    /**
     * Starts polling progress for the current operation.
     * Polls every 500ms until the operation completes or is cancelled.
     * Only polls when app is in foreground.
     */
    private fun startPolling() {
        stopPolling() // Stop any existing polling
        
        if (!isForeground) {
            // Don't start polling if app is in background
            return
        }
        
        pollingJob = viewModelScope.launch {
            while (true) {
                delay(500) // Poll every 500ms
                
                // Check if still in foreground before polling
                if (!isForeground) {
                    break
                }
                
                val operation = OperationManager.currentOperation.value
                if (operation == null || operation.done) {
                    // Operation completed or was cleared, stop polling
                    break
                }
                
                // Poll progress
                OperationManager.pollProgress()
            }
        }
    }
    
    /**
     * Stops the current polling job.
     */
    private fun stopPolling() {
        pollingJob?.cancel()
        pollingJob = null
    }
    
    /**
     * Starts background polling at reduced frequency (2 seconds) to keep state updated for notifications.
     * This runs when the app is in the background.
     */
    private fun startBackgroundPolling() {
        stopBackgroundPolling()
        
        backgroundPollingJob = viewModelScope.launch {
            while (true) {
                delay(2000) // Poll every 2 seconds in background
                
                val operation = OperationManager.currentOperation.value
                if (operation == null || operation.done) {
                    // Operation completed or was cleared, stop polling
                    break
                }
                
                // Poll progress to update state (notification will be updated by MainActivity observer)
                OperationManager.pollProgress()
            }
        }
    }
    
    /**
     * Stops the background polling job.
     */
    private fun stopBackgroundPolling() {
        backgroundPollingJob?.cancel()
        backgroundPollingJob = null
    }
    
    override fun onCleared() {
        super.onCleared()
        stopPolling()
        stopBackgroundPolling()
    }
}

