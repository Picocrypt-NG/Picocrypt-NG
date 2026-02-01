package io.github.picocrypt_ng


import android.app.Application
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.remember
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.SavedStateHandle
import io.github.picocrypt_ng.FileCopyService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.lifecycle.lifecycleScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.unit.dp
import io.github.picocrypt_ng.ui.components.AdvancedCard
import io.github.picocrypt_ng.ui.components.CommentsCard
import io.github.picocrypt_ng.ui.components.DecryptionInfoCard
import io.github.picocrypt_ng.ui.components.ErrorDialog
import io.github.picocrypt_ng.ui.components.FileCard
import io.github.picocrypt_ng.ui.components.KeyfileCard
import io.github.picocrypt_ng.ui.components.LogoBar
import io.github.picocrypt_ng.ui.components.PasswordCard
import io.github.picocrypt_ng.ui.components.ProgressCard
import io.github.picocrypt_ng.ui.components.WorkButton
import io.github.picocrypt_ng.ui.theme.PicocryptNGTheme

// Enum to track card visibility for spacing
private enum class CardType {
    FILE,
    COMMENTS,
    DECRYPTION_INFO,
    PASSWORD,
    ADVANCED,
    KEYFILE,
    WORK_BUTTON
}

class MainActivity : ComponentActivity() {
    private var operationViewModel: OperationViewModel? = null
    private var backgroundObserverJob: Job? = null
    private val backgroundScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    
    // Static flag to track if cleanup has been done in this process lifecycle
    // This ensures cleanup only happens once per app process, not on every activity recreation
    companion object {
        @Volatile
        private var cleanupDoneInThisProcess = false
    }
    
    // Permission launcher for notification permission (Android 13+)
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        // Permission result handled - notification service will check permission before showing
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Cleanup files on app startup (only once per process lifecycle, not on activity recreation)
        // Use a static flag to ensure cleanup only happens once per app process
        if (!cleanupDoneInThisProcess) {
            cleanupDoneInThisProcess = true
            lifecycleScope.launch(Dispatchers.IO) {
                FileCopyService.cleanupAllFiles(this@MainActivity)
            }
        }
        
        // Request notification permission if needed (Android 13+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this,
                    android.Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                requestPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        
        enableEdgeToEdge()
        setContent {
            PicocryptNGTheme {
                Scaffold { innerPadding ->
                    Column(modifier = Modifier.padding(innerPadding)) {
                        MainLayout { viewModel ->
                            // Store ViewModel reference for lifecycle hooks
                            operationViewModel = viewModel
                        }
                    }
                }
            }
        }
    }
    
    override fun onPause() {
        super.onPause()
        operationViewModel?.pausePolling()
        
        // Start observing operation state to update notification while backgrounded
        operationViewModel?.let { viewModel ->
            // Show initial notification if operation is active
            val currentOp = viewModel.operationState.value
            if (currentOp != null && !currentOp.done) {
                OperationNotificationService.showNotification(
                    this,
                    currentOp.type,
                    currentOp.status
                )
            }
            
            // Observe state changes and update notification
            backgroundObserverJob = viewModel.operationState
                .onEach { operationState ->
                    if (operationState != null && !operationState.done) {
                        // Reset dismissal state when operation becomes active (new operation started)
                        if (operationState.progress == 0.0f && operationState.status == "Starting...") {
                            OperationNotificationService.resetDismissalState()
                        }
                        
                        // Update notification with latest progress
                        OperationNotificationService.updateNotification(
                            this,
                            operationState.progress,
                            operationState.status
                        )
                    } else if (operationState?.done == true) {
                        // Operation completed, update notification with final status
                        val finalStatus = if (operationState.error != null) {
                            "Error: ${operationState.error}"
                        } else {
                            "Completed"
                        }
                        OperationNotificationService.updateNotification(
                            this,
                            1.0f,
                            finalStatus
                        )
                    }
                }
                .launchIn(backgroundScope)
        }
    }
    
    override fun onResume() {
        super.onResume()
        
        // Stop observing operation state (we're back in foreground)
        backgroundObserverJob?.cancel()
        backgroundObserverJob = null
        
        // Hide notification
        OperationNotificationService.hideNotification(this)
        
        // Reset dismissal state (notification should be hidden anyway when app resumes)
        OperationNotificationService.resetDismissalState()
        
        // Resume polling
        operationViewModel?.resumePolling()
    }
    
    override fun onDestroy() {
        super.onDestroy()
        // Clean up background scope
        backgroundScope.cancel()
    }
}



@Composable
fun MainLayout(
    onOperationViewModelCreated: (OperationViewModel) -> Unit = {}
) {
    val context = LocalContext.current
    
    // Create ViewModels
    val mainViewModel: MainViewModel = viewModel(
        factory = object : androidx.lifecycle.ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : androidx.lifecycle.ViewModel> create(modelClass: Class<T>): T {
                val savedStateHandle = SavedStateHandle()
                return MainViewModel(
                    context.applicationContext as Application,
                    savedStateHandle
                ) as T
            }
        }
    )
    val operationViewModel: OperationViewModel = viewModel()
    
    // Notify Activity about ViewModel creation
    LaunchedEffect(operationViewModel) {
        onOperationViewModelCreated(operationViewModel)
    }
    
    // Observe form state from ViewModel
    val formData by mainViewModel.formState.collectAsState()
    
    // Observe error state from ViewModel
    val errorMessage by mainViewModel.errorMessage.collectAsState()
    
    val scrollState = rememberScrollState()
    val focusManager = LocalFocusManager.current
    
    // Observe operation state to clear sensitive data when operation completes
    val operationState by operationViewModel.operationState.collectAsState()
    var previousOperationState by remember { mutableStateOf<OperationState?>(null) }
    
    LaunchedEffect(operationState) {
        val previous = previousOperationState
        
        // If operation was cleared after completion, clear sensitive FormData
        // BUT: Don't clear files if it was a password/auth error (user might retry)
        if (previous != null && previous.done && operationState == null) {
            // Check if this was a password/auth error - if so, preserve files for retry
            val isPasswordError = previous.error?.isPasswordError() == true
            
            if (isPasswordError) {
                // Password error - only clear passwords, preserve files and settings for retry
                mainViewModel.clearSensitiveData(clearFiles = false)
            } else {
                // Non-password error or success - full cleanup
                mainViewModel.clearSensitiveData(clearFiles = true)
            }
        }
        
        previousOperationState = operationState
    }

    // Compute visibility for all cards upfront
    val isFileCardVisible = true // Always visible
    val isCommentsCardVisible = remember(formData) {
        if (!(formData.isEncrypt || formData.isDecrypt)) {
            false
        } else if (formData.isDecrypt) {
            // For decrypt: show if comments exist OR if decryptionInfo is not readable (to show "not readable" message)
            val decryptionInfo = formData.decryptionInfo
            formData.comments.isNotEmpty() || (decryptionInfo != null && !decryptionInfo.readable)
        } else {
            true // Always show for encrypt
        }
    }
    val isDecryptionInfoCardVisible = remember(formData) {
        formData.isDecrypt && formData.decryptionInfo != null
    }
    val isPasswordCardVisible = remember(formData) {
        formData.isEncrypt || formData.isDecrypt
    }
    val isAdvancedCardVisible = remember(formData) {
        formData.isEncrypt
    }
    val isKeyfileCardVisible = remember(formData) {
        if (!(formData.isEncrypt || formData.isDecrypt)) {
            false
        } else if (formData.isDecrypt) {
            // For decrypt: show if keyfiles required or if deniability mode (unknown)
            val decryptionInfo = formData.decryptionInfo
            decryptionInfo == null || !decryptionInfo.readable || decryptionInfo.keyfilesRequired
        } else {
            true // Always show for encrypt
        }
    }
    val isWorkButtonVisible = remember(formData) {
        formData.isEncrypt || formData.isDecrypt
    }
    
    // Helper function to add spacing between cards
    @Composable
    fun SpacerIf(condition: Boolean) {
        if (condition) {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
    
    // Track which card was last visible to determine spacing
    var lastVisibleCard by remember { mutableStateOf<CardType?>(null) }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(scrollState)
            .imePadding()
            .clickable( // Allow tapping outside of fields to unfocus them
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                onClick = { focusManager.clearFocus() }),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        LogoBar()
        
        // FileCard - always visible (no spacing before first card)
        if (isFileCardVisible) {
            FileCard(mainViewModel)
            lastVisibleCard = CardType.FILE
        }
        
        // CommentsCard - add spacing if previous card was visible
        if (isCommentsCardVisible) {
            SpacerIf(lastVisibleCard != null)
            CommentsCard(mainViewModel)
            lastVisibleCard = CardType.COMMENTS
        }
        
        // DecryptionInfoCard - add spacing if previous card was visible
        if (isDecryptionInfoCardVisible) {
            SpacerIf(lastVisibleCard != null)
            DecryptionInfoCard(mainViewModel)
            lastVisibleCard = CardType.DECRYPTION_INFO
        }
        
        // PasswordCard - add spacing if previous card was visible
        if (isPasswordCardVisible) {
            SpacerIf(lastVisibleCard != null)
            PasswordCard(mainViewModel)
            lastVisibleCard = CardType.PASSWORD
        }
        
        // AdvancedCard - add spacing if previous card was visible
        if (isAdvancedCardVisible) {
            SpacerIf(lastVisibleCard != null)
            AdvancedCard(mainViewModel)
            lastVisibleCard = CardType.ADVANCED
        }
        
        // KeyfileCard - add spacing if previous card was visible
        if (isKeyfileCardVisible) {
            SpacerIf(lastVisibleCard != null)
            KeyfileCard(mainViewModel)
            lastVisibleCard = CardType.KEYFILE
        }
        
        // WorkButton - add spacing if previous card was visible
        if (isWorkButtonVisible) {
            SpacerIf(lastVisibleCard != null)
            WorkButton(mainViewModel, operationViewModel)
            lastVisibleCard = CardType.WORK_BUTTON
        }
        
        // ProgressCard is now a modal dialog, not part of scrollable content
        ProgressCard(
            mainViewModel = mainViewModel,
            operationViewModel = operationViewModel
        )
        
        // ErrorDialog for non-operation errors (file operations, etc.)
        ErrorDialog(
            error = errorMessage,
            onDismiss = { mainViewModel.clearError() }
        )
    }
}