package io.github.picocrypt_ng.picocrypt_ng


import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.DEFAULT_ARGS_KEY
import androidx.lifecycle.viewmodel.CreationExtras
import androidx.lifecycle.viewmodel.MutableCreationExtras
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.compose.LifecycleResumeEffect
import kotlinx.coroutines.launch
import androidx.lifecycle.lifecycleScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.unit.dp
import io.github.picocrypt_ng.picocrypt_ng.ui.components.AdvancedCard
import io.github.picocrypt_ng.picocrypt_ng.ui.components.CommentsCard
import io.github.picocrypt_ng.picocrypt_ng.ui.components.DecryptOptionsCard
import io.github.picocrypt_ng.picocrypt_ng.ui.components.DecryptionInfoCard
import io.github.picocrypt_ng.picocrypt_ng.ui.components.ErrorDialog
import io.github.picocrypt_ng.picocrypt_ng.ui.components.FileCard
import io.github.picocrypt_ng.picocrypt_ng.ui.components.KeyfileCard
import io.github.picocrypt_ng.picocrypt_ng.ui.components.LogoBar
import io.github.picocrypt_ng.picocrypt_ng.ui.components.PasswordCard
import io.github.picocrypt_ng.picocrypt_ng.ui.components.PrivacyCard
import io.github.picocrypt_ng.picocrypt_ng.ui.components.ProgressCard
import io.github.picocrypt_ng.picocrypt_ng.ui.components.WorkButton
import io.github.picocrypt_ng.picocrypt_ng.ui.theme.PicocryptNGTheme

class MainActivity : ComponentActivity() {
    // Exported launch extras are not process-restoration authority.
    override val defaultViewModelCreationExtras: CreationExtras
        get() = MutableCreationExtras(super.defaultViewModelCreationExtras).apply {
            this[DEFAULT_ARGS_KEY] = Bundle.EMPTY
        }

    // Permission launcher for notification permission (Android 13+)
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        // Permission result handled - notification service will check permission before showing
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Apply screenshot protection before the first frame so the cold-start frame is
        // already secure under the default-ON setting. Orthogonal to enableEdgeToEdge().
        val settingsRepository = SettingsRepository.getInstance(this)
        if (settingsRepository.screenshotProtectionEnabled.value) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }

        enableEdgeToEdge()

        lifecycleScope.launch {
            check(StartupCleanup.runBeforeUi(this@MainActivity)) {
                "Startup cleanup failed before UI initialization"
            }

            requestNotificationPermissionIfNeeded()
            showMainContent()
            observeScreenshotProtection(settingsRepository)
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
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
    }

    private fun showMainContent() {
        setContent {
            PicocryptNGTheme {
                Scaffold { innerPadding ->
                    Column(modifier = Modifier.padding(innerPadding)) {
                        MainLayout()
                    }
                }
            }
        }
    }

    private fun observeScreenshotProtection(settingsRepository: SettingsRepository) {
        // Apply runtime toggles of the screenshot-protection setting to the activity window.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                settingsRepository.screenshotProtectionEnabled.collect { secure ->
                    if (secure) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
            }
        }
    }
}



@Composable
fun MainLayout() {
    // Create ViewModels. The default SavedStateViewModelFactory (the Activity's
    // defaultViewModelProviderFactory) injects both the Application and a registry-backed
    // SavedStateHandle into MainViewModel's (Application, SavedStateHandle) constructor, so
    // its saved fields survive process death.
    val mainViewModel: MainViewModel = viewModel()
    val operationViewModel: OperationViewModel = viewModel()
    // Static for the loaded AAR and intentionally separate from fresh native
    // admission performed for every operation.
    val pcv3AndroidPolicyState = GoBridge.pcv3AndroidPolicyState

    // Drive the operation polling cadence from the Compose lifecycle: poll at foreground
    // frequency while RESUMED, drop to background frequency on pause/dispose.
    LifecycleResumeEffect(operationViewModel) {
        operationViewModel.resumePolling()
        onPauseOrDispose { operationViewModel.pausePolling() }
    }

    // Observe form state from ViewModel
    val formData by mainViewModel.formState.collectAsState()

    // Observe error state from ViewModel
    val errorMessage by mainViewModel.errorMessage.collectAsState()

    // Screenshot-protection setting, observed from the process-singleton repository.
    val context = LocalContext.current
    val settingsRepository = remember { SettingsRepository.getInstance(context.applicationContext) }
    val screenshotProtection by settingsRepository.screenshotProtectionEnabled.collectAsState()
    
    val scrollState = rememberScrollState()
    val focusManager = LocalFocusManager.current
    
    // Observe operation state to clear sensitive data when operation completes
    val operationState by operationViewModel.operationState.collectAsState()
    val pcv3Presentation by operationViewModel.pcv3Presentation.collectAsState()
    val pcv3Intent by operationViewModel.pcv3Intent.collectAsState()
    val pcv3Busy by operationViewModel.pcv3Busy.collectAsState()
    val pcv3Error by operationViewModel.pcv3Error.collectAsState()
    val pcv3ArtifactDetails by operationViewModel.pcv3ArtifactDetails.collectAsState()
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
    val isAnyOperationActive = operationState != null || pcv3Busy
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
    val isConfiguredPcv3Selection =
        pcv3AndroidPolicyState == Pcv3AndroidPolicyState.CONFIGURED &&
            formData.isPcv3Selection && !formData.pcvUnavailable
    // A live consent projection is an independent lifecycle path; the static
    // policy flag itself grants neither a request nor operation authority.
    val isDecryptOptionsCardVisible = formData.isDecrypt || isConfiguredPcv3Selection ||
        (pcv3Presentation as? Pcv3Presentation.Live)?.consent != null
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
        formData.isEncrypt || formData.isDecrypt || isConfiguredPcv3Selection
    }
    
    // Collect only the currently visible cards, in render order. Arrangement.spacedBy(24.dp)
    // then yields no gap before the first card and 24.dp between consecutive cards — matching
    // the previous SpacerIf behavior without writing Compose state during composition.
    val visibleCards = buildList<@Composable () -> Unit> {
        if (isFileCardVisible) add {
            FileCard(
                viewModel = mainViewModel,
                enabled = !isAnyOperationActive,
                pcv3AndroidPolicyState = pcv3AndroidPolicyState,
            )
        }
        add { PrivacyCard(enabled = screenshotProtection, onChange = settingsRepository::setScreenshotProtectionEnabled) }
        if (isCommentsCardVisible) add { CommentsCard(mainViewModel) }
        if (isDecryptionInfoCardVisible) add { DecryptionInfoCard(mainViewModel) }
        if (isPasswordCardVisible) add { PasswordCard(mainViewModel) }
        if (isAdvancedCardVisible) add {
            AdvancedCard(mainViewModel, pcv3AndroidPolicyState = pcv3AndroidPolicyState)
        }
        if (isDecryptOptionsCardVisible) add {
            DecryptOptionsCard(
                viewModel = mainViewModel,
                pcv3Presentation = pcv3Presentation,
                onSelectPcv3ConsentRole = operationViewModel::selectPcv3ConsentRole,
                onConfirmPcv3Consent = operationViewModel::confirmPcv3Consent,
                onRefusePcv3Consent = operationViewModel::refusePcv3Consent,
            )
        }
        if (isKeyfileCardVisible) add { KeyfileCard(mainViewModel) }
        if (isWorkButtonVisible) add {
            WorkButton(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel,
                pcv3Presentation = pcv3Presentation,
            )
        }
    }

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

        // No gap between LogoBar and the first card; 24.dp between consecutive cards.
        Column(
            verticalArrangement = Arrangement.spacedBy(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            visibleCards.forEach { it() }
        }

        // ProgressCard is now a modal dialog, not part of scrollable content
        ProgressCard(
            mainViewModel = mainViewModel,
            operationViewModel = operationViewModel,
            pcv3Presentation = pcv3Presentation,
            pcv3Intent = pcv3Intent,
            onCancelPcv3 = operationViewModel::cancelPcv3,
            onClosePcv3Result = operationViewModel::dismissPcv3,
            onClosePcv3Archive = operationViewModel::closePcv3Archive,
            onBeginPcv3Archive = operationViewModel::beginPcv3Archive,
            onCompletePcv3Archive = operationViewModel::completePcv3Archive,
            pcv3ArtifactDetails = pcv3ArtifactDetails,
            onBeginPcv3Save = operationViewModel::beginPcv3Save,
            onCompletePcv3Save = operationViewModel::completePcv3Save,
            onDiscardPcv3Output = operationViewModel::discardPcv3Output,
            onInspectPcv3Artifact = operationViewModel::inspectPcv3Artifact,
            onLoadPcv3ArtifactPage = operationViewModel::loadPcv3ArtifactPage,
            onClosePcv3ArtifactInspection = operationViewModel::closePcv3ArtifactInspection,
        )
        
        // ErrorDialog for non-operation errors (file operations, etc.)
        ErrorDialog(
            error = errorMessage,
            onDismiss = { mainViewModel.clearError() }
        )
        ErrorDialog(
            // A cleanup failure never replaces or obscures the native terminal result.
            // Once that result is dismissed, the retained cleanup error is shown.
            // Save failures remain visible while the output awaits another destination.
            error = pcv3VisibleError(pcv3Error, pcv3Presentation),
            onDismiss = operationViewModel::clearPcv3Error,
        )
    }
}
