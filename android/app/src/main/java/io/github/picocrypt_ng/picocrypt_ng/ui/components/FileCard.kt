package io.github.picocrypt_ng.picocrypt_ng.ui.components


import android.net.Uri
import android.os.CancellationSignal
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.FileCopyService
import io.github.picocrypt_ng.picocrypt_ng.FormData
import io.github.picocrypt_ng.picocrypt_ng.GoBridge
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationManager
import io.github.picocrypt_ng.picocrypt_ng.Pcv3AndroidPolicyState
import io.github.picocrypt_ng.picocrypt_ng.Pcv3FormatIntent
import io.github.picocrypt_ng.picocrypt_ng.Pcv3Route
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.SelectionKind
import androidx.compose.runtime.collectAsState
import io.github.picocrypt_ng.picocrypt_ng.StagedSelection
import io.github.picocrypt_ng.picocrypt_ng.StagingService
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext


private const val MAX_SELECTED_FILE_DISPLAY_CHARS = 256

private data class PendingSingleFileSelection(
    val uri: Uri,
    val releasedSources: List<String>,
)

@Composable
fun ChooseFile(
    viewModel: MainViewModel,
    enabled: Boolean = true,
    pcv3AndroidPolicyState: Pcv3AndroidPolicyState = Pcv3AndroidPolicyState.UNCONFIGURED,
) {
    val context = LocalContext.current
    val unknownErrorMsg = stringResource(R.string.error_unknown)
    val formData by viewModel.formState.collectAsState()
    var isCopying by remember { mutableStateOf(false) }
    var isCheckingRoute by remember { mutableStateOf(false) }
    var pendingSingleFile by remember { mutableStateOf<PendingSingleFileSelection?>(null) }
    var allowPcv3D1 by remember(pcv3AndroidPolicyState) { mutableStateOf(false) }
    val selectionEnabled by rememberUpdatedState(enabled)

    fun canAcceptSelection(): Boolean = selectionEnabled && !isCopying && !isCheckingRoute &&
        pendingSingleFile == null && !OperationManager.currentPcv3InputCleanupPending.value
    
    // Handle file copying and detection when URI is selected
    LaunchedEffect(pendingSingleFile) {
        val selection = pendingSingleFile ?: return@LaunchedEffect
        var localCopiedOwner: String? = null
        isCopying = true
        try {
            // The picker callback already invalidated the runnable form. Its released
            // owner must be deleted before this copy can claim the fixed final path.
            if (!cleanupReplacedSelection(context, selection.releasedSources)) {
                viewModel.setError(selectionCleanupError())
                return@LaunchedEffect
            }
            if (!selectionEnabled) {
                return@LaunchedEffect
            }

            val (displayName, queryError) = withContext(Dispatchers.IO) {
                val signal = CancellationSignal()
                val watcher = launch(start = CoroutineStart.UNDISPATCHED) {
                    try {
                        awaitCancellation()
                    } finally {
                        try { signal.cancel() } catch (_: Exception) { }
                    }
                }
                try {
                    var name = ""
                    val failure = try {
                        context.contentResolver.query(
                            selection.uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null, signal,
                        )?.use { cursor ->
                            if (cursor.moveToFirst()) {
                                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                                if (nameIndex != -1) name = cursor.getString(nameIndex).orEmpty()
                            }
                        }
                        null
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (error: Exception) {
                        error.toAppError(unknownErrorMsg)
                    }
                    name to failure
                } finally {
                    withContext(NonCancellable) { watcher.cancelAndJoin() }
                }
            }
            val primaryError = queryError ?: if (FormData.isSplitVolumeChunkName(displayName)) {
                AppError.ValidationError.SplitVolumeNotSupported
            } else null
            primaryError?.let {
                viewModel.setError(it)
                return@LaunchedEffect
            }

            val copiedPath = FileCopyService.copyFileToInternalStorage(
                context,
                selection.uri,
                displayName,
            ).getOrElse { error ->
                viewModel.setError(error.toAppError(unknownErrorMsg))
                return@LaunchedEffect
            }
            localCopiedOwner = copiedPath

            isCopying = false
            isCheckingRoute = true
            val route = withContext(Dispatchers.IO) {
                GoBridge.detectPcv3Route(copiedPath)
            }.getOrElse {
                // Unknown/IO routing failures are terminal for this selection. They
                // never fall through to filename-based legacy behavior.
                viewModel.setError(pcv3RouteFailure())
                return@LaunchedEffect
            }

            when (route) {
                Pcv3Route.NORMAL -> {
                    val cleanup = routeNormalPcv3Selection(
                        viewModel = viewModel,
                        selectedFilename = displayName,
                        copiedPath = copiedPath,
                        policyState = pcv3AndroidPolicyState,
                    )
                    val cleanupComplete = deleteOwnedCopies(context, cleanup)
                    if (pcv3AndroidPolicyState == Pcv3AndroidPolicyState.CONFIGURED ||
                        cleanupComplete
                    ) {
                        localCopiedOwner = null
                    }
                    // An UNCONFIGURED refusal is the primary result and must not be
                    // replaced by a secondary app-private cleanup diagnostic.
                    if (!cleanupComplete &&
                        pcv3AndroidPolicyState == Pcv3AndroidPolicyState.CONFIGURED
                    ) {
                        viewModel.setError(selectionCleanupError())
                    }
                }
                Pcv3Route.UNSUPPORTED,
                Pcv3Route.INVALID,
                -> {
                    val code = if (route == Pcv3Route.UNSUPPORTED) {
                        "PCV3_UNSUPPORTED"
                    } else {
                        "PCV3_INVALID_STRUCTURE"
                    }
                    val refusal = AppError.OperationError.PCVUnavailable(
                        userMessage = "",
                        technicalMessage = code,
                        messageResId = R.string.error_pcv_unavailable,
                    )
                    val cleanup = viewModel.retainRefusedPcv3(
                        displayName,
                        copiedPath,
                        refusal,
                    )
                    // Cleanup failure must not mask the primary typed refusal.
                    if (deleteOwnedCopies(context, cleanup)) {
                        localCopiedOwner = null
                    }
                }
                Pcv3Route.LEGACY -> {
                    if (applyLegacySelection(
                        context = context,
                        viewModel = viewModel,
                        selectedFilename = displayName,
                        copiedPath = copiedPath,
                        unknownErrorMsg = unknownErrorMsg,
                    )) {
                        localCopiedOwner = null
                    }
                    allowPcv3D1 = pcv3AndroidPolicyState == Pcv3AndroidPolicyState.CONFIGURED
                }
            }
        } finally {
            localCopiedOwner?.let { path ->
                val cleanupComplete = deleteOwnedCopies(context, listOf(path))
                if (!cleanupComplete && viewModel.errorMessage.value == null) {
                    viewModel.setError(selectionCleanupError())
                }
            }
            isCopying = false
            isCheckingRoute = false
            pendingSingleFile = null
        }
    }
    
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (!canAcceptSelection()) return@rememberLauncherForActivityResult
        uri?.let { selected ->
            allowPcv3D1 = false
            // This is the first mutation after accepting a picker result. It closes
            // the interval in which Work could start the old form while replacement
            // metadata was queried or its deterministic copy was being scheduled.
            val releasedSources = viewModel.resetFormToDefaults()
            isCopying = true

            pendingSingleFile = PendingSingleFileSelection(
                uri = selected,
                releasedSources = releasedSources,
            )
        }
    }

    val scope = rememberCoroutineScope()

    val folderPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        if (!canAcceptSelection()) return@rememberLauncherForActivityResult
        uri ?: return@rememberLauncherForActivityResult
        allowPcv3D1 = false
        // Invalidate the runnable form before scheduling staging. UNDISPATCHED
        // enters the protected cleanup before this callback can return.
        val sourceToRelease = viewModel.resetFormToDefaults()
        isCopying = true
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                if (!cleanupReplacedSelection(context, sourceToRelease)) {
                    viewModel.setError(selectionCleanupError())
                    return@launch
                }
                if (!selectionEnabled) return@launch

                applyStagedSelection(viewModel, unknownErrorMsg) {
                    StagingService.copyTreeToStaging(context, uri)
                }
            } finally {
                isCopying = false
            }
        }
    }

    val filesPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments()
    ) { uris: List<Uri> ->
        if (!canAcceptSelection()) return@rememberLauncherForActivityResult
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        allowPcv3D1 = false
        // Match the single/folder path: old source ownership is removed from the
        // runnable form synchronously, then cleaned before staging writes begin.
        val sourceToRelease = viewModel.resetFormToDefaults()
        isCopying = true
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                if (!cleanupReplacedSelection(context, sourceToRelease)) {
                    viewModel.setError(selectionCleanupError())
                    return@launch
                }
                if (!selectionEnabled) return@launch

                applyStagedSelection(viewModel, unknownErrorMsg) {
                    StagingService.copyFilesToStaging(
                        context,
                        uris,
                        System.currentTimeMillis() / 1000,
                    )
                }
            } finally {
                isCopying = false
            }
        }
    }

    var menuOpen by remember { mutableStateOf(false) }
    LaunchedEffect(enabled) {
        if (!enabled) menuOpen = false
    }
    val isBusy = isCopying || isCheckingRoute
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp)
            .clickable(enabled = enabled && !isBusy) { menuOpen = true },
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        if (isBusy) {
            CircularProgressIndicator(modifier = Modifier.padding(8.dp))
            Text(
                stringResource(
                    if (isCheckingRoute) R.string.pcv3_checking_selected_file else R.string.copying_file,
                ),
            )
        } else {
            Text(
                text = when {
                    formData.selectedFilename.isNotEmpty() ->
                        formData.selectedFilename.take(MAX_SELECTED_FILE_DISPLAY_CHARS)
                    formData.isPcv3Selection -> stringResource(R.string.pcv3_selected_file)
                    else -> stringResource(R.string.choose_file)
                },
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            // Keep the folder icon and its dropdown in a Box: a DropdownMenu placed directly in
            // this SpaceBetween Row would, while expanded, add a zero-size popup anchor as a third
            // arrangement child, shoving the icon from the right edge toward the center. Anchoring
            // the menu inside the Box keeps the Row at two children, so the icon never moves.
            Box {
                Icon(
                    imageVector = Icons.Filled.Folder,
                    contentDescription = stringResource(R.string.choose_file_description)
                )
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.choose_single_file)) },
                        enabled = enabled,
                        onClick = { menuOpen = false; filePickerLauncher.launch("*/*") }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.choose_multiple_files)) },
                        enabled = enabled,
                        onClick = { menuOpen = false; filesPickerLauncher.launch(arrayOf("*/*")) }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.choose_folder)) },
                        enabled = enabled,
                        onClick = { menuOpen = false; folderPickerLauncher.launch(null) }
                    )
                }
            }
        }
    }

    formData.pcv3Intent?.let { intent ->
        Text(
            text = stringResource(
                if (intent.format == Pcv3FormatIntent.NORMAL) {
                    R.string.pcv3_format_normal
                } else {
                    R.string.pcv3_format_d1
                },
            ),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 8.dp),
        )
    }
    val canSelectD1 = pcv3AndroidPolicyState == Pcv3AndroidPolicyState.CONFIGURED &&
        allowPcv3D1 && !formData.isPcv3Selection && !formData.pcvUnavailable &&
        formData.selectionKind == SelectionKind.SINGLE_FILE &&
        formData.copiedFilePath.isNotBlank() && formData.inputFiles.isEmpty()
    if (canSelectD1) {
        TextButton(
            enabled = enabled && !isBusy && !formData.hasAnyCredentialInput,
            onClick = { viewModel.selectPcv3D1() },
        ) {
            Text(stringResource(R.string.pcv3_open_as_d1))
        }
    }
}

/**
 * Applies only the static Android presentation/configuration gate after the Go
 * content detector selected NORMAL. Native StartPCV3 still owns fresh admission.
 */
internal fun routeNormalPcv3Selection(
    viewModel: MainViewModel,
    selectedFilename: String,
    copiedPath: String,
    policyState: Pcv3AndroidPolicyState,
): List<String> = when (policyState) {
    Pcv3AndroidPolicyState.CONFIGURED ->
        listOfNotNull(viewModel.claimPcv3Normal(selectedFilename, copiedPath))
    Pcv3AndroidPolicyState.UNCONFIGURED -> viewModel.retainRefusedPcv3(
        selectedFilename = selectedFilename,
        ownedCopyPath = copiedPath,
        error = AppError.OperationError.PCVUnavailable(
            userMessage = "",
            technicalMessage = "PCV3_ANDROID_UNCONFIGURED",
            messageResId = R.string.pcv3_unavailable_device_build,
        ),
    )
}

private suspend fun applyLegacySelection(
    context: android.content.Context,
    viewModel: MainViewModel,
    selectedFilename: String,
    copiedPath: String,
    unknownErrorMsg: String,
): Boolean {
    val current = viewModel.formState.value
    val isEncrypt = withContext(Dispatchers.IO) {
        GoBridge.detectOperation(copiedPath)
    }.getOrElse {
        viewModel.setError(pcv3RouteFailure())
        return false
    }
    if (isEncrypt) {
        viewModel.updateFormData(
            current.copy(
                selectedFilename = selectedFilename,
                copiedFilePath = copiedPath,
                comments = "",
                decryptionInfo = null,
            ),
        )
        return viewModel.formState.value.copiedFilePath == copiedPath
    }

    return withContext(Dispatchers.IO) {
        GoBridge.getDecryptionInfo(copiedPath)
    }.fold(onSuccess = { info ->
        viewModel.updateFormData(
            current.copy(
                selectedFilename = selectedFilename,
                copiedFilePath = copiedPath,
                comments = if (info.readable) info.comments else "",
                decryptionInfo = info,
            ),
        )
        viewModel.formState.value.copiedFilePath == copiedPath
    }, onFailure = { error ->
        val appError = error.toAppError(unknownErrorMsg)
        if (appError is AppError.OperationError.PCVUnavailable) {
            viewModel.retainRefusedPcv3(
                selectedFilename,
                copiedPath,
                appError,
            )
            false
        } else {
            // The common detector already selected legacy; retain its copy for the
            // existing legacy diagnostic/recovery path without guessing from an error.
            viewModel.setError(appError)
            viewModel.updateFormData(
                current.copy(
                    selectedFilename = selectedFilename,
                    copiedFilePath = copiedPath,
                    comments = "",
                    decryptionInfo = null,
                ),
            )
            viewModel.formState.value.copiedFilePath == copiedPath
        }
    })
}

internal suspend fun cleanupReplacedSelection(context: android.content.Context, sources: List<String>): Boolean =
    withContext(NonCancellable) {
        val sourcesDeleted = deleteOwnedCopies(context, sources.distinct())
        val keyfilesDeleted = FileCopyService.cleanupKeyfiles(context)
        val stagingDeleted = StagingService.wipeStaging(context)
        sourcesDeleted && keyfilesDeleted && stagingDeleted
    }

private suspend fun deleteOwnedCopies(context: android.content.Context, paths: List<String>): Boolean =
    withContext(NonCancellable) {
        var deleted = true
        paths.forEach { path ->
            if (!FileCopyService.deleteFile(context, path)) deleted = false
        }
        deleted
    }

private fun selectionCleanupError() = AppError.FileError.DeleteFailed(
    userMessage = "",
    technicalMessage = "Failed to clear previous internal selection",
    messageResId = R.string.error_delete_failed,
)

private fun pcv3RouteFailure() = AppError.OperationError.GenericOperation(
    userMessage = "",
    technicalMessage = "PCV3 route unavailable",
    messageResId = R.string.error_detect_operation_type_failed,
)

private fun Throwable.toAppError(unknownErrorMsg: String): AppError =
    (this as? AppError) ?: AppError.fromException(
        this as? Exception ?: Exception(message ?: unknownErrorMsg),
    )

internal suspend fun applyStagedSelection(
    viewModel: MainViewModel,
    unknownErrorMsg: String,
    prepare: suspend () -> Result<StagedSelection>,
) {
    val result = try {
        prepare()
    } catch (cancelled: CancellationException) {
        StagingService.cleanupFailure(cancelled)?.let(viewModel::setError)
        throw cancelled
    }
    result.onSuccess { sel ->
        viewModel.resetFormToDefaults()
        val base = viewModel.formState.value
        viewModel.updateFormData(
            base.copy(
                selectedFilename = sel.displayName,
                copiedFilePath = "",
                inputFiles = sel.inputFiles,
                onlyFolders = sel.onlyFolders,
                onlyFiles = sel.onlyFiles,
                selectionKind = sel.kind,
                suggestedOutputName = sel.suggestedOutputName,
                comments = "",
                decryptionInfo = null,
            )
        )
    }.onFailure { error ->
        viewModel.setError(
            (error as? AppError) ?: AppError.fromException(
                error as? Exception ?: Exception(error.message ?: unknownErrorMsg)
            )
        )
    }
}

@Composable
fun FileCard(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    pcv3AndroidPolicyState: Pcv3AndroidPolicyState = Pcv3AndroidPolicyState.UNCONFIGURED,
) {
    Card(modifier = modifier) {
        Column(
            modifier = Modifier.padding(8.dp)
        ) {
            ChooseFile(
                viewModel = viewModel,
                enabled = enabled,
                pcv3AndroidPolicyState = pcv3AndroidPolicyState,
            )
        }
    }
}
