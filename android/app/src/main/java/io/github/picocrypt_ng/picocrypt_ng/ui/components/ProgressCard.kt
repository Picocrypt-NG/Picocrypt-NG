package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationType
import io.github.picocrypt_ng.picocrypt_ng.OperationStatus
import io.github.picocrypt_ng.picocrypt_ng.OperationUiState
import io.github.picocrypt_ng.picocrypt_ng.Pcv3OperationIntent
import io.github.picocrypt_ng.picocrypt_ng.Pcv3ArtifactDetailsUiState
import io.github.picocrypt_ng.picocrypt_ng.Pcv3Presentation
import io.github.picocrypt_ng.picocrypt_ng.Pcv3ResultAction
import io.github.picocrypt_ng.picocrypt_ng.Pcv3ResultTone
import io.github.picocrypt_ng.picocrypt_ng.toUiState
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.FileCopyService
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.localizedMessage
import io.github.picocrypt_ng.picocrypt_ng.pcv3ProgressDisplay
import io.github.picocrypt_ng.picocrypt_ng.pcv3ArtifactMetadataDisplay
import io.github.picocrypt_ng.picocrypt_ng.pcv3ArtifactPageNavigation
import io.github.picocrypt_ng.picocrypt_ng.pcv3ArtifactStatusResource
import io.github.picocrypt_ng.picocrypt_ng.pcv3ResultActions
import io.github.picocrypt_ng.picocrypt_ng.pcv3ResultDisplay
import io.github.picocrypt_ng.picocrypt_ng.renderOperationStatus
import androidx.compose.runtime.collectAsState
import kotlinx.coroutines.launch
import java.io.File

@Composable
fun ProgressCard(
    mainViewModel: MainViewModel,
    operationViewModel: OperationViewModel,
    modifier: Modifier = Modifier,
    pcv3Presentation: Pcv3Presentation? = null,
    pcv3Intent: Pcv3OperationIntent? = null,
    onCancelPcv3: ((operationId: String, generation: Long) -> Unit)? = null,
    onClosePcv3Result: ((operationId: String, generation: Long) -> Unit)? = null,
    onClosePcv3Archive: ((operationId: String, generation: Long) -> Unit)? = null,
    onBeginPcv3Archive: ((operationId: String, generation: Long) -> Boolean)? = null,
    onCompletePcv3Archive: ((android.content.Context, Uri?) -> Unit)? = null,
    pcv3ArtifactDetails: Pcv3ArtifactDetailsUiState = Pcv3ArtifactDetailsUiState.Closed,
    onBeginPcv3Save: ((operationId: String, generation: Long) -> String?)? = null,
    onCompletePcv3Save: ((android.content.Context, Uri?) -> Unit)? = null,
    onDiscardPcv3Output: ((operationId: String, generation: Long) -> Unit)? = null,
    onInspectPcv3Artifact: ((operationId: String, generation: Long) -> Unit)? = null,
    onLoadPcv3ArtifactPage: ((operationId: String, generation: Long, offsetDecimal: String) -> Unit)? = null,
    onClosePcv3ArtifactInspection: ((operationId: String, generation: Long) -> Unit)? = null,
) {
    if (pcv3Presentation != null) {
        Pcv3PresentationDialog(
            presentation = pcv3Presentation,
            intent = pcv3Intent,
            onCancel = onCancelPcv3,
            onCloseResult = onClosePcv3Result,
            onCloseArchive = onClosePcv3Archive,
            onBeginArchive = onBeginPcv3Archive,
            onCompleteArchive = onCompletePcv3Archive,
            artifactDetails = pcv3ArtifactDetails,
            onBeginSave = onBeginPcv3Save,
            onCompleteSave = onCompletePcv3Save,
            onDiscardOutput = onDiscardPcv3Output,
            onInspectArtifact = onInspectPcv3Artifact,
            onLoadArtifactPage = onLoadPcv3ArtifactPage,
            onCloseArtifactInspection = onClosePcv3ArtifactInspection,
            modifier = modifier,
        )
        return
    }

    val context = LocalContext.current
    val unknownErrorMsg = stringResource(R.string.error_unknown)
    val operationState by operationViewModel.operationState.collectAsState()
    var saveError by remember { mutableStateOf<AppError?>(null) }
    val scope = rememberCoroutineScope()

    // File save launcher
    val saveFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("*/*")
    ) { uri: Uri? ->
        uri?.let { destinationUri ->
            val op = operationState
            if (
                op != null && op.done && op.error == null &&
                op.status.code != OperationStatus.CANCELLED
            ) {
                scope.launch {
                    val result = FileCopyService.saveFileToUri(context, op.outputFile, destinationUri)
                    result.onSuccess {
                        // Successfully saved, cleanup files and clear operation
                        saveError = null
                        operationViewModel.clearOperation(context, shouldCleanupFiles = true)
                    }.onFailure { error ->
                        saveError = if (error is AppError) {
                            error
                        } else {
                            AppError.fromException(error as? Exception ?: Exception(error.message ?: unknownErrorMsg))
                        }
                    }
                }
            }
        }
    }

    // Project the polled OperationState into the exhaustive UI state and branch over it.
    when (val ui = operationState.toUiState()) {
        is OperationUiState.Idle -> {
            // Nothing to render.
        }

        is OperationUiState.Running -> {
            val displayText = renderOperationStatus(context, ui.status, ui.detail, ui.progress)
            AlertDialog(
                modifier = modifier,
                onDismissRequest = { /* Non-dismissible */ },
                title = {
                    Text(
                        text = if (ui.type == OperationType.ENCRYPT) {
                            stringResource(R.string.encrypting)
                        } else {
                            stringResource(R.string.decrypting)
                        }
                    )
                },
                text = {
                    Column(
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        LinearProgressIndicator(
                            progress = { ui.progress },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Text(
                            text = displayText.status,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        displayText.detail?.let { detail ->
                            Text(
                                text = detail,
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            operationViewModel.cancelOperation()
                        }
                    ) {
                        Text(stringResource(R.string.cancel))
                    }
                }
            )
        }

        is OperationUiState.Failed -> {
            val error = ui.error
            when {
                // Force decrypt dialog (data corruption only).
                error.allowsForceDecrypt() -> {
                    AlertDialog(
                        modifier = modifier,
                        onDismissRequest = { /* Non-dismissible - must use Close button */ },
                        title = {
                            Text(stringResource(R.string.data_corruption_detected))
                        },
                        text = {
                            Column(
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Text(
                                    text = error.localizedMessage(context),
                                    style = MaterialTheme.typography.bodyMedium
                                )
                                Text(
                                    text = stringResource(R.string.force_decrypt_warning),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        },
                        confirmButton = {
                            Button(
                                onClick = {
                                    operationViewModel.retryDecryptWithForce(context)
                                }
                            ) {
                                Text(stringResource(R.string.force_decrypt))
                            }
                        },
                        dismissButton = {
                            TextButton(
                                onClick = {
                                    // Cleanup files and clear operation
                                    operationViewModel.clearOperation(context, shouldCleanupFiles = true)
                                    // Explicitly clear form data since Cancel means "give up"
                                    mainViewModel.clearSensitiveData(clearFiles = true)
                                }
                            ) {
                                Text(stringResource(R.string.cancel))
                            }
                        }
                    )
                }

                // Password/auth error dialog (retry option).
                error.allowsPasswordRetry() -> {
                    AlertDialog(
                        modifier = modifier,
                        onDismissRequest = { /* Non-dismissible - must use buttons */ },
                        title = {
                            Text(stringResource(R.string.authentication_error))
                        },
                        text = {
                            Text(error.localizedMessage(context))
                        },
                        confirmButton = {
                            Button(
                                onClick = {
                                    // Clear operation state but keep files and settings for retry
                                    operationViewModel.clearOperation(context, shouldCleanupFiles = false)
                                    // Note: Password fields remain - user can re-enter or overwrite
                                }
                            ) {
                                Text(stringResource(R.string.retry))
                            }
                        },
                        dismissButton = {
                            TextButton(
                                onClick = {
                                    // Full cleanup on cancel - delete files and clear form data
                                    operationViewModel.clearOperation(context, shouldCleanupFiles = true)
                                    // Explicitly clear form data since Cancel means "give up"
                                    mainViewModel.clearSensitiveData(clearFiles = true)
                                }
                            ) {
                                Text(stringResource(R.string.cancel))
                            }
                        }
                    )
                }

                // Standard error dialog (non-corruption, non-password errors).
                else -> {
                    AlertDialog(
                        modifier = modifier,
                        onDismissRequest = { /* Non-dismissible - must use Close button */ },
                        title = {
                            Text(stringResource(R.string.error))
                        },
                        text = {
                            Text(error.localizedMessage(context))
                        },
                        confirmButton = {
                            TextButton(
                                onClick = {
                                    // Full cleanup on error
                                    operationViewModel.clearOperation(context, shouldCleanupFiles = true)
                                    // Explicitly clear form data since Close means "give up"
                                    mainViewModel.clearSensitiveData(clearFiles = true)
                                }
                            ) {
                                Text(stringResource(R.string.close))
                            }
                        }
                    )
                }
            }
        }

        is OperationUiState.Cancelled -> {
            AlertDialog(
                modifier = modifier,
                onDismissRequest = { /* Non-dismissible */ },
                title = {
                    Text(stringResource(R.string.operation_cancelled))
                },
                text = {
                    Text(stringResource(R.string.operation_cancelled_message))
                },
                confirmButton = {
                    TextButton(
                        onClick = {
                            operationViewModel.clearOperation(context, shouldCleanupFiles = true)
                            mainViewModel.clearSensitiveData(clearFiles = true)
                        }
                    ) {
                        Text(stringResource(R.string.close))
                    }
                }
            )
        }

        is OperationUiState.Success -> {
            // Derive filename from original selected filename, not internal storage name.
            // Data (outputFile/formData) comes from the polled OperationState; the sealed
            // Success state only drives control flow + carries the type.
            val op = operationState
            val outputFileName = op?.formData
                ?.suggestedOutputNameFor(ui.type)
                ?.takeIf { it.isNotEmpty() }
                ?: op?.let { File(it.outputFile).name } // Fallback to internal storage name if formData is null

            AlertDialog(
                modifier = modifier,
                onDismissRequest = {
                    // Don't cleanup on dismiss - user might want to save later
                    // Only cleanup when the discard action is explicitly clicked
                },
                title = {
                    Text(
                        text = if (ui.type == OperationType.ENCRYPT) {
                            stringResource(R.string.encryption_complete)
                        } else {
                            stringResource(R.string.decryption_complete)
                        }
                    )
                },
                text = {
                    Column(
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(stringResource(R.string.operation_completed_successfully))
                        saveError?.let { error ->
                            Text(
                                text = stringResource(
                                    R.string.error_saving_file,
                                    error.localizedMessage(context)
                                ),
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            saveError = null
                            outputFileName?.let { saveFileLauncher.launch(it) }
                        }
                    ) {
                        Text(stringResource(R.string.save))
                    }
                },
                dismissButton = {
                    TextButton(
                        onClick = {
                            // Cleanup files and clear operation
                            operationViewModel.clearOperation(context, shouldCleanupFiles = true)
                            // Explicitly clear form data (LaunchedEffect should handle this, but be explicit)
                            mainViewModel.clearSensitiveData(clearFiles = true)
                        }
                    ) {
                        Text(stringResource(R.string.discard_output))
                    }
                }
            )
        }
    }
}

internal const val PCV3_PROGRESS_TAG = "pcv3-progress"
internal const val PCV3_RESULT_TAG = "pcv3-result"

/**
 * Renders exactly one complete Go projection. Live consent is rendered by
 * [Pcv3ConsentDialog], so progress never competes with the modal consent decision.
 */
@Composable
internal fun Pcv3PresentationDialog(
    presentation: Pcv3Presentation,
    intent: Pcv3OperationIntent?,
    onCancel: ((operationId: String, generation: Long) -> Unit)?,
    onCloseResult: ((operationId: String, generation: Long) -> Unit)?,
    onCloseArchive: ((operationId: String, generation: Long) -> Unit)?,
    artifactDetails: Pcv3ArtifactDetailsUiState,
    onBeginSave: ((operationId: String, generation: Long) -> String?)?,
    onCompleteSave: ((android.content.Context, Uri?) -> Unit)?,
    onDiscardOutput: ((operationId: String, generation: Long) -> Unit)?,
    onInspectArtifact: ((operationId: String, generation: Long) -> Unit)?,
    onLoadArtifactPage: ((operationId: String, generation: Long, offsetDecimal: String) -> Unit)?,
    onCloseArtifactInspection: ((operationId: String, generation: Long) -> Unit)?,
    onBeginArchive: ((operationId: String, generation: Long) -> Boolean)? = null,
    onCompleteArchive: ((android.content.Context, Uri?) -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    if (presentation is Pcv3Presentation.Live && presentation.consent != null) {
        return
    }
    val live = presentation as? Pcv3Presentation.Live
    if (presentation.snapshot.completionClass == "unknown" && !presentation.snapshot.archivePending) {
        val action = intent?.action
        if (action == null) {
            Pcv3ProgressDialog(
                snapshot = presentation.snapshot,
                cancelLabelResId = null,
                onCancel = null,
                modifier = modifier,
            )
            return
        }
        Pcv3ProgressDialog(
            snapshot = presentation.snapshot,
            cancelLabelResId = if (action.isRecovery) {
                R.string.pcv3_cancel_recovery
            } else {
                R.string.pcv3_cancel_decryption
            },
            onCancel = if (live != null && onCancel != null) {
                { onCancel(live.operationId, live.generation) }
            } else null,
            modifier = modifier,
        )
        return
    }

    Pcv3ResultDialog(
        presentation = presentation,
        artifactDetails = artifactDetails,
        onBeginSave = onBeginSave,
        onCompleteSave = onCompleteSave,
        onDiscardOutput = onDiscardOutput,
        onInspectArtifact = onInspectArtifact,
        onLoadArtifactPage = onLoadArtifactPage,
        onCloseArtifactInspection = onCloseArtifactInspection,
        onCloseResult = onCloseResult,
        onCloseArchive = onCloseArchive,
        onBeginArchive = onBeginArchive,
        onCompleteArchive = onCompleteArchive,
        modifier = modifier,
    )
}

@Composable
private fun Pcv3ProgressDialog(
    snapshot: io.github.picocrypt_ng.picocrypt_ng.Pcv3SnapshotView,
    cancelLabelResId: Int?,
    onCancel: (() -> Unit)?,
    modifier: Modifier,
) {
    val progress = pcv3ProgressDisplay(snapshot)
    AlertDialog(
        modifier = modifier.testTag(PCV3_PROGRESS_TAG),
        onDismissRequest = { /* Only a live core cancellation action can dismiss progress. */ },
        title = { Text(stringResource(progress.statusResId)) },
        text = {
            if (progress.fraction == null) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            } else {
                LinearProgressIndicator(
                    progress = { progress.fraction },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            if (cancelLabelResId != null && onCancel != null) {
                Button(onClick = onCancel) {
                    Text(stringResource(cancelLabelResId))
                }
            }
        },
    )
}

@Composable
private fun Pcv3ResultDialog(
    presentation: Pcv3Presentation,
    artifactDetails: Pcv3ArtifactDetailsUiState,
    onBeginSave: ((operationId: String, generation: Long) -> String?)?,
    onCompleteSave: ((android.content.Context, Uri?) -> Unit)?,
    onDiscardOutput: ((operationId: String, generation: Long) -> Unit)?,
    onInspectArtifact: ((operationId: String, generation: Long) -> Unit)?,
    onLoadArtifactPage: ((operationId: String, generation: Long, offsetDecimal: String) -> Unit)?,
    onCloseArtifactInspection: ((operationId: String, generation: Long) -> Unit)?,
    onCloseResult: ((operationId: String, generation: Long) -> Unit)?,
    onCloseArchive: ((operationId: String, generation: Long) -> Unit)?,
    onBeginArchive: ((operationId: String, generation: Long) -> Boolean)?,
    onCompleteArchive: ((android.content.Context, Uri?) -> Unit)?,
    modifier: Modifier,
) {
    val display = pcv3ResultDisplay(presentation)
    val actionProjection = pcv3ResultActions(presentation)
    val actions = actionProjection.actions
    val presentationTitle = display.publication?.titleResId ?: display.outcome.titleResId
    var confirmDiscard by remember(presentation.operationId, presentation.generation) {
        mutableStateOf(false)
    }
    val closeResult = if (Pcv3ResultAction.CLOSE_RESULT in actions && onCloseResult != null) {
        { onCloseResult(presentation.operationId, presentation.generation) }
    } else {
        null
    }
    val closeArchive = if (Pcv3ResultAction.CLOSE_ARCHIVE in actions && onCloseArchive != null) {
        { onCloseArchive(presentation.operationId, presentation.generation) }
    } else {
        null
    }
    val close = closeArchive ?: closeResult

    if (Pcv3ResultAction.INSPECT_RECOVERY_ARTIFACT in actions &&
        artifactDetails !is Pcv3ArtifactDetailsUiState.Closed
    ) {
        Pcv3ArtifactDetailsDialog(
            presentation = presentation,
            state = artifactDetails,
            onLoadPage = onLoadArtifactPage,
            onClose = onCloseArtifactInspection,
            modifier = modifier,
        )
        return
    }

    if (confirmDiscard && Pcv3ResultAction.DISCARD_RECOVERY_ARTIFACT in actions &&
        onDiscardOutput != null
    ) {
        Pcv3DiscardConfirmationDialog(
            operationId = presentation.operationId,
            generation = presentation.generation,
            onKeep = { confirmDiscard = false },
            onDiscard = {
                confirmDiscard = false
                onDiscardOutput(presentation.operationId, presentation.generation)
            },
            modifier = modifier,
        )
        return
    }

    AlertDialog(
        modifier = modifier.testTag(PCV3_RESULT_TAG),
        onDismissRequest = { close?.invoke() },
        icon = if (display.tone == Pcv3ResultTone.NEUTRAL) {
            null
        } else {
            {
                Icon(
                    imageVector = Icons.Filled.Warning,
                    contentDescription = null,
                    tint = if (display.tone == Pcv3ResultTone.ERROR) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        },
        title = { Text(stringResource(presentationTitle)) },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = 400.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (presentationTitle != display.outcome.titleResId) {
                    Text(
                        text = stringResource(display.outcome.titleResId),
                        style = MaterialTheme.typography.titleMedium,
                    )
                }
                Text(
                    text = stringResource(display.outcome.bodyResId),
                    style = MaterialTheme.typography.bodyMedium,
                )
                display.supportingOutcome?.let { supportingOutcome ->
                    Text(
                        text = stringResource(supportingOutcome.titleResId),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(
                        text = stringResource(supportingOutcome.bodyResId),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                display.publication?.let { publication ->
                    if (publication.titleResId != presentationTitle &&
                        publication.titleResId != display.outcome.titleResId
                    ) {
                        Text(
                            text = stringResource(publication.titleResId),
                            style = MaterialTheme.typography.titleMedium,
                        )
                    }
                    Text(
                        text = stringResource(publication.bodyResId),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                display.warnings.forEach { warning ->
                    Text(
                        text = stringResource(warning.titleResId),
                        style = MaterialTheme.typography.titleMedium,
                        color = if (display.tone == Pcv3ResultTone.ERROR) {
                            MaterialTheme.colorScheme.error
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                    )
                    Text(
                        text = stringResource(warning.bodyResId),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        },
        confirmButton = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (Pcv3ResultAction.EXPORT_ARCHIVE in actions &&
                    onBeginArchive != null && onCompleteArchive != null
                ) {
                    Pcv3ArchiveButton(
                        presentation = presentation,
                        onBeginArchive = onBeginArchive,
                        onCompleteArchive = onCompleteArchive,
                    )
                }
                if (Pcv3ResultAction.SAVE_DECRYPTED_OUTPUT in actions &&
                    onBeginSave != null && onCompleteSave != null
                ) {
                    Pcv3SaveButton(
                        presentation = presentation,
                        labelResId = R.string.pcv3_save_decrypted_output,
                        onBeginSave = onBeginSave,
                        onCompleteSave = onCompleteSave,
                    )
                }
                if (Pcv3ResultAction.SAVE_RECOVERY_ARTIFACT in actions &&
                    onBeginSave != null && onCompleteSave != null
                ) {
                    Pcv3SaveButton(
                        presentation = presentation,
                        labelResId = R.string.pcv3_save_recovery_artifact,
                        onBeginSave = onBeginSave,
                        onCompleteSave = onCompleteSave,
                    )
                }
                if (Pcv3ResultAction.INSPECT_RECOVERY_ARTIFACT in actions &&
                    onInspectArtifact != null
                ) {
                    TextButton(
                        onClick = {
                            onInspectArtifact(presentation.operationId, presentation.generation)
                        },
                    ) {
                        Text(stringResource(R.string.pcv3_inspect_recovery_artifact))
                    }
                }
                if (Pcv3ResultAction.DISCARD_RECOVERY_ARTIFACT in actions &&
                    onDiscardOutput != null
                ) {
                    TextButton(onClick = { confirmDiscard = true }) {
                        Text(stringResource(R.string.pcv3_discard_recovery_artifact))
                    }
                }
                if (close != null && actionProjection.closeActionResId != null) {
                    TextButton(onClick = close) {
                        Text(stringResource(actionProjection.closeActionResId))
                    }
                }
            }
        },
    )
}

@Composable
private fun Pcv3ArchiveButton(
    presentation: Pcv3Presentation,
    onBeginArchive: (operationId: String, generation: Long) -> Boolean,
    onCompleteArchive: (android.content.Context, Uri?) -> Unit,
) {
    val applicationContext = LocalContext.current.applicationContext
    val archiveLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree(),
    ) { root: Uri? ->
        onCompleteArchive(applicationContext, root)
    }
    Button(
        onClick = {
            if (onBeginArchive(presentation.operationId, presentation.generation)) {
                archiveLauncher.launch(null)
            }
        },
    ) {
        Text(stringResource(R.string.choose_folder))
    }
}

@Composable
private fun Pcv3SaveButton(
    presentation: Pcv3Presentation,
    labelResId: Int,
    onBeginSave: (operationId: String, generation: Long) -> String?,
    onCompleteSave: (android.content.Context, Uri?) -> Unit,
) {
    val applicationContext = LocalContext.current.applicationContext
    val saveLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri: Uri? ->
        onCompleteSave(applicationContext, uri)
    }
    Button(
        onClick = {
            onBeginSave(presentation.operationId, presentation.generation)
                ?.let(saveLauncher::launch)
        },
    ) {
        Text(stringResource(labelResId))
    }
}

@Composable
private fun Pcv3DiscardConfirmationDialog(
    operationId: String,
    generation: Long,
    onKeep: () -> Unit,
    onDiscard: () -> Unit,
    modifier: Modifier,
) {
    val keepFocus = remember(operationId, generation) { FocusRequester() }
    var consumed by remember(operationId, generation) { mutableStateOf(false) }
    LaunchedEffect(keepFocus) { keepFocus.requestFocus() }

    AlertDialog(
        modifier = modifier,
        onDismissRequest = onKeep,
        title = { Text(stringResource(R.string.pcv3_discard_artifact_title)) },
        text = { Text(stringResource(R.string.pcv3_discard_artifact_body)) },
        confirmButton = {
            Button(
                enabled = !consumed,
                onClick = {
                    if (!consumed) {
                        consumed = true
                        onDiscard()
                    }
                },
            ) {
                Text(stringResource(R.string.pcv3_discard_recovery_artifact))
            }
        },
        dismissButton = {
            TextButton(
                onClick = onKeep,
                modifier = Modifier.focusRequester(keepFocus),
            ) {
                Text(stringResource(R.string.pcv3_keep_recovery_artifact))
            }
        },
    )
}

@Composable
private fun Pcv3ArtifactDetailsDialog(
    presentation: Pcv3Presentation,
    state: Pcv3ArtifactDetailsUiState,
    onLoadPage: ((operationId: String, generation: Long, offsetDecimal: String) -> Unit)?,
    onClose: ((operationId: String, generation: Long) -> Unit)?,
    modifier: Modifier,
) {
    val close = onClose?.let { closeInspection ->
        { closeInspection(presentation.operationId, presentation.generation) }
    }
    val ready = (state as? Pcv3ArtifactDetailsUiState.Ready)?.takeIf {
        it.metadata == presentation.artifactMetadata
    }
    val metadataDisplay = ready?.let { pcv3ArtifactMetadataDisplay(it.metadata) }
    val navigation = ready?.let { pcv3ArtifactPageNavigation(it.metadata, it.page) }
    val validReady = ready != null && metadataDisplay != null && navigation != null
    val previousOffset = navigation?.previousOffsetDecimal
    val nextOffset = navigation?.nextOffsetDecimal

    AlertDialog(
        modifier = modifier,
        onDismissRequest = { close?.invoke() },
        title = { Text(stringResource(R.string.pcv3_artifact_details_title)) },
        text = {
            when {
                state is Pcv3ArtifactDetailsUiState.Loading -> {
                    Text(stringResource(R.string.pcv3_artifact_loading))
                }
                state is Pcv3ArtifactDetailsUiState.Failed || !validReady -> {
                    Text(stringResource(R.string.pcv3_artifact_load_failed))
                }
                else -> {
                    Pcv3ArtifactReadyDetails(
                        metadata = ready.metadata,
                        page = ready.page,
                        display = metadataDisplay,
                    )
                }
            }
        },
        confirmButton = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (validReady && previousOffset != null && onLoadPage != null) {
                    TextButton(
                        onClick = {
                            onLoadPage(
                                presentation.operationId,
                                presentation.generation,
                                previousOffset,
                            )
                        },
                    ) {
                        Text(stringResource(R.string.pcv3_artifact_previous_page))
                    }
                }
                if (validReady && nextOffset != null && onLoadPage != null) {
                    TextButton(
                        onClick = {
                            onLoadPage(
                                presentation.operationId,
                                presentation.generation,
                                nextOffset,
                            )
                        },
                    ) {
                        Text(stringResource(R.string.pcv3_artifact_next_page))
                    }
                }
                if (close != null) {
                    TextButton(onClick = close) {
                        Text(stringResource(R.string.pcv3_artifact_details_close))
                    }
                }
            }
        },
    )
}

@Composable
private fun Pcv3ArtifactReadyDetails(
    metadata: io.github.picocrypt_ng.picocrypt_ng.Pcv3ArtifactMetadataView,
    page: io.github.picocrypt_ng.picocrypt_ng.Pcv3ArtifactPageView,
    display: io.github.picocrypt_ng.picocrypt_ng.Pcv3ArtifactMetadataDisplay,
) {
    LazyColumn(
        modifier = Modifier.heightIn(max = 400.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Text(
                stringResource(
                    R.string.pcv3_artifact_kind,
                    stringResource(display.kindResId),
                ),
            )
        }
        item {
            Text(
                if (metadata.role == "none") {
                    stringResource(display.roleResId)
                } else {
                    stringResource(
                        R.string.pcv3_artifact_role,
                        stringResource(display.roleResId),
                    )
                },
            )
        }
        item {
            Text(stringResource(R.string.pcv3_artifact_plaintext_length, metadata.plaintextLength))
        }
        item {
            Text(
                stringResource(
                    R.string.pcv3_artifact_final_status,
                    stringResource(display.finalStatusResId),
                ),
            )
        }
        item {
            Text(stringResource(R.string.pcv3_artifact_verified_count, metadata.verifiedCount))
        }
        item {
            Text(stringResource(R.string.pcv3_artifact_unverified_count, metadata.unverifiedCount))
        }
        item {
            Text(stringResource(R.string.pcv3_artifact_missing_count, metadata.missingCount))
        }
        if (page.ranges.isEmpty()) {
            item { Text(stringResource(R.string.pcv3_artifact_no_ranges)) }
        } else {
            items(page.ranges) { range ->
                val statusResId = pcv3ArtifactStatusResource(range.status)
                    ?: R.string.pcv3_artifact_load_failed
                Text(
                    stringResource(
                        R.string.pcv3_artifact_row,
                        range.recordIndex,
                        range.start,
                        range.end,
                        stringResource(statusResId),
                    ),
                )
            }
        }
    }
}
