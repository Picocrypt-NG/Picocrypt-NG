package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationType
import io.github.picocrypt_ng.picocrypt_ng.OperationStatus
import io.github.picocrypt_ng.picocrypt_ng.OperationUiState
import io.github.picocrypt_ng.picocrypt_ng.toUiState
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.FileCopyService
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.localizedMessage
import io.github.picocrypt_ng.picocrypt_ng.renderOperationStatus
import androidx.compose.runtime.collectAsState
import kotlinx.coroutines.launch
import java.io.File

@Composable
fun ProgressCard(
    mainViewModel: MainViewModel,
    operationViewModel: OperationViewModel,
    modifier: Modifier = Modifier
) {
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
