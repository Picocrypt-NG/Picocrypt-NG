package io.github.picocrypt_ng.ui.components

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.OperationViewModel
import io.github.picocrypt_ng.OperationType
import io.github.picocrypt_ng.AppError
import io.github.picocrypt_ng.FileCopyService
import io.github.picocrypt_ng.R
import androidx.compose.runtime.collectAsState
import kotlinx.coroutines.launch
import java.io.File

@Composable
fun ProgressCard(
    mainViewModel: MainViewModel,
    operationViewModel: OperationViewModel
) {
    val context = LocalContext.current
    val operationState by operationViewModel.operationState.collectAsState()
    var saveError by remember { mutableStateOf<AppError?>(null) }
    val scope = rememberCoroutineScope()
    
    // File save launcher
    val saveFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("*/*")
    ) { uri: Uri? ->
        uri?.let { destinationUri ->
            val op = operationState
            if (op != null && op.done && op.error == null) {
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
                            AppError.fromException(error as? Exception ?: Exception(error.message ?: "Unknown error"))
                        }
                    }
                }
            }
        }
    }
    
    // Determine which dialog to show
    val showProgress = operationState != null && !operationState!!.done
    val showError = operationState != null && operationState!!.done && operationState!!.error != null
    val showSuccess = operationState != null && operationState!!.done && operationState!!.error == null
    
    // Check if error is data corruption (for force decrypt option)
    val isCorruptionError = operationState?.error?.isDataCorruption() == true
    
    // Check if error is password/auth error (for retry option)
    val isPasswordError = operationState?.error?.isPasswordError() == true
    
    // Progress dialog (operation running)
    if (showProgress) {
        val op = operationState!!
        AlertDialog(
            onDismissRequest = { /* Non-dismissible */ },
            title = {
                Text(
                    text = if (op.type == OperationType.ENCRYPT) {
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
                        progress = { op.progress },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(
                        text = op.status,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    if (op.info.isNotEmpty()) {
                        Text(
                            text = op.info,
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
    
    // Force decrypt dialog (for data corruption errors)
    if (showError && isCorruptionError) {
        val op = operationState!!
        AlertDialog(
            onDismissRequest = { /* Non-dismissible - must use Close button */ },
            title = {
                Text(stringResource(R.string.data_corruption_detected))
            },
            text = {
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = op.error?.userMessage ?: stringResource(R.string.data_corruption_detected),
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
                        operationViewModel.retryDecryptWithForce()
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
    
    // Password/auth error dialog (for retry option)
    if (showError && !isCorruptionError && isPasswordError) {
        val op = operationState!!
        AlertDialog(
            onDismissRequest = { /* Non-dismissible - must use buttons */ },
            title = {
                Text(stringResource(R.string.authentication_error))
            },
            text = {
                Text(op.error?.userMessage ?: stringResource(R.string.authentication_failed))
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
    
    // Standard error dialog (for non-corruption, non-password errors)
    if (showError && !isCorruptionError && !isPasswordError) {
        val op = operationState!!
        AlertDialog(
            onDismissRequest = { /* Non-dismissible - must use Close button */ },
            title = {
                Text(stringResource(R.string.error))
            },
            text = {
                Text(op.error?.userMessage ?: stringResource(R.string.unknown_error_occurred))
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
    
    // Success dialog (operation completed)
    if (showSuccess) {
        val op = operationState!!
        // Derive filename from original selected filename, not internal storage name
        val outputFileName = op.formData?.selectedFilename?.let { selectedFilename ->
            if (op.type == OperationType.ENCRYPT) {
                // For encryption: add .pcv if not present
                if (selectedFilename.endsWith(".pcv")) {
                    selectedFilename
                } else {
                    "$selectedFilename.pcv"
                }
            } else {
                // For decryption: remove .pcv if present
                if (selectedFilename.endsWith(".pcv")) {
                    selectedFilename.removeSuffix(".pcv")
                } else {
                    selectedFilename
                }
            }
        } ?: File(op.outputFile).name // Fallback to internal storage name if formData is null
        
        AlertDialog(
            onDismissRequest = { 
                // Don't cleanup on dismiss - user might want to save later
                // Only cleanup when Cancel button is explicitly clicked
            },
            title = {
                Text(
                    text = if (op.type == OperationType.ENCRYPT) {
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
                            text = stringResource(R.string.error_saving_file, error.userMessage),
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
                        saveFileLauncher.launch(outputFileName)
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
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}


