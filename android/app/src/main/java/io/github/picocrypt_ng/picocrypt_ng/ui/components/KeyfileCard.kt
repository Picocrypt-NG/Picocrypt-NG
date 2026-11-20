package io.github.picocrypt_ng.picocrypt_ng.ui.components


import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.unit.dp
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.FileCopyService
import io.github.picocrypt_ng.picocrypt_ng.KeyfileInfo
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import androidx.compose.runtime.collectAsState
import androidx.lifecycle.viewModelScope
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import io.github.picocrypt_ng.picocrypt_ng.readKeyfileDisplayName
import io.github.picocrypt_ng.picocrypt_ng.R


private val keyfileMutationMutex = Mutex()

internal suspend fun <T> withKeyfileMutation(block: suspend () -> T): T {
    keyfileMutationMutex.lock()
    return try {
        block()
    } finally {
        keyfileMutationMutex.unlock()
    }
}


@Composable
fun AddKeyfile(viewModel: MainViewModel) {
    val context = LocalContext.current
    val importScope = rememberCoroutineScope()
    val unknownErrorMsg = stringResource(R.string.error_unknown)
    val formData by viewModel.formState.collectAsState()
    var pickerSelection by rememberSaveable { mutableStateOf<Long?>(null) }
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        val selection = pickerSelection
        pickerSelection = null
        if (selection != null && uri != null) {
            val mutation = viewModel.beginKeyfileMutation(selection) ?: return@rememberLauncherForActivityResult
            val keyfileIndex = viewModel.formState.value.keyfileFilenames.size
            importScope.launch(start = CoroutineStart.UNDISPATCHED) {
                try {
                    withKeyfileMutation {
                        if (!viewModel.ownsKeyfileMutation(selection, mutation)) return@withKeyfileMutation
                        val name = readKeyfileDisplayName(context, uri) ?: "keyfile_$keyfileIndex"
                        FileCopyService.copyKeyfileToInternalStorage(
                            context, uri, keyfileIndex,
                            adopt = { path ->
                                viewModel.finishKeyfileMutation(selection, mutation, added = KeyfileInfo(path, name))
                            },
                        ).onFailure { error ->
                            val appError = error as? AppError ?: AppError.fromException(
                                error as? Exception ?: Exception(error.message ?: unknownErrorMsg),
                            )
                            viewModel.finishKeyfileMutation(selection, mutation, error = appError)
                        }
                    }
                } finally {
                    viewModel.finishKeyfileMutation(selection, mutation)
                }
            }
        }
    }

    Button(
        onClick = {
            pickerSelection = formData.selectionGeneration
            try {
                filePickerLauncher.launch("*/*")
            } catch (error: Exception) {
                pickerSelection = null
                viewModel.setError(AppError.fromException(error))
            }
        },
        modifier = Modifier.fillMaxWidth(),
        enabled = pickerSelection == null && !formData.keyfileMutationPending && !formData.legacyStartPending,
    ) {
        if (formData.keyfileMutationPending) {
            Text(stringResource(R.string.copying))
        } else {
            Text(stringResource(R.string.add))
        }
    }
}


@Composable
fun ClearKeyfiles(viewModel: MainViewModel) {
    ClearKeyfiles(viewModel, FileCopyService::cleanupKeyfiles)
}

@Composable
internal fun ClearKeyfiles(
    viewModel: MainViewModel,
    cleanupKeyfiles: suspend (Context) -> Boolean,
) {
    val context = LocalContext.current.applicationContext
    val deleteFailedMessage = stringResource(R.string.error_delete_failed)
    val scope = viewModel.viewModelScope
    val formData by viewModel.formState.collectAsState()
    
    Button(
        onClick = {
            val selection = formData.selectionGeneration
            val mutation = viewModel.beginKeyfileMutation(selection) ?: return@Button
            scope.launch(start = CoroutineStart.UNDISPATCHED) {
                withContext(NonCancellable) {
                    try {
                        withKeyfileMutation {
                            if (!viewModel.ownsKeyfileMutation(selection, mutation)) return@withKeyfileMutation
                            val cleared = cleanupKeyfiles(context)
                            val error = if (cleared) null else AppError.FileError.DeleteFailed(
                                    userMessage = deleteFailedMessage,
                                    technicalMessage = "Failed to remove all internal keyfiles",
                                    messageResId = R.string.error_delete_failed,
                            )
                            viewModel.finishKeyfileMutation(selection, mutation, cleared = cleared, error = error)
                        }
                    } finally {
                        viewModel.finishKeyfileMutation(selection, mutation)
                    }
                }
            }
        },
        modifier = Modifier.fillMaxWidth(),
        enabled = !formData.keyfileMutationPending && !formData.legacyStartPending,
    ) {
        Text(stringResource(R.string.clear))
    }
}


@Composable
fun RequireOrder(viewModel: MainViewModel) {
    val formData by viewModel.formState.collectAsState()
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(stringResource(R.string.require_this_order))
        Checkbox(
            formData.keyfileOrdered, onCheckedChange = {
                viewModel.updateFormData(formData.copy(keyfileOrdered = it))
            }
        )
    }
}


@Composable
fun KeyfileNames(viewModel: MainViewModel) {
    val formData by viewModel.formState.collectAsState()
    // Display the user-chosen display names
    val displayNames = formData.keyfileFilenames.map { keyfileInfo ->
        keyfileInfo.displayName
    }
    Text(
        text = displayNames.joinToString(separator = "\n"),
        minLines = 3,
    )
}

@Composable
fun KeyfileCard(viewModel: MainViewModel, modifier: Modifier = Modifier) {
    val resources = LocalResources.current
    val formData by viewModel.formState.collectAsState()
    if (!(formData.isDecrypt || formData.isEncrypt)) {
        return
    }
    
    // For decrypt mode: hide if we know keyfiles are not needed, but show for deniability mode (unknown)
    val decryptionInfo = formData.decryptionInfo
    if (formData.isDecrypt) {
        if (decryptionInfo != null && decryptionInfo.readable && !decryptionInfo.keyfilesRequired) {
            // We know keyfiles are not needed, so hide the card
            return
        }
        // Otherwise show it (deniability mode or keyfiles required)
    }
    
    // Determine if keyfiles are required and missing
    val keyfilesRequired = formData.isDecrypt && decryptionInfo != null && decryptionInfo.readable && decryptionInfo.keyfilesRequired
    val keyfilesMissing = keyfilesRequired && formData.keyfileFilenames.isEmpty()
    
    // Build title with "Required" indicator if needed
    val titleText = if (keyfilesRequired) {
        resources.getQuantityString(
            R.plurals.keyfiles_required_count,
            formData.keyfileFilenames.size,
            formData.keyfileFilenames.size,
        )
    } else {
        resources.getQuantityString(
            R.plurals.keyfiles_count,
            formData.keyfileFilenames.size,
            formData.keyfileFilenames.size,
        )
    }
    
    // Use error color if keyfiles are required but missing
    val titleColor = if (keyfilesMissing) {
        androidx.compose.material3.MaterialTheme.colorScheme.error
    } else {
        null
    }
    
    ExpandableCard(title = titleText, modifier = modifier, titleColor = titleColor) {
        if (formData.isEncrypt) {
            if (formData.isPcv3Creation) {
                // PCV3 creation binds keyfiles (desktop parity); legacy v2 cannot.
                Column(
                    modifier = Modifier
                        .padding(8.dp)
                ) {
                    AddKeyfile(viewModel)
                    if (formData.keyfileFilenames.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        RequireOrder(viewModel)
                        ClearKeyfiles(viewModel)
                        KeyfileNames(viewModel)
                    }
                }
            } else {
                Column(
                    modifier = Modifier
                        .padding(8.dp)
                ) {
                    Text(
                        text = stringResource(R.string.error_keyfile_writes_disabled),
                        style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                        color = androidx.compose.material3.MaterialTheme.colorScheme.primary,
                    )
                    if (formData.keyfileFilenames.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        ClearKeyfiles(viewModel)
                        KeyfileNames(viewModel)
                    }
                }
            }
        } else {
            Row {
                Column(
                    modifier = Modifier
                        .padding(8.dp)
                        .weight(0.4F)
                ) {
                    AddKeyfile(viewModel)
                    if (formData.keyfileFilenames.isNotEmpty()) {
                        ClearKeyfiles(viewModel)
                    }
                }
                Column(
                    modifier = Modifier
                        .padding(8.dp)
                        .weight(0.6F)
                ) {
                    if (decryptionInfo != null && decryptionInfo.keyfilesRequired) {
                        Text(
                            text = stringResource(R.string.keyfiles_required_warning),
                            style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                            color = androidx.compose.material3.MaterialTheme.colorScheme.primary
                        )
                        if (decryptionInfo.keyfileOrdered) {
                            Text(
                                text = stringResource(R.string.keyfile_order_matters),
                                style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
                                color = androidx.compose.material3.MaterialTheme.colorScheme.primary
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        HorizontalDivider()
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                    KeyfileNames(viewModel)
                }
            }
        }
    }
}
