package io.github.picocrypt_ng.picocrypt_ng.ui.components


import android.content.Context
import android.content.res.Resources
import android.net.Uri
import android.provider.OpenableColumns
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.unit.dp
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.FileCopyService
import io.github.picocrypt_ng.picocrypt_ng.FormData
import io.github.picocrypt_ng.picocrypt_ng.KeyfileInfo
import io.github.picocrypt_ng.picocrypt_ng.LocalizedMessageArg
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import androidx.compose.runtime.collectAsState
import androidx.lifecycle.viewModelScope
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import kotlin.coroutines.cancellation.CancellationException
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.failureReasonResId


private val keyfileMutationMutex = Mutex()

internal suspend fun <T> withKeyfileMutation(block: suspend () -> T): T {
    keyfileMutationMutex.lock()
    return try {
        block()
    } finally {
        keyfileMutationMutex.unlock()
    }
}


internal suspend fun <T> runNewKeyfileCreation(
    operation: suspend () -> Result<T>,
    onSuccess: (T) -> Unit,
    onFailure: (Throwable) -> Unit,
) {
    val result = try {
        operation()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Result.failure(e)
    }

    val failure = result.exceptionOrNull()
    if (failure is CancellationException) {
        throw failure
    }
    result.fold(onSuccess = onSuccess, onFailure = onFailure)
}

internal suspend fun <T> withZeroedKeyfileBuffer(
    bytes: ByteArray,
    operation: suspend (ByteArray) -> T,
): T = try {
    operation(bytes)
} finally {
    bytes.fill(0)
}

internal suspend fun createAndCopyKeyfile(
    context: Context,
    resources: Resources,
    uri: Uri,
    keyfileIndex: Int,
    randomBytes: ByteArray = ByteArray(32),
    copyKeyfile: suspend (Context, Uri, Int) -> Result<String> =
        FileCopyService::copyKeyfileToInternalStorage,
): Result<String> {
    return withZeroedKeyfileBuffer(randomBytes) { keyfileBytes ->
        val writeSuccess = withContext(Dispatchers.IO) {
            SecureRandom().nextBytes(keyfileBytes)
            try {
                context.contentResolver.openOutputStream(uri)?.use { outputStream ->
                    outputStream.write(keyfileBytes)
                    true
                } ?: false
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                false
            }
        }

        if (!writeSuccess) {
            return@withZeroedKeyfileBuffer Result.failure(
                AppError.FileError.SaveFailed(
                    userMessage = resources.getString(R.string.keyfile_write_failed),
                    messageResId = R.string.keyfile_write_failed,
                ),
            )
        }

        copyKeyfile(context, uri, keyfileIndex)
    }
}


@Composable
fun AddKeyfile(viewModel: MainViewModel) {
    val context = LocalContext.current
    val unknownErrorMsg = stringResource(R.string.error_unknown)
    var isCopying by remember { mutableStateOf(false) }
    var selectedUri by remember { mutableStateOf<Uri?>(null) }
    var selectedFileName by remember { mutableStateOf("") }
    
    // Handle file copying when URI is selected
    LaunchedEffect(selectedUri) {
        val uri = selectedUri ?: return@LaunchedEffect
        isCopying = true

        try {
            withKeyfileMutation {
                // Use current list size as index for fixed filename
                val currentFormData = viewModel.formState.value
                val keyfileIndex = currentFormData.keyfileFilenames.size

                val copyResult = FileCopyService.copyKeyfileToInternalStorage(context, uri, keyfileIndex)

                copyResult.onSuccess { copiedPath ->
                    // Add KeyfileInfo with internal path and display name
                    val updatedFormData = viewModel.formState.value
                    val displayName = if (selectedFileName.isNotEmpty()) selectedFileName else "keyfile_$keyfileIndex"
                    val keyfileInfo = KeyfileInfo(internalPath = copiedPath, displayName = displayName)
                    val keyfileInfos = updatedFormData.keyfileFilenames + keyfileInfo
                    viewModel.updateFormData(updatedFormData.copy(keyfileFilenames = keyfileInfos))
                }.onFailure { error ->
                    // Keyfile copy failed - show error to user
                    val appError = if (error is AppError) {
                        error
                    } else {
                        AppError.fromException(error as? Exception ?: Exception(error.message ?: unknownErrorMsg))
                    }
                    viewModel.setError(appError)
                }
            }
        } finally {
            isCopying = false
            selectedUri = null // Reset after processing
        }
    }
    
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            // Get filename from URI
            val contentResolver = context.contentResolver
            val cursor = contentResolver.query(it, null, null, null, null)
            var fileName = ""
            cursor?.use { c ->
                if (c.moveToFirst()) {
                    val nameIndex = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameIndex != -1) {
                        fileName = c.getString(nameIndex)
                    }
                }
            }
            selectedFileName = fileName
            selectedUri = it // Trigger LaunchedEffect
        }
    }
    
    Button(
        onClick = { filePickerLauncher.launch("*/*") },
        modifier = Modifier.fillMaxWidth(),
        enabled = !isCopying
    ) {
        if (isCopying) {
            Text(stringResource(R.string.copying))
        } else {
            Text(stringResource(R.string.add))
        }
    }
}


@Composable
fun NewKeyfile(viewModel: MainViewModel) {
    val context = LocalContext.current
    val resources = LocalResources.current
    NewKeyfile(
        viewModel = viewModel,
        initialCreatedUri = null,
        createKeyfile = { uri, keyfileIndex ->
            createAndCopyKeyfile(context, resources, uri, keyfileIndex)
        },
    )
}

@Composable
internal fun NewKeyfile(
    viewModel: MainViewModel,
    initialCreatedUri: Uri?,
    createKeyfile: suspend (Uri, Int) -> Result<String>,
) {
    val context = LocalContext.current
    val resources = LocalResources.current
    var isCreating by remember { mutableStateOf(false) }
    var createdUri by remember { mutableStateOf(initialCreatedUri) }
    var createdFileName by remember { mutableStateOf("") }
    
    // Generate default filename with timestamp
    val defaultFileName = remember {
        val timestamp = System.currentTimeMillis() / 1000 // Unix timestamp in seconds
        "keyfile-$timestamp.bin"
    }
    
    // Handle file creation and copying after URI is selected
    LaunchedEffect(createdUri) {
        val uri = createdUri ?: return@LaunchedEffect
        isCreating = true
        
        try {
            withKeyfileMutation {
                val currentFormData = viewModel.formState.value
                val keyfileIndex = currentFormData.keyfileFilenames.size
                runNewKeyfileCreation(
                    operation = {
                        createKeyfile(uri, keyfileIndex).map { it to keyfileIndex }
                    },
                    onSuccess = { (copiedPath, keyfileIndex) ->
                        // Step 4: Add to keyfiles list automatically
                        // Get current form data again to avoid stale state
                        val updatedFormData = viewModel.formState.value
                        val displayName = if (createdFileName.isNotEmpty()) {
                            createdFileName
                        } else {
                            "keyfile_$keyfileIndex"
                        }
                        val keyfileInfo = KeyfileInfo(
                            internalPath = copiedPath,
                            displayName = displayName,
                        )
                        val keyfileInfos = updatedFormData.keyfileFilenames + keyfileInfo
                        viewModel.updateFormData(updatedFormData.copy(keyfileFilenames = keyfileInfos))
                    },
                    onFailure = { error ->
                        val appError = if (error is AppError) {
                            error
                        } else {
                            val reasonResId = failureReasonResId(error)
                            val fallbackReason = resources.getString(reasonResId)
                            AppError.FileError.SaveFailed(
                                userMessage = resources.getString(
                                    R.string.keyfile_create_failed,
                                    fallbackReason,
                                ),
                                technicalMessage = error.message ?: error.toString(),
                                messageResId = R.string.keyfile_create_failed,
                                messageArgs = listOf(LocalizedMessageArg(reasonResId)),
                            )
                        }
                        viewModel.setError(appError)
                    }
                )
            }
        } finally {
            isCreating = false
            createdUri = null
        }
    }
    
    // File creation launcher
    val createFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        uri?.let {
            // Get filename from URI if available, otherwise use default
            val contentResolver = context.contentResolver
            val cursor = contentResolver.query(it, null, null, null, null)
            var fileName = defaultFileName
            cursor?.use { c ->
                if (c.moveToFirst()) {
                    val nameIndex = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameIndex != -1) {
                        val uriFileName = c.getString(nameIndex)
                        if (!uriFileName.isNullOrEmpty()) {
                            fileName = uriFileName
                        }
                    }
                }
            }
            createdFileName = fileName
            createdUri = it // Trigger LaunchedEffect
        }
    }
    
    Button(
        onClick = { createFileLauncher.launch(defaultFileName) },
        modifier = Modifier.fillMaxWidth(),
        enabled = !isCreating
    ) {
        if (isCreating) {
            Text(stringResource(R.string.creating))
        } else {
            Text(stringResource(R.string.new_keyfile))
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
    
    Button(
        onClick = { 
            scope.launch {
                withContext(NonCancellable) {
                    withKeyfileMutation {
                        if (cleanupKeyfiles(context)) {
                            val updatedFormData = viewModel.formState.value
                            viewModel.updateFormData(updatedFormData.copy(keyfileFilenames = emptyList()))
                        } else {
                            viewModel.setError(
                                AppError.FileError.DeleteFailed(
                                    userMessage = deleteFailedMessage,
                                    technicalMessage = "Failed to remove all internal keyfiles",
                                    messageResId = R.string.error_delete_failed,
                                )
                            )
                        }
                    }
                }
            }
        },
        modifier = Modifier.fillMaxWidth()
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
        Row {
            Column(
                modifier = Modifier
                    .padding(8.dp)
                    .weight(0.4F)
            ) {
                AddKeyfile(viewModel)
                if (formData.isEncrypt) {
                    NewKeyfile(viewModel)
                }
                if (formData.keyfileFilenames.isNotEmpty()) {
                    ClearKeyfiles(viewModel)
                }
            }
            Column(
                modifier = Modifier
                    .padding(8.dp)
                    .weight(0.6F)
            ) {
                // Show keyfile requirements from decryption info
                if (formData.isDecrypt && decryptionInfo != null) {
                    if (decryptionInfo.keyfilesRequired) {
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
                }
                if (formData.isEncrypt) {
                    RequireOrder(viewModel)
                    HorizontalDivider()
                    Spacer(modifier = Modifier.height(8.dp))
                }
                KeyfileNames(viewModel)
            }
        }
    }
}
