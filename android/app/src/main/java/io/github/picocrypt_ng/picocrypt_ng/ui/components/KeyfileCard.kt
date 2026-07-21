package io.github.picocrypt_ng.picocrypt_ng.ui.components


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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.FileCopyService
import io.github.picocrypt_ng.picocrypt_ng.FormData
import io.github.picocrypt_ng.picocrypt_ng.KeyfileInfo
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.localizedFailureReason
import io.github.picocrypt_ng.picocrypt_ng.localizedMessage


@Composable
fun AddKeyfile(viewModel: MainViewModel) {
    val context = LocalContext.current
    val unknownErrorMsg = stringResource(R.string.error_unknown)
    val formData by viewModel.formState.collectAsState()
    var isCopying by remember { mutableStateOf(false) }
    var selectedUri by remember { mutableStateOf<Uri?>(null) }
    var selectedFileName by remember { mutableStateOf("") }
    
    // Handle file copying when URI is selected
    LaunchedEffect(selectedUri) {
        val uri = selectedUri ?: return@LaunchedEffect
        isCopying = true
        
        // Use current list size as index for fixed filename
        val currentFormData = viewModel.formState.value
        val keyfileIndex = currentFormData.keyfileFilenames.size
        
        val copyResult = withContext(Dispatchers.IO) {
            FileCopyService.copyKeyfileToInternalStorage(context, uri, keyfileIndex)
        }
        
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
        
        isCopying = false
        selectedUri = null // Reset after processing
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
    val formData by viewModel.formState.collectAsState()
    var isCreating by remember { mutableStateOf(false) }
    var createdUri by remember { mutableStateOf<Uri?>(null) }
    var createdFileName by remember { mutableStateOf("") }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var showErrorDialog by rememberSaveable { mutableStateOf(false) }
    val keyfileWriteFailedMsg = stringResource(R.string.keyfile_write_failed)
    val unknownErrorMsg = stringResource(R.string.error_unknown)
    
    // Generate default filename with timestamp
    val defaultFileName = remember {
        val timestamp = System.currentTimeMillis() / 1000 // Unix timestamp in seconds
        "keyfile-$timestamp.bin"
    }
    
    // Handle file creation and copying after URI is selected
    LaunchedEffect(createdUri) {
        val uri = createdUri ?: return@LaunchedEffect
        isCreating = true
        errorMessage = null
        
        try {
            // Step 1: Generate 32 random bytes
            val randomBytes = withContext(Dispatchers.IO) {
                val bytes = ByteArray(32)
                SecureRandom().nextBytes(bytes)
                bytes
            }
            
            // Step 2: Write bytes to user's selected URI
            val writeSuccess = withContext(Dispatchers.IO) {
                try {
                    context.contentResolver.openOutputStream(uri)?.use { outputStream ->
                        outputStream.write(randomBytes)
                        true
                    } ?: false
                } catch (e: Exception) {
                    false
                } finally {
                    randomBytes.fill(0) // zero key material after write
                }
            }

            if (!writeSuccess) {
                errorMessage = keyfileWriteFailedMsg
                showErrorDialog = true
                isCreating = false
                createdUri = null
                return@LaunchedEffect
            }
            
            // Step 3: Copy from URI to internal storage (for app operations)
            // Use current list size as index for fixed filename
            val currentFormData = viewModel.formState.value
            val keyfileIndex = currentFormData.keyfileFilenames.size
            
            val copyResult = withContext(Dispatchers.IO) {
                FileCopyService.copyKeyfileToInternalStorage(context, uri, keyfileIndex)
            }
            
            copyResult.onSuccess { copiedPath ->
                // Step 4: Add to keyfiles list automatically
                // Get current form data again to avoid stale state
                val updatedFormData = viewModel.formState.value
                val displayName = if (createdFileName.isNotEmpty()) createdFileName else "keyfile_$keyfileIndex"
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
                errorMessage = appError.localizedMessage(context)
                showErrorDialog = true
            }
        } catch (e: Exception) {
            val reason = localizedFailureReason(context, e)
            val appError = AppError.FileError.SaveFailed(
                userMessage = context.getString(R.string.keyfile_create_failed, reason),
                technicalMessage = e.message ?: e.toString(),
                messageResId = R.string.keyfile_create_failed,
                messageArgs = listOf(reason),
            )
            viewModel.setError(appError)
            errorMessage = appError.localizedMessage(context)
            showErrorDialog = true
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
    
    // Error dialog
    if (showErrorDialog) {
        AlertDialog(
            onDismissRequest = { 
                showErrorDialog = false
                errorMessage = null
            },
            title = { Text(text = stringResource(R.string.error_creating_keyfile)) },
            text = { Text(text = errorMessage ?: stringResource(R.string.unknown_error_occurred)) },
            confirmButton = {
                TextButton(onClick = { 
                    showErrorDialog = false
                    errorMessage = null
                }) {
                    Text(stringResource(R.string.ok))
                }
            },
        )
    }
}


@Composable
fun ClearKeyfiles(viewModel: MainViewModel) {
    val context = LocalContext.current
    val formData by viewModel.formState.collectAsState()
    val scope = rememberCoroutineScope()
    
    Button(
        onClick = { 
            // Clear the list
            viewModel.updateFormData(formData.copy(keyfileFilenames = listOf()))
            // Also cleanup keyfile files from internal storage
            scope.launch {
                FileCopyService.cleanupKeyfiles(context)
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
    val context = LocalContext.current
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
        context.resources.getQuantityString(
            R.plurals.keyfiles_required_count,
            formData.keyfileFilenames.size,
            formData.keyfileFilenames.size,
        )
    } else {
        context.resources.getQuantityString(
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
