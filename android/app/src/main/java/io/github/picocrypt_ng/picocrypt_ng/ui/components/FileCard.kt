package io.github.picocrypt_ng.picocrypt_ng.ui.components


import android.net.Uri
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.FileCopyService
import io.github.picocrypt_ng.picocrypt_ng.FormData
import io.github.picocrypt_ng.picocrypt_ng.GoBridge
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import androidx.compose.runtime.collectAsState
import io.github.picocrypt_ng.picocrypt_ng.StagedSelection
import io.github.picocrypt_ng.picocrypt_ng.StagingService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext


@Composable
fun ChooseFile(viewModel: MainViewModel) {
    val context = LocalContext.current
    val unknownErrorMsg = stringResource(R.string.error_unknown)
    val formData by viewModel.formState.collectAsState()
    var isCopying by remember { mutableStateOf(false) }
    var selectedUri by remember { mutableStateOf<Uri?>(null) }
    var selectedFileName by remember { mutableStateOf("") }
    
    // Handle file copying and detection when URI is selected
    LaunchedEffect(selectedUri) {
        val uri = selectedUri ?: return@LaunchedEffect
        isCopying = true
        
        val copyResult = withContext(Dispatchers.IO) {
            FileCopyService.copyFileToInternalStorage(context, uri, selectedFileName)
        }
        
        copyResult.onSuccess { copiedPath ->
            // Reset all form fields to defaults whenever a file is selected
            viewModel.resetFormToDefaults()
            
            // Get current form data (after reset)
            val currentFormData = viewModel.formState.value
            
            // Detect operation type
            val detectResult = GoBridge.detectOperation(copiedPath)
            detectResult.onSuccess { isEncrypt ->
                if (isEncrypt) {
                    // For encryption, update the form data with new file info
                    // All fields are reset to defaults for new files
                    viewModel.updateFormData(
                        currentFormData.copy(
                            selectedFilename = selectedFileName,
                            copiedFilePath = copiedPath,
                            comments = "", // Always start with empty comments for new file
                            decryptionInfo = null
                        )
                    )
                } else {
                    // For decryption, fetch decryption metadata
                    val decryptionInfoResult = withContext(Dispatchers.IO) {
                        GoBridge.getDecryptionInfo(copiedPath)
                    }
                    
                    decryptionInfoResult.onSuccess { info ->
                        // Update form data with decryption info
                        // Comments come from decryption info if readable
                        viewModel.updateFormData(
                            currentFormData.copy(
                                selectedFilename = selectedFileName,
                                copiedFilePath = copiedPath,
                                comments = if (info.readable) info.comments else "",
                                decryptionInfo = info
                            )
                        )
                    }.onFailure { error ->
                        val appError = if (error is AppError) {
                            error
                        } else {
                            AppError.fromException(error as? Exception ?: Exception(error.message ?: unknownErrorMsg))
                        }
                        if (appError is AppError.OperationError.PCVUnavailable) {
                            rejectPCVAndDeleteOwnedCopy(
                                viewModel = viewModel,
                                selectedFilename = selectedFileName,
                                ownedCopyPath = copiedPath,
                                error = appError,
                            ) { path -> FileCopyService.deleteFile(context, path) }
                        } else {
                            // On an ordinary metadata error, retain the copied input so
                            // existing legacy recovery behavior remains available.
                            viewModel.setError(appError)
                            viewModel.updateFormData(
                                currentFormData.copy(
                                    selectedFilename = selectedFileName,
                                    copiedFilePath = copiedPath,
                                    comments = "",
                                    decryptionInfo = null
                                )
                            )
                        }
                    }
                }
            }.onFailure { error ->
                val appError = if (error is AppError) {
                    error
                } else {
                    AppError.fromException(error as? Exception ?: Exception(error.message ?: unknownErrorMsg))
                }
                if (appError is AppError.OperationError.PCVUnavailable) {
                    rejectPCVAndDeleteOwnedCopy(
                        viewModel = viewModel,
                        selectedFilename = selectedFileName,
                        ownedCopyPath = copiedPath,
                        error = appError,
                    ) { path -> FileCopyService.deleteFile(context, path) }
                } else {
                    // An ordinary detection failure retains the existing diagnostic state.
                    viewModel.setError(appError)
                    viewModel.updateFormData(
                        currentFormData.copy(
                            selectedFilename = selectedFileName,
                            copiedFilePath = copiedPath,
                            decryptionInfo = null
                        )
                    )
                }
            }
        }.onFailure { error ->
            // File copy failed - show error to user
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
            if (FormData.isSplitVolumeChunkName(fileName)) {
                // Split-volume chunk (secret.pcv.0): Android cannot recombine sibling
                // chunks. Surface the reason loudly and skip copy/detect -- otherwise it
                // would be treated as an encrypt target and double-encrypted.
                viewModel.setError(AppError.ValidationError.SplitVolumeNotSupported)
            } else {
                selectedUri = it // Trigger LaunchedEffect (copy + detect)
            }
        }
    }

    val scope = rememberCoroutineScope()

    val folderPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        uri ?: return@rememberLauncherForActivityResult
        isCopying = true
        scope.launch {
            val result = StagingService.copyTreeToStaging(context, uri)
            applyStagedSelection(viewModel, result, unknownErrorMsg)
            isCopying = false
        }
    }

    val filesPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments()
    ) { uris: List<Uri> ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        isCopying = true
        scope.launch {
            val result = StagingService.copyFilesToStaging(context, uris, System.currentTimeMillis() / 1000)
            applyStagedSelection(viewModel, result, unknownErrorMsg)
            isCopying = false
        }
    }

    var menuOpen by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp)
            .clickable(enabled = !isCopying) { menuOpen = true },
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        if (isCopying) {
            CircularProgressIndicator(modifier = Modifier.padding(8.dp))
            Text(stringResource(R.string.copying_file))
        } else {
            Text(formData.selectedFilename.ifEmpty { stringResource(R.string.choose_file) })
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
                        onClick = { menuOpen = false; filePickerLauncher.launch("*/*") }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.choose_multiple_files)) },
                        onClick = { menuOpen = false; filesPickerLauncher.launch(arrayOf("*/*")) }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.choose_folder)) },
                        onClick = { menuOpen = false; folderPickerLauncher.launch(null) }
                    )
                }
            }
        }
    }
}

internal suspend fun rejectPCVAndDeleteOwnedCopy(
    viewModel: MainViewModel,
    selectedFilename: String,
    ownedCopyPath: String,
    error: AppError.OperationError.PCVUnavailable,
    deleteOwnedCopy: suspend (String) -> Boolean,
): Boolean {
    val cleanupPath = viewModel.rejectPCV(selectedFilename, ownedCopyPath, error)
    return withContext(NonCancellable) {
        deleteOwnedCopy(cleanupPath)
    }
}

private fun applyStagedSelection(
    viewModel: MainViewModel,
    result: Result<StagedSelection>,
    unknownErrorMsg: String,
) {
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
fun FileCard(viewModel: MainViewModel, modifier: Modifier = Modifier) {
    Card(modifier = modifier) {
        Column(
            modifier = Modifier.padding(8.dp)
        ) {
            ChooseFile(viewModel)
        }
    }
}
