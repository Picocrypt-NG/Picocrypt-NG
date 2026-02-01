package io.github.picocrypt_ng.ui.components


import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.AppError
import io.github.picocrypt_ng.FileCopyService
import io.github.picocrypt_ng.FormData
import io.github.picocrypt_ng.GoBridge
import io.github.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.R
import androidx.compose.runtime.collectAsState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext


@Composable
fun ChooseFile(viewModel: MainViewModel) {
    val context = LocalContext.current
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
                        // On error, still update filename but without decryption info
                        // Set error to show user that decryption info couldn't be read
                        val appError = if (error is AppError) {
                            error
                        } else {
                            AppError.fromException(error as? Exception ?: Exception(error.message ?: "Unknown error"))
                        }
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
            }.onFailure { error ->
                // On error detecting operation, still update filename but show error
                val appError = if (error is AppError) {
                    error
                } else {
                    AppError.fromException(error as? Exception ?: Exception(error.message ?: "Unknown error"))
                }
                viewModel.setError(appError)
                viewModel.updateFormData(
                    currentFormData.copy(
                        selectedFilename = selectedFileName,
                        copiedFilePath = copiedPath,
                        decryptionInfo = null
                    )
                )
            }
        }.onFailure { error ->
            // File copy failed - show error to user
            val appError = if (error is AppError) {
                error
            } else {
                AppError.fromException(error as? Exception ?: Exception(error.message ?: "Unknown error"))
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
    
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp)
            .clickable(enabled = !isCopying) { filePickerLauncher.launch("*/*") },
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        if (isCopying) {
            CircularProgressIndicator(modifier = Modifier.padding(8.dp))
            Text(stringResource(R.string.copying_file))
        } else {
            Text(formData.selectedFilename.ifEmpty { stringResource(R.string.choose_file) })
            Icon(
                imageVector = Icons.Filled.Folder,
                contentDescription = stringResource(R.string.choose_file_description)
            )
        }
    }
}

@Composable
fun FileCard(viewModel: MainViewModel) {
    Card {
        Column(
            modifier = Modifier.padding(8.dp)
        ) {
            ChooseFile(viewModel)
        }
    }
}