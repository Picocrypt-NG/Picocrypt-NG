package io.github.picocrypt_ng.ui.components


import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.OperationViewModel
import io.github.picocrypt_ng.AppError
import io.github.picocrypt_ng.R


@Composable
fun WorkButton(
    mainViewModel: MainViewModel,
    operationViewModel: OperationViewModel
) {
    val context = LocalContext.current
    val formData by mainViewModel.formState.collectAsState()
    val operationState by operationViewModel.operationState.collectAsState()
    
    if (!(formData.isEncrypt || formData.isDecrypt)) {
        return
    }
    
    val text = if (formData.isEncrypt) stringResource(R.string.encrypt_file) else stringResource(R.string.decrypt_file)
    var showErrorDialog by rememberSaveable { mutableStateOf<AppError?>(null) }
    
    val isOperationActive = operationState != null && !operationState!!.done
    val isButtonEnabled = formData.isFormValid && !isOperationActive && formData.copiedFilePath.isNotEmpty()
    var shouldStartOperation by remember { mutableStateOf(false) }
    
    // Start operation when button is clicked
    LaunchedEffect(shouldStartOperation) {
        if (shouldStartOperation) {
            shouldStartOperation = false
            try {
                if (formData.isEncrypt) {
                    operationViewModel.startEncrypt(context, formData)
                } else {
                    operationViewModel.startDecrypt(context, formData)
                }
            } catch (e: Exception) {
                showErrorDialog = AppError.fromException(e)
            }
        }
    }
    
    Button(
        onClick = {
            shouldStartOperation = true
        },
        modifier = Modifier.fillMaxWidth(),
        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary),
        enabled = isButtonEnabled
    ) {
        Text(if (isOperationActive) stringResource(R.string.processing) else text)
    }
    
    // Error dialog
    showErrorDialog?.let { error ->
        AlertDialog(
            onDismissRequest = { showErrorDialog = null },
            title = { Text(stringResource(R.string.error)) },
            text = { Text(error.userMessage) },
            confirmButton = {
                TextButton(onClick = { showErrorDialog = null }) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}