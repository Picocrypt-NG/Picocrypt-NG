package io.github.picocrypt_ng.picocrypt_ng.ui.components


import android.content.Context
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationViewModel
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.FileCopyService
import io.github.picocrypt_ng.picocrypt_ng.Pcv3ActionIntent
import io.github.picocrypt_ng.picocrypt_ng.Pcv3Presentation
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.StartupCleanup
import io.github.picocrypt_ng.picocrypt_ng.localizedMessage


@Composable
fun WorkButton(
    mainViewModel: MainViewModel,
    operationViewModel: OperationViewModel,
    modifier: Modifier = Modifier,
    pcv3Presentation: Pcv3Presentation? = null,
) {
    val context = LocalContext.current
    val formData by mainViewModel.formState.collectAsState()
    val operationState by operationViewModel.operationState.collectAsState()
    
    if (
        pcv3Presentation != null ||
        formData.pcv3Intent?.action == Pcv3ActionIntent.FORCE_AUTHENTICATED_ONLY ||
        !(formData.isEncrypt || formData.isDecrypt || formData.isPcv3Selection)
    ) {
        return
    }
    
    val text = when {
        formData.isEncrypt -> stringResource(R.string.encrypt_file)
        formData.isDecrypt -> stringResource(R.string.decrypt_file)
        formData.pcv3Intent?.action == Pcv3ActionIntent.RECOVERY -> stringResource(R.string.pcv3_start_recovery)
        formData.pcv3Intent?.action == Pcv3ActionIntent.FORCE_WITH_UNVERIFIED_CONSENT ->
            stringResource(R.string.pcv3_start_force_recovery)
        else -> stringResource(R.string.pcv3_start_decrypt)
    }
    var showErrorDialog by remember { mutableStateOf<AppError?>(null) }
    
    val isOperationActive = operationState != null && !operationState!!.done
    val isButtonEnabled = formData.isFormValid && !isOperationActive && formData.hasSelectedInput
    
    Button(
        onClick = {
            try {
                if (formData.isPcv3Selection) {
                    dispatchPcv3Selection(context, mainViewModel, operationViewModel)
                } else if (formData.isEncrypt) {
                    operationViewModel.startEncrypt(context, formData)
                } else {
                    operationViewModel.startDecrypt(context, formData)
                }
            } catch (e: Exception) {
                showErrorDialog = AppError.fromException(e)
            }
        },
        modifier = modifier.fillMaxWidth(),
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
            text = { Text(error.localizedMessage(context)) },
            confirmButton = {
                TextButton(onClick = { showErrorDialog = null }) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}

/**
 * Exact non-suspending handoff from the content-owned selection to the sole PCV3
 * lifecycle. The opaque transfer cannot fall through to either legacy start path.
 */
internal fun dispatchPcv3Selection(
    context: Context,
    mainViewModel: MainViewModel,
    operationViewModel: OperationViewModel,
) {
    if (!StartupCleanup.allowsPcv3Dispatch()) return
    val applicationContext = context.applicationContext
    val target = FileCopyService.getPcv3RetainedOutputPath(applicationContext)
    mainViewModel.takePcv3Operation(target)?.let { transfer ->
        operationViewModel.startPcv3(applicationContext, transfer)
    }
}
