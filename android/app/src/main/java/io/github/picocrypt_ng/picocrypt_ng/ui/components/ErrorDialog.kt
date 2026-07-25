package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.localizedMessage

/**
 * Reusable error dialog component for displaying non-operation errors.
 * Shows user-friendly error messages from AppError.
 */
@Composable
fun ErrorDialog(
    error: AppError?,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    val resources = LocalResources.current
    error?.let {
        AlertDialog(
            modifier = modifier,
            onDismissRequest = onDismiss,
            title = { Text(stringResource(R.string.error)) },
            text = { Text(it.localizedMessage(resources)) },
            confirmButton = {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}
