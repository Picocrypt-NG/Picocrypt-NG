package io.github.picocrypt_ng.ui.components

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.AppError
import io.github.picocrypt_ng.R

/**
 * Reusable error dialog component for displaying non-operation errors.
 * Shows user-friendly error messages from AppError.
 */
@Composable
fun ErrorDialog(
    error: AppError?,
    onDismiss: () -> Unit
) {
    error?.let {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(R.string.error)) },
            text = { Text(it.userMessage) },
            confirmButton = {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}

