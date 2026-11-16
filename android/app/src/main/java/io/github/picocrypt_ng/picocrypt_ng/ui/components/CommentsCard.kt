package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.legacySecurityWarningResource

@Composable
fun Comments(viewModel: MainViewModel) {
    val formData by viewModel.formState.collectAsState()
    if (!(formData.isEncrypt || formData.isDecrypt)) {
        return
    }
    val decryptionInfo = formData.decryptionInfo
    if (formData.isDecrypt && formData.comments.isEmpty()) {
        // Check if decryption info says comments are not readable
        if (decryptionInfo != null && !decryptionInfo.readable) {
            // Show that comments are not readable
            TextField(
                value = stringResource(R.string.comments_not_readable),
                onValueChange = { },
                label = { Text(stringResource(R.string.comments)) },
                modifier = Modifier.fillMaxWidth(),
                enabled = false,
            )
            return
        }
        return
    }
    var value = formData.comments
    var enabled = formData.isEncrypt
    if (formData.isEncrypt && formData.deniability) {
        value = stringResource(R.string.comments_disabled_deniability)
        enabled = false
    }
    // For decrypt, use comments from decryption info if available
    if (formData.isDecrypt && decryptionInfo != null) {
        if (decryptionInfo.readable) {
            value = decryptionInfo.comments
        } else {
            value = stringResource(R.string.comments_not_readable)
        }
    }
    TextField(
        value = value,
        onValueChange = { viewModel.updateFormData(formData.copy(comments = it)) },
        label = { Text(stringResource(if (formData.isDecrypt && decryptionInfo?.readable != false) R.string.comments_unverified else R.string.comments)) },
        modifier = Modifier.fillMaxWidth(),
        enabled = enabled,
    )
}

@Composable
fun CommentsCard(viewModel: MainViewModel, modifier: Modifier = Modifier) {
    val formData by viewModel.formState.collectAsState()
    if (!(formData.isEncrypt || formData.isDecrypt)) {
        return
    }
    val preview = formData.decryptionInfo
    val hasVisibleComment = formData.isDecrypt && preview?.readable != false &&
        (preview?.comments ?: formData.comments).isNotEmpty()
    Card(modifier = modifier) {
        Column(
            modifier = Modifier.padding(8.dp)
        ) {
            Comments(viewModel)
            if (formData.isEncrypt || hasVisibleComment) {
                Text(
                    text = stringResource(R.string.comments_plaintext_warning),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
            if (formData.isDecrypt) {
                formData.decryptionInfo?.securityWarning?.let(::legacySecurityWarningResource)?.let { resource ->
                    Text(
                        text = stringResource(resource),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
            }
        }
    }
}
