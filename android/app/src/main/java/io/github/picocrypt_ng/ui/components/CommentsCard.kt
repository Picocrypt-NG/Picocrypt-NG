package io.github.picocrypt_ng.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.R
import androidx.compose.runtime.collectAsState

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
        label = { Text(stringResource(R.string.comments)) },
        modifier = Modifier.fillMaxWidth(),
        enabled = enabled,
    )
}

@Composable
fun CommentsCard(viewModel: MainViewModel) {
    val formData by viewModel.formState.collectAsState()
    if (!(formData.isEncrypt || formData.isDecrypt)) {
        return
    }
    Card {
        Column(
            modifier = Modifier.padding(8.dp)
        ) {
            Comments(viewModel)
        }
    }
}

