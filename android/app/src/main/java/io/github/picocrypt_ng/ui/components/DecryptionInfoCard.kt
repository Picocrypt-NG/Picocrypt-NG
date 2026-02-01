package io.github.picocrypt_ng.ui.components


import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.DecryptionInfo
import io.github.picocrypt_ng.FormData
import io.github.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.R
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue


@Composable
fun DecryptionInfoCard(viewModel: MainViewModel) {
    val formData by viewModel.formState.collectAsState()
    // Only show for decrypt operations with decryption info
    val info = formData.decryptionInfo
    if (!formData.isDecrypt || info == null) {
        return
    }
    
    ExpandableCard(title = stringResource(R.string.encryption_settings)) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Keyfiles section
            Text(
                text = stringResource(R.string.keyfiles_section),
                style = androidx.compose.material3.MaterialTheme.typography.titleSmall
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.required, if (info.keyfilesRequired) stringResource(R.string.yes) else stringResource(R.string.no))
            )
            if (info.keyfilesRequired) {
                Text(
                    text = stringResource(R.string.order_matters, if (info.keyfileOrdered) stringResource(R.string.yes) else stringResource(R.string.no))
                )
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(16.dp))
            
            // Advanced settings section
            Text(
                text = stringResource(R.string.advanced_settings_section),
                style = androidx.compose.material3.MaterialTheme.typography.titleSmall
            )
            Spacer(modifier = Modifier.height(8.dp))
            val reedSolomonStatus = if (!info.readable) stringResource(R.string.unknown) else if (info.reedSolomon) stringResource(R.string.enabled) else stringResource(R.string.disabled)
            Text(
                text = stringResource(R.string.reed_solomon_status, reedSolomonStatus)
            )
            val deniabilityStatus = if (info.deniability) stringResource(R.string.enabled) else stringResource(R.string.disabled)
            Text(
                text = stringResource(R.string.deniability_status, deniabilityStatus)
            )
            val paranoidStatus = if (!info.readable) stringResource(R.string.unknown) else if (info.paranoid) stringResource(R.string.enabled) else stringResource(R.string.disabled)
            Text(
                text = stringResource(R.string.paranoid_mode_status, paranoidStatus)
            )
            
            // Show readable status warning if not readable
            if (!info.readable) {
                Spacer(modifier = Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = stringResource(R.string.deniability_note),
                    style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
                    color = androidx.compose.material3.MaterialTheme.colorScheme.error
                )
            }
            
            // Comments section (if readable)
            if (info.readable && info.comments.isNotEmpty()) {
                Spacer(modifier = Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = stringResource(R.string.comments_section),
                    style = androidx.compose.material3.MaterialTheme.typography.titleSmall
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = info.comments
                )
            } else if (info.readable && info.comments.isEmpty()) {
                Spacer(modifier = Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = stringResource(R.string.comments_section),
                    style = androidx.compose.material3.MaterialTheme.typography.titleSmall
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.no_comments)
                )
            }
        }
    }
}

