package io.github.picocrypt_ng.picocrypt_ng.ui.components


import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.ui.graphics.Color
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.Pcv3AndroidPolicyState
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.SelectionKind
import androidx.compose.runtime.collectAsState


@Composable
fun ExpandableCard(
    title: String,
    modifier: Modifier = Modifier,
    titleColor: Color? = null,
    content: @Composable () -> Unit
) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    Card(modifier = modifier.fillMaxWidth()) {
        Column {
            Row(modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded }
                .padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = title,
                    modifier = Modifier.weight(1f),
                    color = titleColor ?: MaterialTheme.colorScheme.onSurface
                )
                Icon(
                    imageVector = Icons.Default.ArrowDropDown,
                    contentDescription = stringResource(R.string.expand_or_collapse),
                    modifier = Modifier.rotate(if (expanded) 180f else 0f)
                )
            }
            AnimatedVisibility(
                visible = expanded,
                enter = expandVertically(animationSpec = tween(durationMillis = 300)),
                exit = shrinkVertically(animationSpec = tween(durationMillis = 300))
            ) {
                content()
            }
        }
    }
}


@Composable
fun LabeledCheckbox(label: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.clickable { onChange(!value) },
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(checked = value, onCheckedChange = { onChange(it) })
        Text(label)
    }
}


@Composable
fun AdvancedCard(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier,
    pcv3AndroidPolicyState: Pcv3AndroidPolicyState = Pcv3AndroidPolicyState.UNCONFIGURED,
) {
    val formData by viewModel.formState.collectAsState()
    if (!formData.isEncrypt) {
        return
    }
    // PCV3 creation is a single-file concept; the staged folder/multi tree only feeds
    // the legacy zip path. The toggle also requires a configured PCV3 Android build.
    val canCreatePcv3 = pcv3AndroidPolicyState == Pcv3AndroidPolicyState.CONFIGURED &&
        formData.selectionKind == SelectionKind.SINGLE_FILE
    val count =
        (if (formData.reedSolomon) 1 else 0) + (if (formData.deniability) 1 else 0) +
            (if (formData.paranoid) 1 else 0) + (if (formData.createPcv3) 1 else 0)
    ExpandableCard(title = stringResource(R.string.advanced_settings, count), modifier = modifier) {
        Column(modifier = Modifier.padding(16.dp)) {
            if (canCreatePcv3) {
                LabeledCheckbox(stringResource(R.string.pcv3_create), formData.createPcv3) { checked ->
                    // D1 creation has no suite choice: deniability with PCV3 forces paranoid.
                    viewModel.updateFormData(
                        formData.copy(
                            createPcv3 = checked,
                            paranoid = formData.paranoid || (checked && formData.deniability),
                        )
                    )
                }
            }
            LabeledCheckbox(stringResource(R.string.reed_solomon), formData.reedSolomon) {
                viewModel.updateFormData(formData.copy(reedSolomon = it))
            }
            LabeledCheckbox(stringResource(R.string.paranoid), formData.paranoid) {
                viewModel.updateFormData(formData.copy(paranoid = it))
            }
            LabeledCheckbox(stringResource(R.string.deniability), formData.deniability) {
                viewModel.updateFormData(
                    formData.copy(
                        deniability = it,
                        paranoid = formData.paranoid || (it && formData.createPcv3),
                    )
                )
            }
            // The PCV3 creation envelope has no compression input; the toggle stays
            // legacy-only so it can never silently not apply.
            if (!formData.createPcv3) {
                LabeledCheckbox(stringResource(R.string.compress), formData.compress) {
                    viewModel.updateFormData(formData.copy(compress = it))
                }
            }
        }
    }
}