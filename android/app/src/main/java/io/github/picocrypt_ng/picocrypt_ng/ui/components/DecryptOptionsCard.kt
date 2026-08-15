package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.Pcv3ActionIntent
import io.github.picocrypt_ng.picocrypt_ng.Pcv3FactorPolicyIntent
import io.github.picocrypt_ng.picocrypt_ng.Pcv3KeyfileOrderIntent
import io.github.picocrypt_ng.picocrypt_ng.Pcv3OperationIntent
import io.github.picocrypt_ng.picocrypt_ng.Pcv3Presentation
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.pcv3ConsentRoleResource
import kotlinx.coroutines.flow.distinctUntilChanged

/**
 * Decrypt-only options card. Mirrors AdvancedCard (encrypt) but for decrypt-time
 * options. Currently exposes verify-first (integrity-verify-before-write); reuses the
 * ExpandableCard / LabeledCheckbox helpers defined in AdvancedCard.kt.
 */
@Composable
fun DecryptOptionsCard(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier,
    pcv3Presentation: Pcv3Presentation? = null,
    onSelectPcv3ConsentRole: ((
        operationId: String,
        generation: Long,
        role: String,
    ) -> Unit)? = null,
    onConfirmPcv3Consent: ((operationId: String, generation: Long) -> Unit)? = null,
    onRefusePcv3Consent: ((operationId: String, generation: Long) -> Unit)? = null,
) {
    val formData by viewModel.formState.collectAsState()
    val pcv3Intent = formData.pcv3Intent
    when {
        formData.isDecrypt -> {
            val count = if (formData.verifyFirst) 1 else 0
            ExpandableCard(
                title = stringResource(R.string.decrypt_options, count),
                modifier = modifier,
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    LabeledCheckbox(stringResource(R.string.verify_first), formData.verifyFirst) {
                        viewModel.updateFormData(formData.copy(verifyFirst = it))
                    }
                }
            }
        }
        !formData.pcvUnavailable && pcv3Intent != null -> Pcv3IntentOptionsCard(
            viewModel = viewModel,
            intent = pcv3Intent,
            onAction = viewModel::setPcv3Action,
            onFactorPolicy = viewModel::setPcv3FactorPolicy,
            onKeyfileOrder = viewModel::setPcv3KeyfileOrder,
            modifier = modifier,
        )
    }

    Pcv3ConsentDialog(
        presentation = pcv3Presentation,
        onSelectRole = onSelectPcv3ConsentRole,
        onConfirm = onConfirmPcv3Consent,
        onRefuse = onRefusePcv3Consent,
        modifier = modifier,
    )
}

@Composable
private fun Pcv3IntentOptionsCard(
    viewModel: MainViewModel,
    intent: Pcv3OperationIntent,
    onAction: (Pcv3ActionIntent) -> Unit,
    onFactorPolicy: (Pcv3FactorPolicyIntent) -> Unit,
    onKeyfileOrder: (Pcv3KeyfileOrderIntent) -> Unit,
    modifier: Modifier,
) {
    val formData by viewModel.formState.collectAsState()
    ExpandableCard(
        title = stringResource(R.string.pcv3_decrypt_options),
        modifier = modifier,
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.pcv3_operation_heading),
                style = MaterialTheme.typography.titleMedium,
            )
            Pcv3Choice(
                label = stringResource(R.string.pcv3_action_decrypt),
                selected = intent.action == Pcv3ActionIntent.DECRYPT,
                onClick = { onAction(Pcv3ActionIntent.DECRYPT) },
            )
            Pcv3Choice(
                label = stringResource(R.string.pcv3_action_recovery),
                selected = intent.action == Pcv3ActionIntent.RECOVERY,
                onClick = { onAction(Pcv3ActionIntent.RECOVERY) },
            )
            Pcv3Choice(
                label = stringResource(R.string.pcv3_action_force_recovery),
                selected = intent.action == Pcv3ActionIntent.FORCE_WITH_UNVERIFIED_CONSENT,
                onClick = { onAction(Pcv3ActionIntent.FORCE_WITH_UNVERIFIED_CONSENT) },
            )

            Text(
                text = stringResource(R.string.pcv3_credential_policy_heading),
                style = MaterialTheme.typography.titleMedium,
            )
            if (intent.factorPolicy == null) {
                Text(stringResource(R.string.pcv3_credential_policy_unset_hint))
            }
            Pcv3Choice(
                label = stringResource(R.string.pcv3_factor_password_only),
                selected = intent.factorPolicy == Pcv3FactorPolicyIntent.PASSWORD_ONLY,
                onClick = { onFactorPolicy(Pcv3FactorPolicyIntent.PASSWORD_ONLY) },
            )
            Pcv3Choice(
                label = stringResource(R.string.pcv3_factor_keyfiles_only),
                selected = intent.factorPolicy == Pcv3FactorPolicyIntent.KEYFILES_ONLY,
                onClick = { onFactorPolicy(Pcv3FactorPolicyIntent.KEYFILES_ONLY) },
            )
            Pcv3Choice(
                label = stringResource(R.string.pcv3_factor_combined),
                selected = intent.factorPolicy == Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES,
                onClick = { onFactorPolicy(Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES) },
            )

            if (intent.factorPolicy == Pcv3FactorPolicyIntent.PASSWORD_ONLY ||
                intent.factorPolicy == Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES ||
                formData.hasPassword
            ) {
                Pcv3PasswordInput(
                    viewModel = viewModel,
                    passwordAllowed = intent.factorPolicy !=
                        Pcv3FactorPolicyIntent.KEYFILES_ONLY,
                )
            }

            if (intent.factorPolicy == Pcv3FactorPolicyIntent.KEYFILES_ONLY ||
                intent.factorPolicy == Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES ||
                formData.hasKeyfiles
            ) {
                AddKeyfile(viewModel)
                if (formData.hasKeyfiles) {
                    ClearKeyfiles(viewModel)
                    KeyfileNames(viewModel)
                }
            }

            if (intent.factorPolicy == Pcv3FactorPolicyIntent.KEYFILES_ONLY ||
                intent.factorPolicy == Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES
            ) {
                Text(
                    text = stringResource(R.string.pcv3_keyfile_order_heading),
                    style = MaterialTheme.typography.titleMedium,
                )
                Pcv3Choice(
                    label = stringResource(R.string.pcv3_keyfile_order_selected),
                    selected = intent.keyfileOrder == Pcv3KeyfileOrderIntent.SELECTED,
                    onClick = { onKeyfileOrder(Pcv3KeyfileOrderIntent.SELECTED) },
                )
                Pcv3Choice(
                    label = stringResource(R.string.pcv3_keyfile_order_any),
                    selected = intent.keyfileOrder == Pcv3KeyfileOrderIntent.ANY,
                    onClick = { onKeyfileOrder(Pcv3KeyfileOrderIntent.ANY) },
                )
            }
        }
    }
}

@Composable
private fun Pcv3PasswordInput(viewModel: MainViewModel, passwordAllowed: Boolean) {
    val formData by viewModel.formState.collectAsState()
    val passwordState = remember(formData.pcv3OwnedSource) { TextFieldState() }
    var visible by remember(formData.pcv3OwnedSource) { mutableStateOf(false) }

    PreventAutofillSaveEffect()
    DisposableEffect(passwordState) {
        onDispose { passwordState.clearText() }
    }
    LaunchedEffect(passwordState) {
        snapshotFlow { passwordState.text }
            .distinctUntilChanged { first, second -> first.contentEquals(second) }
            .collect { text ->
                val password = CharArray(text.length) { text[it] }
                try {
                    viewModel.updatePasswords(password = password)
                } finally {
                    password.fill('\u0000')
                }
            }
    }
    Password(
        state = passwordState,
        visible = visible,
        icon = { PasswordIcon(visible) { visible = !visible } },
        isError = !passwordAllowed || (passwordAllowed && !formData.hasPassword),
        errorMessage = stringResource(
            if (passwordAllowed) {
                R.string.enter_password
            } else {
                R.string.pcv3_password_not_allowed
            },
        ),
    )
}

@Composable
private fun Pcv3Choice(label: String, selected: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .selectable(selected = selected, role = Role.RadioButton, onClick = onClick),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null)
        Text(label)
    }
}

internal const val PCV3_CONSENT_TAG = "pcv3-consent"

/** Displays only the exact, currently live Go consent tuple; no role or acknowledgement is saved. */
@Composable
internal fun Pcv3ConsentDialog(
    presentation: Pcv3Presentation?,
    onSelectRole: ((operationId: String, generation: Long, role: String) -> Unit)?,
    onConfirm: ((operationId: String, generation: Long) -> Unit)?,
    onRefuse: ((operationId: String, generation: Long) -> Unit)?,
    modifier: Modifier = Modifier,
) {
    val live = presentation as? Pcv3Presentation.Live ?: return
    val consent = live.consent ?: return
    if (live.consentHandle == null || onSelectRole == null || onConfirm == null || onRefuse == null) {
        return
    }
    val roleResources = consent.allowedRoles.map { role ->
        role to (pcv3ConsentRoleResource(role) ?: return)
    }
    var acknowledged by remember(
        live.operationId,
        live.generation,
        consent.mode,
        consent.allowedRoles,
    ) { mutableStateOf(false) }
    val cancelFocus = remember(live.operationId, live.generation) { FocusRequester() }
    LaunchedEffect(cancelFocus) { cancelFocus.requestFocus() }

    AlertDialog(
        modifier = modifier.testTag(PCV3_CONSENT_TAG),
        onDismissRequest = { onRefuse(live.operationId, live.generation) },
        title = { Text(stringResource(R.string.pcv3_consent_title)) },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = 400.dp)
                    .verticalScroll(rememberScrollState()),
            ) {
                Text(stringResource(R.string.pcv3_consent_body))
                roleResources.forEach { (role, resourceId) ->
                    Pcv3Choice(
                        label = stringResource(resourceId),
                        selected = consent.selectedRole == role,
                        onClick = {
                            onSelectRole(live.operationId, live.generation, role)
                        },
                    )
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .toggleable(
                            value = acknowledged,
                            role = Role.Checkbox,
                            onValueChange = { acknowledged = it },
                        ),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(
                        checked = acknowledged,
                        onCheckedChange = null,
                    )
                    Text(stringResource(R.string.pcv3_consent_acknowledgement))
                }
            }
        },
        confirmButton = {
            Button(
                enabled = consent.selectedRole != null && acknowledged,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError,
                ),
                onClick = { onConfirm(live.operationId, live.generation) },
            ) {
                Text(stringResource(R.string.pcv3_consent_confirm))
            }
        },
        dismissButton = {
            TextButton(
                modifier = Modifier.focusRequester(cancelFocus),
                onClick = { onRefuse(live.operationId, live.generation) },
            ) {
                Text(stringResource(R.string.pcv3_consent_cancel))
            }
        },
    )
}
