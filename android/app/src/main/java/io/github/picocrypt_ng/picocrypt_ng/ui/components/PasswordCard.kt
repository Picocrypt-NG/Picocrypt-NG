package io.github.picocrypt_ng.picocrypt_ng.ui.components


import android.os.Build
import android.view.View
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.picocrypt_ng.FormData
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import androidx.compose.runtime.collectAsState
import io.github.picocrypt_ng.picocrypt_ng.R
import kotlinx.coroutines.flow.distinctUntilChanged


/**
 * Composable that enables autofill but prevents password save prompts.
 * 
 * Strategy (Option 7): Set autofill hints directly on EditText views to enable autofill,
 * then immediately set importantForAutofill to NO. The hints enable autofill functionality,
 * but setting importantForAutofill to NO prevents password managers from prompting to save.
 * 
 * This approach works because:
 * - Autofill hints enable the autofill service to provide suggestions
 * - Setting importantForAutofill to NO prevents the save prompt
 * - Both are set immediately, so autofill works but save prompts are blocked
 */
@Composable
fun PreventAutofillSaveEffect() {
    val view = LocalView.current
    
    DisposableEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Find all EditText views and configure them for autofill without save prompts
            view.post {
                findEditTextViews(view).forEach { editText ->
                    // Set autofill hints to enable autofill functionality
                    editText.setAutofillHints(android.view.View.AUTOFILL_HINT_PASSWORD)
                    // Set importantForAutofill to NO to prevent save prompts
                    // The hints enable autofill, but NO prevents saving
                    editText.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                }
            }
            
            onDispose { }
        } else {
            onDispose { }
        }
    }
}

/**
 * Recursively finds all EditText views in the view hierarchy.
 */
private fun findEditTextViews(root: View): List<android.widget.EditText> {
    val result = mutableListOf<android.widget.EditText>()
    
    fun traverse(view: View) {
        if (view is android.widget.EditText) {
            result.add(view)
        }
        if (view is android.view.ViewGroup) {
            for (i in 0 until view.childCount) {
                traverse(view.getChildAt(i))
            }
        }
    }
    
    traverse(root)
    return result
}

/**
 * Copies a [CharSequence] (e.g. [TextFieldState.text]) into a [CharArray] without
 * the interned-String round-trip the old value-based field forced. The stdlib
 * [CharArray]-producing helpers are defined on [String] only, not [CharSequence].
 */
private fun CharSequence.toCharArray(): CharArray = CharArray(length) { this[it] }

@Composable
fun PasswordIcon(visible: Boolean, onClick: () -> Unit) {
    val image = if (visible) Icons.Filled.Visibility else Icons.Filled.VisibilityOff
    val description = if (visible) stringResource(R.string.hide_password) else stringResource(R.string.show_password)
    IconButton(onClick = onClick) {
        Icon(imageVector = image, contentDescription = description)
    }
}


@Composable
fun Password(
    state: TextFieldState,
    visible: Boolean,
    icon: @Composable (() -> Unit)?,
    isError: Boolean,
    errorMessage: String,
) {
    SecureTextField(
        state = state,
        label = { Text(stringResource(R.string.password)) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        isError = isError,
        textObfuscationMode = if (visible) TextObfuscationMode.Visible else TextObfuscationMode.Hidden,
        trailingIcon = icon,
        modifier = Modifier.fillMaxWidth(),
        supportingText = { if (isError) Text(errorMessage) })
}


@Composable
fun ConfirmPassword(
    state: TextFieldState,
    visible: Boolean,
    icon: @Composable (() -> Unit)?,
    isError: Boolean,
) {
    SecureTextField(
        state = state,
        label = { Text(stringResource(R.string.confirm_password)) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        isError = isError,
        textObfuscationMode = if (visible) TextObfuscationMode.Visible else TextObfuscationMode.Hidden,
        trailingIcon = icon,
        modifier = Modifier.fillMaxWidth(),
        supportingText = { if (isError) Text(stringResource(R.string.passwords_must_match)) })
}


@Composable
fun PasswordCard(
    viewModel: MainViewModel,
    modifier: Modifier = Modifier
) {
    val formData by viewModel.formState.collectAsState()
    if (!(formData.isEncrypt || formData.isDecrypt)) {
        return
    }
    var visible by rememberSaveable { mutableStateOf(false) }

    // Prevent autofill save prompts for password fields
    PreventAutofillSaveEffect()

    Card(modifier = modifier) {
        Column(
            modifier = Modifier.padding(8.dp)
        ) {
            // State-based secure input (Google's recommended pattern). Use plain
            // remember { TextFieldState() } rather than rememberTextFieldState():
            // the latter is rememberSaveable-backed and would write the secret to
            // the Bundle on process death, defeating the migration's intent.
            val passwordState = remember { TextFieldState() }
            val confirmPasswordState = remember { TextFieldState() }

            // Reset the secure buffers when the selected file changes.
            DisposableEffect(formData.copiedFilePath) {
                onDispose {
                    passwordState.clearText()
                    confirmPasswordState.clearText()
                }
            }

            // Forward edits to the ViewModel as CharArray, without an interned String
            // intermediate. snapshotFlow replaces the old debounce + String sync.
            // distinctUntilChanged (by content) guards against re-emits that don't
            // change the text: snapshotFlow emits on subscribe, and forwarding an
            // empty CharArray would zero the ViewModel's existing password via fill
            // on every recomposition of this card.
            LaunchedEffect(passwordState) {
                snapshotFlow { passwordState.text }
                    .distinctUntilChanged { a, b -> a.contentEquals(b) }
                    .collect { viewModel.updatePasswords(password = it.toCharArray()) }
            }
            LaunchedEffect(confirmPasswordState) {
                snapshotFlow { confirmPasswordState.text }
                    .distinctUntilChanged { a, b -> a.contentEquals(b) }
                    .collect { viewModel.updatePasswords(confirmPassword = it.toCharArray()) }
            }

            val passwordErrorMessage = if (formData.isDeniabilityPasswordMissing) {
                stringResource(R.string.deniability_password_required)
            } else {
                stringResource(R.string.enter_password)
            }
            val showPasswordError =
                formData.isPasswordInputRequired && !formData.isKeyfileEncryptionUnsupported
            Password(
                state = passwordState,
                visible = visible,
                icon = { PasswordIcon(visible) { visible = !visible } },
                isError = showPasswordError,
                errorMessage = passwordErrorMessage,
            )
            if (formData.isEncrypt) {
                ConfirmPassword(
                    state = confirmPasswordState,
                    visible = visible,
                    isError = !formData.isPasswordsMatch,
                    icon = { PasswordIcon(visible) { visible = !visible } })
            }
        }
    }
}
