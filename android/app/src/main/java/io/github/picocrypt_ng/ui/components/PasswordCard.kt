package io.github.picocrypt_ng.ui.components


import android.os.Build
import android.view.View
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import kotlinx.coroutines.Job
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import io.github.picocrypt_ng.FormData
import io.github.picocrypt_ng.MainViewModel
import androidx.compose.runtime.collectAsState
import io.github.picocrypt_ng.R


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
    value: String,
    onChange: (String) -> Unit,
    visible: Boolean,
    icon: @Composable (() -> Unit)?,
    isError: Boolean
) {
    TextField(
        value = value,
        onValueChange = { onChange(it) },
        label = { Text(stringResource(R.string.password)) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        isError = isError,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = icon,
        modifier = Modifier.fillMaxWidth(),
        supportingText = { if (isError) Text(stringResource(R.string.enter_password)) })
}


@Composable
fun ConfirmPassword(
    value: String,
    onChange: (String) -> Unit,
    visible: Boolean,
    icon: @Composable (() -> Unit)?,
    isError: Boolean,
) {
    TextField(
        value = value,
        onValueChange = { onChange(it) },
        label = { Text(stringResource(R.string.confirm_password)) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        isError = isError,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = icon,
        modifier = Modifier.fillMaxWidth(),
        supportingText = { if (isError) Text(stringResource(R.string.passwords_must_match)) })
}


@Composable
fun PasswordCard(
    viewModel: MainViewModel
) {
    val formData by viewModel.formState.collectAsState()
    if (!(formData.isEncrypt || formData.isDecrypt)) {
        return
    }
    var visible by rememberSaveable { mutableStateOf(false) }
    
    // Prevent autofill save prompts for password fields
    PreventAutofillSaveEffect()
    
    Card {
        Column(
            modifier = Modifier.padding(8.dp)
        ) {
            // Use copiedFilePath as key so passwords reset when file changes
            // Store as String for UI, convert to CharArray when updating ViewModel
            var passwordValue by rememberSaveable(key = formData.copiedFilePath) { mutableStateOf("") }
            var confirmPasswordValue by rememberSaveable(key = formData.copiedFilePath) { mutableStateOf("") }
            var debounceJob by remember { mutableStateOf<Job?>(null) }
            
            // Sync local state with ViewModel state when it changes externally
            // Convert CharArray to String for UI display
            LaunchedEffect(formData.passwordInput, formData.confirmPasswordInput) {
                // Only update if ViewModel state differs from local state
                // This handles cases where form is reset or cleared
                val currentPasswordString = String(formData.passwordInput)
                val currentConfirmString = String(formData.confirmPasswordInput)
                
                if (currentPasswordString != passwordValue) {
                    passwordValue = currentPasswordString
                }
                if (currentConfirmString != confirmPasswordValue) {
                    confirmPasswordValue = currentConfirmString
                }
            }
            
            // Clean up debounce job when file changes or composable is disposed
            DisposableEffect(formData.copiedFilePath) {
                onDispose {
                    debounceJob?.cancel()
                    debounceJob = null
                }
            }
            
            fun updatePasswords(password: String? = null, confirm: String? = null) {
                // Update local state immediately for UI responsiveness
                if (password != null) {
                    passwordValue = password
                }
                if (confirm != null) {
                    confirmPasswordValue = confirm
                }
                
                // Cancel previous debounce job
                debounceJob?.cancel()
                
                // Debounce ViewModel update to batch rapid changes
                debounceJob = CoroutineScope(Dispatchers.Main).launch {
                    delay(150) // 150ms debounce - balances responsiveness with batching
                    
                    // Convert String to CharArray for secure storage
                    // Use atomic update method from ViewModel
                    viewModel.updatePasswords(
                        password = passwordValue.takeIf { password != null }?.toCharArray(),
                        confirmPassword = confirmPasswordValue.takeIf { confirm != null }?.toCharArray()
                    )
                }
            }
            Password(
                value = passwordValue,
                onChange = { updatePasswords(password = it) },
                visible = visible,
                icon = { PasswordIcon(visible) { visible = !visible } },
                isError = formData.passwordInput.isEmpty()
            )
            if (formData.isEncrypt) {
                ConfirmPassword(
                    value = confirmPasswordValue,
                    onChange = { updatePasswords(confirm = it) },
                    visible = visible,
                    isError = !formData.isPasswordsMatch,
                    icon = { PasswordIcon(visible) { visible = !visible } })
            }
        }
    }
}