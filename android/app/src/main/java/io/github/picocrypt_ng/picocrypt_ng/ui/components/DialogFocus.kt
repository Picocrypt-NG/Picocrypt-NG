package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.input.InputMode
import androidx.compose.ui.platform.LocalInputModeManager
import androidx.compose.ui.platform.LocalWindowInfo
import kotlinx.coroutines.flow.first

/**
 * Requests safe-default focus once this dialog can accept keyboard focus.
 *
 * Call from the dialog's content so input mode and window focus belong to
 * the dialog, rather than the activity behind it.
 */
@Composable
internal fun SafeDefaultDialogFocus(focusRequester: FocusRequester) {
    val inputModeManager = LocalInputModeManager.current
    val windowInfo = LocalWindowInfo.current
    LaunchedEffect(focusRequester, inputModeManager, windowInfo) {
        snapshotFlow {
            inputModeManager.inputMode == InputMode.Keyboard && windowInfo.isWindowFocused
        }.first { it }
        focusRequester.requestFocus()
    }
}
