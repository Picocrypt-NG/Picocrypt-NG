package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.InputMode
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalInputModeManager
import androidx.compose.ui.platform.LocalWindowInfo
import kotlinx.coroutines.flow.first

/**
 * Requests safe-default focus once the target is placed and the dialog accepts keyboard focus.
 *
 * Call from the dialog's content so input mode and window focus belong to
 * the dialog, rather than the activity behind it.
 */
@Composable
internal fun Modifier.safeDefaultDialogFocus(focusRequester: FocusRequester): Modifier {
    val inputModeManager = LocalInputModeManager.current
    val windowInfo = LocalWindowInfo.current
    var placed by remember(focusRequester, inputModeManager, windowInfo) { mutableStateOf(false) }
    LaunchedEffect(focusRequester, inputModeManager, windowInfo) {
        snapshotFlow {
            placed && inputModeManager.inputMode == InputMode.Keyboard && windowInfo.isWindowFocused
        }.first { it }
        focusRequester.requestFocus()
    }
    return this.focusRequester(focusRequester).onGloballyPositioned { placed = true }
}
