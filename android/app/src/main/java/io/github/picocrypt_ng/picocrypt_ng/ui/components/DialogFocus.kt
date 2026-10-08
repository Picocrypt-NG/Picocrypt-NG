package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.view.ViewTreeObserver
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.platform.LocalView
import kotlinx.coroutines.flow.first

/**
 * Requests focus for the safe default action of a modal dialog.
 *
 * A one-shot focus request at composition time is denied permanently in
 * touch mode — the default state of every phone and emulator until a key is
 * pressed — because the dialog's Compose view may not take focus there at
 * all. The safe default action (cancel/keep) must hold focus as soon as
 * focus navigation exists, so this waits until the device leaves touch mode
 * instead of firing a single request that would be silently dropped.
 */
@Composable
internal fun SafeDefaultDialogFocus(focusRequester: FocusRequester) {
    val view = LocalView.current
    val touchMode = remember(view) { mutableStateOf(view.isInTouchMode) }
    DisposableEffect(view) {
        val listener = ViewTreeObserver.OnTouchModeChangeListener { inTouchMode ->
            touchMode.value = inTouchMode
        }
        view.viewTreeObserver.addOnTouchModeChangeListener(listener)
        onDispose { view.viewTreeObserver.removeOnTouchModeChangeListener(listener) }
    }
    LaunchedEffect(focusRequester) {
        snapshotFlow { !touchMode.value }.first { it }
        focusRequester.requestFocus()
    }
}
