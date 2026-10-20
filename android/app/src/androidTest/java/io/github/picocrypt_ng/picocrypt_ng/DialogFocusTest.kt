package io.github.picocrypt_ng.picocrypt_ng

import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.InputMode
import androidx.compose.ui.input.InputModeManager
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.platform.LocalInputModeManager
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.platform.WindowInfo
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.assertIsFocused
import androidx.compose.ui.test.assertIsNotFocused
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performKeyInput
import androidx.compose.ui.test.pressKey
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.ui.components.safeDefaultDialogFocus
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Component focus contract with controlled readiness; this is not native window-order evidence. */
@RunWith(AndroidJUnit4::class)
class DialogFocusTest {
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun safeDefaultWaitsForPlacementAndDoesNotRegrabAfterKeyboardNavigation() {
        val inputModeManager = ModelInputModeManager()
        val windowInfo = ModelWindowInfo()
        val placeSafe = mutableStateOf(false)
        val safeFocus = FocusRequester()
        val otherFocus = FocusRequester()

        compose.setContent {
            CompositionLocalProvider(
                LocalInputModeManager provides inputModeManager,
                LocalWindowInfo provides windowInfo,
            ) {
                Layout(
                    content = {
                        TextButton(
                            modifier = Modifier
                                .safeDefaultDialogFocus(safeFocus)
                                .focusProperties { next = otherFocus }
                                .testTag(SAFE_TAG),
                            onClick = {},
                        ) {
                            Text("Safe")
                        }
                        TextButton(
                            modifier = Modifier.focusRequester(otherFocus).testTag(OTHER_TAG),
                            onClick = {},
                        ) {
                            Text("Other")
                        }
                    },
                ) { measurables, constraints ->
                    val childConstraints = constraints.copy(minWidth = 0, minHeight = 0)
                    val safe = measurables[0].measure(childConstraints)
                    val other = measurables[1].measure(childConstraints)
                    val width = maxOf(safe.width, other.width)
                        .coerceIn(constraints.minWidth, constraints.maxWidth)
                    val height = (safe.height + other.height)
                        .coerceIn(constraints.minHeight, constraints.maxHeight)
                    layout(width, height) {
                        // The safe focus target exists and is measured, but has not been placed.
                        if (placeSafe.value) safe.placeRelative(0, 0)
                        other.placeRelative(0, safe.height)
                    }
                }
            }
        }

        // Establish a real focused owner before exposing the helper's readiness condition.
        compose.runOnIdle {
            assertTrue("Fixture control must accept focus", otherFocus.requestFocus())
            windowInfo.isWindowFocused = true
        }
        // RED oracle: window/input readiness must not spend the one-shot grant before placement.
        compose.onNodeWithTag(SAFE_TAG).assertIsNotFocused()

        compose.runOnIdle { inputModeManager.inputMode = InputMode.Touch }
        compose.runOnIdle { placeSafe.value = true }
        compose.onNodeWithTag(SAFE_TAG).assertIsNotFocused()
        compose.runOnIdle { inputModeManager.inputMode = InputMode.Keyboard }
        compose.onNodeWithTag(SAFE_TAG).assertIsFocused()

        compose.onNodeWithTag(SAFE_TAG).performKeyInput { pressKey(Key.Tab) }
        compose.onNodeWithTag(OTHER_TAG).assertIsFocused()
        compose.runOnIdle { windowInfo.isWindowFocused = false }
        compose.runOnIdle { windowInfo.isWindowFocused = true }
        compose.onNodeWithTag(OTHER_TAG).assertIsFocused()
    }

    private class ModelInputModeManager : InputModeManager {
        override var inputMode: InputMode by mutableStateOf(InputMode.Keyboard)

        override fun requestInputMode(inputMode: InputMode): Boolean {
            this.inputMode = inputMode
            return true
        }
    }

    private class ModelWindowInfo : WindowInfo {
        override var isWindowFocused: Boolean by mutableStateOf(false)
    }

    private companion object {
        const val SAFE_TAG = "safe-default"
        const val OTHER_TAG = "other-control"
    }
}
