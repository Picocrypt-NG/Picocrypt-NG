package io.github.picocrypt_ng.testutils

import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.hasText

/**
 * Compose test helpers for UI testing.
 */
object ComposeTestHelpers {
    
    /**
     * Asserts that a node with the given text is displayed.
     */
    fun SemanticsNodeInteraction.assertTextDisplayed(text: String) {
        assertIsDisplayed()
        assert(hasText(text))
    }
    
    /**
     * Asserts that a node has the exact text.
     */
    fun SemanticsNodeInteraction.assertExactText(text: String) {
        assertTextEquals(text)
    }
}

