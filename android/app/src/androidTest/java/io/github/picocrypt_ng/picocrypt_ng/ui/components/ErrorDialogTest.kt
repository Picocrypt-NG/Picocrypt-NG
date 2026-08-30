package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.R
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for ErrorDialog component.
 *
 * These assert the dialog actually surfaces the error's user-facing message (and that it
 * renders nothing when error is null). Asserting onRoot().assertIsDisplayed() would
 * be tautological — the test harness root is always displayed regardless of whether
 * ErrorDialog renders.
 */
@RunWith(AndroidJUnit4::class)
class ErrorDialogTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun errorDialog_displays_validation_error_message() {
        val error = AppError.ValidationError.NoFileSelected

        composeTestRule.setContent {
            ErrorDialog(error = error, onDismiss = {})
        }

        // The dialog renders the error's localized user-facing message
        // (R.string.error_no_file_selected): ErrorDialog displays localizedMessage,
        // which prefers messageResId over the raw userMessage fallback.
        val context = ApplicationProvider.getApplicationContext<Context>()
        composeTestRule.onNodeWithText(context.getString(R.string.error_no_file_selected))
            .assertIsDisplayed()
    }

    @Test
    fun errorDialog_displays_operation_error_message() {
        val error = AppError.OperationError.GenericOperation(
            userMessage = "Operation failed",
            technicalMessage = "Technical details"
        )

        composeTestRule.setContent {
            ErrorDialog(error = error, onDismiss = {})
        }

        composeTestRule.onNodeWithText("Operation failed").assertIsDisplayed()
    }

    @Test
    fun errorDialog_renders_nothing_when_error_is_null() {
        composeTestRule.setContent {
            ErrorDialog(error = null, onDismiss = {})
        }

        // ErrorDialog wraps its content in `error?.let { AlertDialog(...) }`, so a
        // null error must produce no dialog at all.
        composeTestRule.onNode(isDialog()).assertDoesNotExist()
    }
}
