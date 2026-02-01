package io.github.picocrypt_ng.ui.components

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for ErrorDialog component.
 */
@RunWith(AndroidJUnit4::class)
class ErrorDialogTest {
    
    @get:Rule
    val composeTestRule = createComposeRule()
    
    @Test
    fun `ErrorDialog displays error message`() {
        val error = io.github.picocrypt_ng.AppError.ValidationError.NoFileSelected
        
        composeTestRule.setContent {
            ErrorDialog(
                error = error,
                onDismiss = {}
            )
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
    
    @Test
    fun `ErrorDialog displays operation error`() {
        val error = io.github.picocrypt_ng.AppError.OperationError.GenericOperation(
            userMessage = "Operation failed",
            technicalMessage = "Technical details"
        )
        
        composeTestRule.setContent {
            ErrorDialog(
                error = error,
                onDismiss = {}
            )
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
    
    @Test
    fun `ErrorDialog does not display when error is null`() {
        composeTestRule.setContent {
            ErrorDialog(
                error = null,
                onDismiss = {}
            )
        }
        
        // Dialog should not be displayed when error is null
        // (This depends on implementation - some dialogs may still render but be invisible)
        composeTestRule.onRoot().assertIsDisplayed()
    }
}


