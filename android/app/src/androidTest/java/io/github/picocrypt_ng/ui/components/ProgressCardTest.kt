package io.github.picocrypt_ng.ui.components

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.OperationState
import io.github.picocrypt_ng.OperationType
import io.github.picocrypt_ng.testutils.TestDataBuilders
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for ProgressCard component.
 */
@RunWith(AndroidJUnit4::class)
class ProgressCardTest {
    
    @get:Rule
    val composeTestRule = createComposeRule()
    
    @Test
    fun `ProgressCard displays when operation is active`() {
        val operationState = TestDataBuilders.createOperationState(
            status = "Processing",
            progress = 0.5f,
            info = "Encrypting file...",
            done = false
        )
        
        composeTestRule.setContent {
            ProgressCard(operation = operationState)
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
    
    @Test
    fun `ProgressCard displays completed operation`() {
        val operationState = TestDataBuilders.createOperationState(
            status = "Completed",
            progress = 1.0f,
            info = "Encryption complete",
            done = true
        )
        
        composeTestRule.setContent {
            ProgressCard(operation = operationState)
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
    
    @Test
    fun `ProgressCard displays error state`() {
        val error = io.github.picocrypt_ng.AppError.OperationError.GenericOperation("Test error")
        val operationState = TestDataBuilders.createOperationState(
            status = "Error",
            progress = 0.0f,
            info = "Operation failed",
            done = true,
            error = error
        )
        
        composeTestRule.setContent {
            ProgressCard(operation = operationState)
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
}

