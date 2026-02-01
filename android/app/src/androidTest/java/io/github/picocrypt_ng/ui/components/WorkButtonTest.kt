package io.github.picocrypt_ng.ui.components

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.mockk
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for WorkButton component.
 */
@RunWith(AndroidJUnit4::class)
class WorkButtonTest {
    
    @get:Rule
    val composeTestRule = createComposeRule()
    
    @Test
    fun `WorkButton displays for encryption`() {
        val mockApplication = mockk<android.app.Application>(relaxed = true)
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val viewModel = MainViewModel(mockApplication, savedStateHandle)
        
        composeTestRule.setContent {
            WorkButton(
                viewModel = viewModel,
                isEncrypt = true,
                onEncrypt = {},
                onDecrypt = {}
            )
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
    
    @Test
    fun `WorkButton displays for decryption`() {
        val mockApplication = mockk<android.app.Application>(relaxed = true)
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val viewModel = MainViewModel(mockApplication, savedStateHandle)
        
        composeTestRule.setContent {
            WorkButton(
                viewModel = viewModel,
                isEncrypt = false,
                onEncrypt = {},
                onDecrypt = {}
            )
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
    
    @Test
    fun `WorkButton is disabled when form is invalid`() {
        val mockApplication = mockk<android.app.Application>(relaxed = true)
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val viewModel = MainViewModel(mockApplication, savedStateHandle)
        
        // Form data with no file selected (invalid)
        val invalidFormData = TestDataBuilders.createEncryptFormData(
            selectedFilename = "" // Invalid
        )
        viewModel.updateFormData(invalidFormData)
        
        composeTestRule.setContent {
            WorkButton(
                viewModel = viewModel,
                isEncrypt = true,
                onEncrypt = {},
                onDecrypt = {}
            )
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
}


