package io.github.picocrypt_ng.ui.components

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.MainViewModel
import io.mockk.mockk
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for PasswordCard component.
 */
@RunWith(AndroidJUnit4::class)
class PasswordCardTest {
    
    @get:Rule
    val composeTestRule = createComposeRule()
    
    @Test
    fun `PasswordCard displays for encryption`() {
        val mockApplication = mockk<android.app.Application>(relaxed = true)
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val viewModel = MainViewModel(mockApplication, savedStateHandle)
        
        composeTestRule.setContent {
            PasswordCard(
                viewModel = viewModel,
                isEncrypt = true
            )
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
    
    @Test
    fun `PasswordCard displays for decryption`() {
        val mockApplication = mockk<android.app.Application>(relaxed = true)
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val viewModel = MainViewModel(mockApplication, savedStateHandle)
        
        composeTestRule.setContent {
            PasswordCard(
                viewModel = viewModel,
                isEncrypt = false
            )
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
}

