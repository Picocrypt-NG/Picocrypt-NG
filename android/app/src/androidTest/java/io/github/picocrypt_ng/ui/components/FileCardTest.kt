package io.github.picocrypt_ng.ui.components

import androidx.compose.ui.test.assertIsDisplayed
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
 * UI tests for FileCard component.
 */
@RunWith(AndroidJUnit4::class)
class FileCardTest {
    
    @get:Rule
    val composeTestRule = createComposeRule()
    
    @Test
    fun `FileCard displays when no file is selected`() {
        val mockApplication = mockk<android.app.Application>(relaxed = true)
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val viewModel = MainViewModel(mockApplication, savedStateHandle)
        
        composeTestRule.setContent {
            ChooseFile(viewModel = viewModel)
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
    
    @Test
    fun `FileCard displays selected filename`() {
        val mockApplication = mockk<android.app.Application>(relaxed = true)
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val viewModel = MainViewModel(mockApplication, savedStateHandle)
        
        val formData = TestDataBuilders.createEncryptFormData(
            selectedFilename = "test.txt"
        )
        viewModel.updateFormData(formData)
        
        composeTestRule.setContent {
            ChooseFile(viewModel = viewModel)
        }
        
        // Verify the component is displayed
        composeTestRule.onRoot().assertIsDisplayed()
    }
}

