package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.app.Application
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.lifecycle.SavedStateHandle
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import org.junit.Assert.assertEquals
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
    fun passwordResetClearsMountedFieldsAndHidesThemWithTheSameFileSelected() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())
        viewModel.updateFormData(TestDataBuilders.createEncryptFormData(password = "", confirmPassword = ""))
        val selectedPath = viewModel.formState.value.copiedFilePath
        composeTestRule.setContent { PasswordCard(viewModel) }
        val password = composeTestRule.onNodeWithText(application.getString(R.string.password))
        val confirm = composeTestRule.onNodeWithText(application.getString(R.string.confirm_password))
        password.performTextInput("old secret")
        confirm.performTextInput("old secret")
        composeTestRule.onAllNodesWithContentDescription(application.getString(R.string.show_password))[0].performClick()
        composeTestRule.waitForIdle()
        assertEquals("old secret", password.fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
        composeTestRule.runOnIdle { viewModel.clearSensitiveData(clearFiles = false) }
        composeTestRule.waitForIdle()
        assertEquals(selectedPath, viewModel.formState.value.copiedFilePath)
        assertEquals("", password.fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
        assertEquals("", confirm.fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
        composeTestRule.onAllNodesWithContentDescription(application.getString(R.string.show_password)).assertCountEquals(2)
        password.performTextInput("new")
        composeTestRule.waitForIdle()
        assertEquals("new", String(viewModel.formState.value.passwordInput))
    }

    @Test
    fun passwordCard_displays_for_encryption() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())

        viewModel.updateFormData(
            TestDataBuilders.createEncryptFormData(
                password = "",
                confirmPassword = ""
            )
        )

        composeTestRule.setContent {
            PasswordCard(viewModel = viewModel)
        }

        composeTestRule.onAllNodesWithText(application.getString(R.string.password)).assertCountEquals(1)
        composeTestRule.onAllNodesWithText(application.getString(R.string.confirm_password)).assertCountEquals(1)
    }

    /**
     * Guards the state-based wiring: typing into the SecureTextField must reach the
     * ViewModel as a CharArray (no debounce/String round-trip in between). If the
     * snapshotFlow -> updatePasswords wiring is dropped, formState never sees the
     * typed text and this fails.
     */
    @Test
    fun typingPassword_propagatesToViewModelAsCharArray() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())

        viewModel.updateFormData(
            TestDataBuilders.createEncryptFormData(
                password = "",
                confirmPassword = ""
            )
        )

        composeTestRule.setContent {
            PasswordCard(viewModel = viewModel)
        }

        composeTestRule.onNodeWithText(application.getString(R.string.password))
            .performTextInput("hunter2")
        composeTestRule.waitForIdle()

        assertEquals("hunter2", String(viewModel.formState.value.passwordInput))
    }

    @Test
    fun pcv3KeyfileOnlyEncryptionDoesNotRequireAPassword() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())

        viewModel.updateFormData(
            TestDataBuilders.createEncryptFormData(
                password = "",
                confirmPassword = "",
                deniability = false,
                keyfiles = listOf(TestDataBuilders.createKeyfileInfo()),
            ),
        )

        composeTestRule.setContent {
            PasswordCard(viewModel = viewModel)
        }

        composeTestRule
            .onAllNodesWithText(application.getString(R.string.enter_password))
            .assertCountEquals(0)
    }

    @Test
    fun pcv3KeyfileOnlyDeniabilityDoesNotRequireAnOuterPassword() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())

        viewModel.updateFormData(
            TestDataBuilders.createEncryptFormData(
                password = "",
                confirmPassword = "",
                deniability = true,
                keyfiles = listOf(TestDataBuilders.createKeyfileInfo()),
            ),
        )

        composeTestRule.setContent {
            PasswordCard(viewModel = viewModel)
        }

        val expectedMessage = application.getString(R.string.deniability_password_required)
        composeTestRule.onAllNodesWithText(expectedMessage).assertCountEquals(0)
    }
}
