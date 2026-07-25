package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.app.Application
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.lifecycle.SavedStateHandle
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class KeyfileCardWriterPolicyTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun encryptModeExplainsWriterFreezeAndDoesNotOfferKeyfileCreation() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())
        viewModel.updateFormData(
            TestDataBuilders.createEncryptFormData(
                password = "secret",
                confirmPassword = "secret",
                keyfiles = emptyList(),
            ),
        )

        composeTestRule.setContent {
            KeyfileCard(viewModel = viewModel)
        }

        val title = application.resources.getQuantityString(R.plurals.keyfiles_count, 0, 0)
        composeTestRule.onNodeWithText(title).performClick()
        composeTestRule
            .onNodeWithText(application.getString(R.string.error_keyfile_writes_disabled))
            .assertIsDisplayed()
        composeTestRule.onAllNodesWithText(application.getString(R.string.add)).assertCountEquals(0)
        composeTestRule
            .onAllNodesWithText(application.getString(R.string.require_this_order))
            .assertCountEquals(0)
    }
}
