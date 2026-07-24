package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.FormData
import io.github.picocrypt_ng.picocrypt_ng.DecryptionInfo
import io.github.picocrypt_ng.picocrypt_ng.KeyfileInfo
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
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
    fun workButton_displays_encrypt_label() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()

        mainViewModel.updateFormData(
            FormData(
                selectedFilename = "test.txt",
                copiedFilePath = "/data/test/input_file.txt",
                comments = "",
                passwordInput = "secret".toCharArray(),
                confirmPasswordInput = "secret".toCharArray(),
                reedSolomon = false,
                paranoid = false,
                deniability = false,
                keyfileFilenames = emptyList(),
                keyfileOrdered = false,
                decryptionInfo = null
            )
        )

        composeTestRule.setContent {
            WorkButton(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel
            )
        }

        composeTestRule
            .onNodeWithText(application.getString(R.string.encrypt_file))
            .assertIsDisplayed()
    }

    @Test
    fun workButton_displays_decrypt_label() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()

        mainViewModel.updateFormData(
            FormData(
                selectedFilename = "test.pcv",
                copiedFilePath = "/data/test/input_file.pcv",
                comments = "",
                passwordInput = "secret".toCharArray(),
                confirmPasswordInput = "secret".toCharArray(),
                reedSolomon = false,
                paranoid = false,
                deniability = false,
                keyfileFilenames = emptyList(),
                keyfileOrdered = false,
                decryptionInfo = null
            )
        )

        composeTestRule.setContent {
            WorkButton(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel
            )
        }

        composeTestRule
            .onNodeWithText(application.getString(R.string.decrypt_file))
            .assertIsDisplayed()
    }

    @Test
    fun workButton_is_disabled_when_copied_file_path_is_missing() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()

        mainViewModel.updateFormData(
            FormData(
                selectedFilename = "test.txt",
                copiedFilePath = "",
                comments = "",
                passwordInput = "secret".toCharArray(),
                confirmPasswordInput = "secret".toCharArray(),
                reedSolomon = false,
                paranoid = false,
                deniability = false,
                keyfileFilenames = emptyList(),
                keyfileOrdered = false,
                decryptionInfo = null
            )
        )

        composeTestRule.setContent {
            WorkButton(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel
            )
        }

        composeTestRule
            .onNodeWithText(application.getString(R.string.encrypt_file))
            .assertIsNotEnabled()
    }

    @Test
    fun workButton_allows_legacy_deniable_keyfile_only_decryption() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()

        mainViewModel.updateFormData(
            FormData(
                selectedFilename = "legacy.pcv",
                copiedFilePath = "/data/test/input_file.pcv",
                comments = "",
                passwordInput = CharArray(0),
                confirmPasswordInput = CharArray(0),
                reedSolomon = false,
                paranoid = false,
                deniability = false,
                keyfileFilenames = listOf(KeyfileInfo("keyfile_0", "legacy.key")),
                keyfileOrdered = false,
                decryptionInfo = DecryptionInfo(
                    keyfilesRequired = true,
                    keyfileOrdered = false,
                    reedSolomon = false,
                    deniability = true,
                    paranoid = false,
                    comments = "",
                    readable = false,
                ),
            ),
        )

        composeTestRule.setContent {
            WorkButton(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel,
            )
        }

        composeTestRule
            .onNodeWithText(application.getString(R.string.decrypt_file))
            .assertIsEnabled()
    }

    @Test
    fun workButton_disables_new_v2_password_and_keyfile_encryption() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val mainViewModel = MainViewModel(application, androidx.lifecycle.SavedStateHandle())
        val operationViewModel = OperationViewModel()

        mainViewModel.updateFormData(
            FormData(
                selectedFilename = "new.txt",
                copiedFilePath = "/data/test/new.txt",
                comments = "",
                passwordInput = "secret".toCharArray(),
                confirmPasswordInput = "secret".toCharArray(),
                reedSolomon = false,
                paranoid = false,
                deniability = false,
                keyfileFilenames = listOf(KeyfileInfo("keyfile_0", "factor.key")),
                keyfileOrdered = false,
                decryptionInfo = null,
            ),
        )

        composeTestRule.setContent {
            WorkButton(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel,
            )
        }

        composeTestRule
            .onNodeWithText(application.getString(R.string.encrypt_file))
            .assertIsNotEnabled()
    }
}
