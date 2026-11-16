package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationManager
import io.github.picocrypt_ng.picocrypt_ng.OperationState
import io.github.picocrypt_ng.picocrypt_ng.OperationStatus
import io.github.picocrypt_ng.picocrypt_ng.OperationStatusData
import io.github.picocrypt_ng.picocrypt_ng.OperationType
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.CommentAuthenticity
import io.github.picocrypt_ng.picocrypt_ng.LegacySecurityWarning
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import kotlinx.coroutines.flow.MutableStateFlow
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
    fun progressCard_preservesLegacyV1WarningAlongsideSuccessfulPayload() = assertLegacyMetadata(
        "v1.49", CommentAuthenticity.UNVERIFIED, LegacySecurityWarning.UNAUTHENTICATED_V1_HEADER,
        R.string.comment_authenticity_unverified, R.string.legacy_v1_security_warning,
    )

    @Test
    fun progressCard_confirmsV2CommentWithoutHidingPasswordOnlyHeaderLimitation() = assertLegacyMetadata(
        "v2.19", CommentAuthenticity.AUTHENTICATED, LegacySecurityWarning.V2_PASSWORD_ONLY_AUTHENTICATION,
        R.string.comment_authenticity_authenticated, R.string.legacy_v2_security_warning,
    )

    @Test
    fun progressCard_recoveryKeepsUnverifiedPayloadWarningAlongsideLegacyMetadata() = assertLegacyMetadata(
        "v2.19", CommentAuthenticity.UNVERIFIED, LegacySecurityWarning.V2_PASSWORD_ONLY_AUTHENTICATION,
        R.string.comment_authenticity_unverified, R.string.legacy_v2_security_warning, unverified = true,
    )

    @Test
    fun progressCard_authenticatedCommentDoesNotUpgradeUnverifiedPayload() = assertLegacyMetadata(
        "v2.19", CommentAuthenticity.AUTHENTICATED, LegacySecurityWarning.V2_PASSWORD_ONLY_AUTHENTICATION,
        R.string.comment_authenticity_authenticated, R.string.legacy_v2_security_warning, unverified = true,
    )

    private fun assertLegacyMetadata(version: String, authenticity: CommentAuthenticity,
        warning: LegacySecurityWarning, commentResource: Int, warningResource: Int, unverified: Boolean = false) {
        val app = ApplicationProvider.getApplicationContext<android.app.Application>()
        val main = MainViewModel(app, androidx.lifecycle.SavedStateHandle())
        val operation = TestDataBuilders.createOperationState(
            type = OperationType.DECRYPT,
            status = OperationStatusData(if (unverified) OperationStatus.COMPLETED_UNVERIFIED else OperationStatus.COMPLETED),
            done = true, error = null,
        ).copy(legacyVersion = version, commentAuthenticity = authenticity, legacySecurityWarning = warning)
        val original = swapOperationState(operation)
        try {
            composeTestRule.setContent { ProgressCard(main, OperationViewModel()) }
            composeTestRule.onNodeWithText(app.getString(commentResource)).assertIsDisplayed()
            composeTestRule.onNodeWithText(app.getString(warningResource)).assertIsDisplayed()
            composeTestRule.onNodeWithText(app.getString(R.string.save)).assertIsEnabled()
            if (unverified) {
                composeTestRule.onNodeWithText(app.getString(R.string.force_decrypt_warning)).assertIsDisplayed()
                composeTestRule.onNodeWithText(app.getString(R.string.operation_completed_successfully)).assertDoesNotExist()
            }
        } finally {
            restoreOperationState(original)
        }
    }

    @Test
    fun progressCard_warnsAboutUnverifiedCompletionAndKeepsSaveEnabled() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val mainViewModel = MainViewModel(application, androidx.lifecycle.SavedStateHandle())
        val operationViewModel = OperationViewModel()
        val original = swapOperationState(TestDataBuilders.createOperationState(
            type = OperationType.DECRYPT,
            status = OperationStatusData("COMPLETED_UNVERIFIED"),
            done = true,
            error = null,
        ))
        try {
            composeTestRule.setContent {
                ProgressCard(mainViewModel = mainViewModel, operationViewModel = operationViewModel)
            }
            composeTestRule.onNodeWithText(application.getString(R.string.force_decrypt_warning)).assertIsDisplayed()
            composeTestRule.onNodeWithText(application.getString(R.string.operation_completed_successfully)).assertDoesNotExist()
            composeTestRule.onNodeWithText(application.getString(R.string.save)).assertIsEnabled()
        } finally {
            restoreOperationState(original)
        }
    }

    @Test
    fun progressCard_composes_with_no_active_operation() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()

        composeTestRule.setContent {
            ProgressCard(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel
            )
        }

        // ProgressCard is a modal: with no active operation it renders nothing.
        // Assert intent — no progress dialog is shown (its Cancel button is absent).
        composeTestRule.onNodeWithText(application.getString(R.string.cancel)).assertDoesNotExist()
    }

    @Test
    fun progressCard_rendersLocalizedStructuredStatusWithoutWireCode() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val mainViewModel = MainViewModel(application, androidx.lifecycle.SavedStateHandle())
        val operationViewModel = OperationViewModel()
        val status = OperationStatusData(
            code = OperationStatus.ENCRYPTING_RATE,
            speedMiBPerSecond = 12.34,
            eta = "100:59:59",
        )
        val originalState = swapOperationState(
            TestDataBuilders.createOperationState(
                type = OperationType.ENCRYPT,
                status = status,
                done = false,
            )
        )

        try {
            composeTestRule.setContent {
                ProgressCard(
                    mainViewModel = mainViewModel,
                    operationViewModel = operationViewModel,
                )
            }

            composeTestRule.onNodeWithText(
                application.getString(R.string.status_encrypting_rate, 12.34, "100:59:59")
            ).assertIsDisplayed()
            composeTestRule.onNodeWithText(OperationStatus.ENCRYPTING_RATE).assertDoesNotExist()
        } finally {
            restoreOperationState(originalState)
        }
    }

    @Test
    fun progressCard_shows_retry_dialog_for_password_errors() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()
        val originalState = swapOperationState(
            TestDataBuilders.createOperationState(
                type = OperationType.DECRYPT,
                done = true,
                error = AppError.OperationError.PasswordAuth("Incorrect password"),
                formData = TestDataBuilders.createDecryptFormData()
            )
        )

        try {
            composeTestRule.setContent {
                ProgressCard(
                    mainViewModel = mainViewModel,
                    operationViewModel = operationViewModel
                )
            }

            composeTestRule.onNodeWithText(application.getString(R.string.retry)).assertIsDisplayed()
            composeTestRule.onNodeWithText(application.getString(R.string.cancel)).assertIsDisplayed()
            composeTestRule.onNodeWithText(
                application.getString(R.string.error_auth_failed)
            ).assertIsDisplayed()
            composeTestRule.onNodeWithText("Incorrect password").assertDoesNotExist()
        } finally {
            restoreOperationState(originalState)
        }
    }

    @Test
    fun progressCard_shows_force_decrypt_dialog_for_corruption_errors() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()
        val originalState = swapOperationState(
            TestDataBuilders.createOperationState(
                type = OperationType.DECRYPT,
                done = true,
                error = AppError.OperationError.DataCorruption("Ciphertext corrupted"),
                formData = TestDataBuilders.createDecryptFormData()
            )
        )

        try {
            composeTestRule.setContent {
                ProgressCard(
                    mainViewModel = mainViewModel,
                    operationViewModel = operationViewModel
                )
            }

            composeTestRule.onNodeWithText(application.getString(R.string.force_decrypt)).assertIsDisplayed()
            composeTestRule.onNodeWithText(application.getString(R.string.cancel)).assertIsDisplayed()
            composeTestRule.onNodeWithText(application.getString(R.string.data_corruption_detected)).assertIsDisplayed()
            composeTestRule.onNodeWithText(
                application.getString(R.string.error_data_corrupted)
            ).assertIsDisplayed()
            composeTestRule.onNodeWithText("Ciphertext corrupted").assertDoesNotExist()
        } finally {
            restoreOperationState(originalState)
        }
    }

    @Test
    fun progressCard_shows_cancelled_dialog_without_save_button() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()
        val originalState = swapOperationState(
            TestDataBuilders.createOperationState(
                type = OperationType.ENCRYPT,
                status = OperationStatusData(OperationStatus.CANCELLED),
                done = true,
                error = null,
                formData = TestDataBuilders.createEncryptFormData()
            )
        )

        try {
            composeTestRule.setContent {
                ProgressCard(
                    mainViewModel = mainViewModel,
                    operationViewModel = operationViewModel
                )
            }

            composeTestRule.onNodeWithText(application.getString(R.string.operation_cancelled)).assertIsDisplayed()
            composeTestRule.onNodeWithText(application.getString(R.string.save)).assertDoesNotExist()
        } finally {
            restoreOperationState(originalState)
        }
    }
}

private fun swapOperationState(state: OperationState?): MutableStateFlow<OperationState?> {
    val field = OperationManager::class.java.getDeclaredField("_currentOperation")
    field.isAccessible = true
    @Suppress("UNCHECKED_CAST")
    val flow = field.get(OperationManager) as MutableStateFlow<OperationState?>
    val original = MutableStateFlow(flow.value)
    flow.value = state
    return original
}

private fun restoreOperationState(original: MutableStateFlow<OperationState?>) {
    val field = OperationManager::class.java.getDeclaredField("_currentOperation")
    field.isAccessible = true
    @Suppress("UNCHECKED_CAST")
    val flow = field.get(OperationManager) as MutableStateFlow<OperationState?>
    flow.value = original.value
}
