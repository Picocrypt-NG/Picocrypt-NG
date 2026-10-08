package io.github.picocrypt_ng.picocrypt_ng

import android.app.Application
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import androidx.lifecycle.SavedStateHandle
import io.github.picocrypt_ng.picocrypt_ng.ui.components.routeNormalPcv3Selection
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class PCVUnavailableStateTest {
    @get:Rule
    val instantTaskExecutorRule = InstantTaskExecutorRule()

    @Test
    fun `stable PCV codes map to one nonrecoverable localized error`() {
        listOf("PCV3_UNSUPPORTED", "PCV3_INVALID_STRUCTURE").forEach { code ->
            val error = AppError.fromGoError(
                errorString = code,
                operationType = OperationType.DECRYPT,
                code = code,
            )

            assertTrue(error is AppError.OperationError.PCVUnavailable)
            assertEquals(R.string.error_pcv_unavailable, error.messageResId)
            assertFalse(error.allowsForceDecrypt())
            assertFalse(error.allowsPasswordRetry())

            val thrown = assertThrows(AppError.OperationError.PCVUnavailable::class.java) {
                GoBridge.parseDecryptionInfo("""{"errorCode":"$code"}""")
            }

            assertEquals(R.string.error_pcv_unavailable, thrown.messageResId)
            assertFalse(thrown.allowsForceDecrypt())
            assertFalse(thrown.allowsPasswordRetry())
        }
    }

    @Test
    fun `unconfigured production route refuses normal PCV3 and returns its sole cleanup owner`() {
        val viewModel = MainViewModel(
            mockk<Application>(relaxed = true),
            SavedStateHandle(),
        )
        viewModel.updatePasswords(
            password = "legacy-secret".toCharArray(),
            confirmPassword = "legacy-secret".toCharArray(),
        )
        val oldPassword = viewModel.formState.value.passwordInput
        val oldConfirmation = viewModel.formState.value.confirmPasswordInput

        val cleanup = routeNormalPcv3Selection(
            viewModel = viewModel,
            selectedFilename = "claimed.pcv",
            copiedPath = "/app/files/claimed.pcv",
            policyState = Pcv3AndroidPolicyState.UNCONFIGURED,
        )
        val rejectedPassword = "must-not-stick".toCharArray()
        viewModel.updatePasswords(password = rejectedPassword)
        viewModel.setPcv3Action(Pcv3ActionIntent.FORCE_WITH_UNVERIFIED_CONSENT)
        viewModel.setPcv3FactorPolicy(Pcv3FactorPolicyIntent.PASSWORD_ONLY)

        assertEquals(listOf("/app/files/claimed.pcv"), cleanup)
        assertTrue(oldPassword.all { it == '\u0000' })
        assertTrue(oldConfirmation.all { it == '\u0000' })
        assertTrue("a rejected caller credential is zeroed in place", rejectedPassword.all { it == '\u0000' })
        val refused = viewModel.formState.value
        assertTrue(refused.pcvUnavailable)
        assertFalse("content-routed PCV3 must not fall through by filename", refused.isDecrypt)
        assertFalse(refused.isEncrypt)
        assertFalse(refused.hasSelectedInput)
        assertFalse(refused.hasAnyCredentialInput)
        assertNull("UNCONFIGURED has no user-selected operation authority", refused.pcv3Intent?.action)
        assertNull(refused.pcv3Intent?.factorPolicy)
        assertFalse(refused.isFormValid)
        val error = viewModel.errorMessage.value
        assertTrue(error is AppError.OperationError.PCVUnavailable)
        assertEquals("PCV3_ANDROID_UNCONFIGURED", error?.technicalMessage)
        assertEquals(R.string.pcv3_unavailable_device_build, error?.messageResId)
        assertNull(
            "an unconfigured refusal cannot transfer credentials or source to StartPCV3",
            viewModel.takePcv3Operation("/app/files/output_file"),
        )
    }
}
