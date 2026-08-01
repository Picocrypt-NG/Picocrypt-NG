package io.github.picocrypt_ng.picocrypt_ng

import android.app.Application
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import androidx.lifecycle.SavedStateHandle
import io.github.picocrypt_ng.picocrypt_ng.ui.components.rejectPCVAndDeleteOwnedCopy
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
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
        }

        val proseOnly = AppError.fromGoError(
            errorString = "This prose mentions PCV3_UNSUPPORTED but is not control data",
            operationType = OperationType.DECRYPT,
            code = "GENERIC",
        )
        assertFalse(proseOnly is AppError.OperationError.PCVUnavailable)
    }

    @Test
    fun `metadata error envelope is rejected before metadata fields are required`() {
        listOf("PCV3_UNSUPPORTED", "PCV3_INVALID_STRUCTURE").forEach { code ->
            val error = assertThrows(AppError.OperationError.PCVUnavailable::class.java) {
                GoBridge.parseDecryptionInfo("""{"errorCode":"$code"}""")
            }

            assertEquals(R.string.error_pcv_unavailable, error.messageResId)
            assertFalse(error.allowsForceDecrypt())
            assertFalse(error.allowsPasswordRetry())
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `rejection clears unsafe state before error and survives dismissal until replacement`() = runTest {
        val savedStateHandle = SavedStateHandle()
        val viewModel = MainViewModel(mockk<Application>(relaxed = true), savedStateHandle)
        val oldPassword = "password-secret".toCharArray()
        val oldConfirmation = "password-secret".toCharArray()
        val priorOwnedPath = "/app/files/prior-selection.pcv"
        val currentOwnedPath = "/app/files/current-claimed-copy"

        viewModel.updateFormData(
            FormData(
                selectedFilename = "prior-selection.pcv",
                copiedFilePath = priorOwnedPath,
                comments = "plaintext header comment",
                passwordInput = oldPassword,
                confirmPasswordInput = oldConfirmation,
                reedSolomon = true,
                paranoid = true,
                deniability = true,
                verifyFirst = true,
                keyfileFilenames = listOf(KeyfileInfo("/app/files/key", "key")),
                keyfileOrdered = true,
                compress = true,
                inputFiles = listOf("/app/files/staged/input"),
                onlyFolders = listOf("/app/files/staged"),
                onlyFiles = listOf("/app/files/staged/input"),
                selectionKind = SelectionKind.SINGLE_FILE,
                suggestedOutputName = "unsafe-output",
                decryptionInfo = DecryptionInfo(
                    keyfilesRequired = true,
                    keyfileOrdered = true,
                    reedSolomon = true,
                    deniability = false,
                    paranoid = true,
                    comments = "metadata",
                    readable = true,
                ),
            )
        )

        val error = AppError.fromGoError(
            errorString = "PCV3_UNSUPPORTED",
            operationType = OperationType.DECRYPT,
            code = "PCV3_UNSUPPORTED",
        ) as AppError.OperationError.PCVUnavailable
        val stateWasUnavailableWhenErrorPublished = CompletableDeferred<Boolean>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
            viewModel.errorMessage.filterNotNull().first()
            stateWasUnavailableWhenErrorPublished.complete(viewModel.formState.value.pcvUnavailable)
        }

        val cleanupPath = viewModel.rejectPCV(
            selectedFilename = "claimed-with-misleading-name.bin",
            ownedCopyPath = currentOwnedPath,
            error = error,
        )

        assertEquals(currentOwnedPath, cleanupPath)
        assertNotEquals(priorOwnedPath, cleanupPath)
        assertTrue(stateWasUnavailableWhenErrorPublished.await())
        assertTrue(oldPassword.all { it == '\u0000' })
        assertTrue(oldConfirmation.all { it == '\u0000' })

        val unavailable = viewModel.formState.value
        assertEquals("claimed-with-misleading-name.bin", unavailable.selectedFilename)
        assertEquals("", unavailable.copiedFilePath)
        assertEquals("", unavailable.comments)
        assertEquals(0, unavailable.passwordInput.size)
        assertEquals(0, unavailable.confirmPasswordInput.size)
        assertFalse(unavailable.reedSolomon)
        assertFalse(unavailable.paranoid)
        assertFalse(unavailable.deniability)
        assertFalse(unavailable.verifyFirst)
        assertFalse(unavailable.keyfileOrdered)
        assertFalse(unavailable.compress)
        assertTrue(unavailable.keyfileFilenames.isEmpty())
        assertTrue(unavailable.inputFiles.isEmpty())
        assertTrue(unavailable.onlyFolders.isEmpty())
        assertTrue(unavailable.onlyFiles.isEmpty())
        assertEquals("", unavailable.suggestedOutputName)
        assertNull(unavailable.decryptionInfo)
        assertTrue(unavailable.pcvUnavailable)
        assertFalse(unavailable.isEncrypt)
        assertFalse(unavailable.isDecrypt)
        assertFalse(unavailable.isFormValid)
        assertFalse(unavailable.hasSelectedInput)
        assertSame(error, viewModel.errorMessage.value)
        assertFalse(savedStateHandle.keys().contains("selected_filename"))
        assertFalse(savedStateHandle.keys().contains("copied_file_path"))
        assertFalse(savedStateHandle.keys().contains("comments"))

        val otherwiseEqual = unavailable.copy(pcvUnavailable = false)
        assertNotEquals(otherwiseEqual, unavailable)

        viewModel.clearError()
        assertNull(viewModel.errorMessage.value)
        assertTrue(viewModel.formState.value.pcvUnavailable)
        assertFalse(viewModel.formState.value.isEncrypt)
        assertFalse(viewModel.formState.value.isDecrypt)

        viewModel.resetFormToDefaults()
        val reset = viewModel.formState.value
        assertFalse(reset.pcvUnavailable)
        assertEquals("", reset.selectedFilename)
        assertEquals("", reset.copiedFilePath)

        viewModel.updateFormData(
            reset.copy(
                selectedFilename = "replacement.txt",
                copiedFilePath = "/app/files/replacement.txt",
                passwordInput = "new-password".toCharArray(),
                confirmPasswordInput = "new-password".toCharArray(),
            )
        )
        assertTrue(viewModel.formState.value.isEncrypt)
        assertTrue(viewModel.formState.value.isFormValid)
    }

    @Test
    fun `cleanup targets only the just-created owned copy after unavailable state is committed`() = runTest {
        val viewModel = MainViewModel(mockk<Application>(relaxed = true), SavedStateHandle())
        val priorOwnedPath = "/app/files/prior-owned-copy.pcv"
        val currentOwnedPath = "/app/files/current-owned-copy.pcv"
        val providerPath = "content://provider/original-volume"
        viewModel.updateFormData(
            FormData(
                selectedFilename = "prior.pcv",
                copiedFilePath = priorOwnedPath,
                comments = "prior metadata",
                passwordInput = "prior-password".toCharArray(),
                confirmPasswordInput = "prior-password".toCharArray(),
                reedSolomon = true,
                paranoid = true,
                deniability = false,
                keyfileFilenames = emptyList(),
                keyfileOrdered = false,
            )
        )
        val error = AppError.fromGoError(
            errorString = "PCV3_INVALID_STRUCTURE",
            operationType = OperationType.DECRYPT,
            code = "PCV3_INVALID_STRUCTURE",
        ) as AppError.OperationError.PCVUnavailable
        val cleanupTargets = mutableListOf<String>()

        val deleted = rejectPCVAndDeleteOwnedCopy(
            viewModel = viewModel,
            selectedFilename = "misleading.txt",
            ownedCopyPath = currentOwnedPath,
            error = error,
        ) { path ->
            assertTrue("unavailable state must precede cleanup", viewModel.formState.value.pcvUnavailable)
            assertEquals("", viewModel.formState.value.copiedFilePath)
            assertSame(error, viewModel.errorMessage.value)
            cleanupTargets += path
            false
        }

        assertFalse("cleanup failure is reported without rolling state back", deleted)
        assertEquals(listOf(currentOwnedPath), cleanupTargets)
        assertFalse(cleanupTargets.contains(priorOwnedPath))
        assertFalse(cleanupTargets.contains(providerPath))
        assertTrue(viewModel.formState.value.pcvUnavailable)
        assertFalse(viewModel.formState.value.isEncrypt)
        assertFalse(viewModel.formState.value.isDecrypt)
        assertFalse(viewModel.formState.value.isFormValid)

        viewModel.clearError()
        assertNull(viewModel.errorMessage.value)
        assertTrue(viewModel.formState.value.pcvUnavailable)
        assertEquals("", viewModel.formState.value.copiedFilePath)
    }
}
