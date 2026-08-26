package io.github.picocrypt_ng.picocrypt_ng

import android.app.Application
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import androidx.lifecycle.SavedStateHandle
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.mockk

/**
 * Unit tests for MainViewModel.
 */
class MainViewModelTest {
    
    @get:Rule
    val instantTaskExecutorRule = InstantTaskExecutorRule()
    
    private lateinit var mockApplication: Application
    private lateinit var savedStateHandle: SavedStateHandle
    private lateinit var viewModel: MainViewModel
    
    @Before
    fun setUp() {
        mockApplication = mockk<Application>(relaxed = true)
        savedStateHandle = SavedStateHandle()
        viewModel = MainViewModel(mockApplication, savedStateHandle)
    }
    
    @Test
    fun `formState is initialized with empty defaults`() = runTest {
        val formState = viewModel.formState.first()
        
        assertEquals("", formState.selectedFilename)
        assertEquals("", formState.copiedFilePath)
        assertEquals("", formState.comments)
        assertEquals(0, formState.passwordInput.size)
        assertEquals(0, formState.confirmPasswordInput.size)
        assertEquals(false, formState.reedSolomon)
        assertEquals(false, formState.paranoid)
        assertEquals(false, formState.deniability)
        assertEquals(emptyList<KeyfileInfo>(), formState.keyfileFilenames)
        assertEquals(false, formState.keyfileOrdered)
        assertNull(formState.decryptionInfo)
    }
    
    @Test
    fun `formState restores from SavedStateHandle`() = runTest {
        savedStateHandle["selected_filename"] = "test.txt"
        savedStateHandle["copied_file_path"] = "/path/to/file.txt"
        savedStateHandle["comments"] = "Test comments"
        
        val restoredViewModel = MainViewModel(mockApplication, savedStateHandle)
        val formState = restoredViewModel.formState.first()
        
        assertEquals("test.txt", formState.selectedFilename)
        assertEquals("/path/to/file.txt", formState.copiedFilePath)
        assertEquals("Test comments", formState.comments)
        // Passwords should not be restored
        assertEquals(0, formState.passwordInput.size)
        assertEquals(0, formState.confirmPasswordInput.size)
    }
    
    @Test
    fun `updateFormData updates form state`() = runTest {
        val newFormData = TestDataBuilders.createEncryptFormData(
            selectedFilename = "newfile.txt",
            copiedFilePath = "/new/path.txt",
            comments = "New comments"
        )
        
        viewModel.updateFormData(newFormData)
        
        val formState = viewModel.formState.first()
        assertEquals("newfile.txt", formState.selectedFilename)
        assertEquals("/new/path.txt", formState.copiedFilePath)
        assertEquals("New comments", formState.comments)
    }
    
    @Test
    fun `updateFormData saves to SavedStateHandle`() = runTest {
        val newFormData = TestDataBuilders.createEncryptFormData(
            selectedFilename = "saved.txt",
            copiedFilePath = "/saved/path.txt",
            comments = "Saved comments"
        )
        
        viewModel.updateFormData(newFormData)
        
        assertEquals("saved.txt", savedStateHandle.get<String>("selected_filename"))
        assertEquals("/saved/path.txt", savedStateHandle.get<String>("copied_file_path"))
        assertEquals("Saved comments", savedStateHandle.get<String>("comments"))
    }
    
    @Test
    fun `updateFormData does not save passwords to SavedStateHandle`() = runTest {
        val newFormData = TestDataBuilders.createEncryptFormData(
            password = "secretpassword",
            confirmPassword = "secretpassword"
        )
        
        viewModel.updateFormData(newFormData)
        
        // Passwords should not be in SavedStateHandle
        assertNull(savedStateHandle.get<String>("passwordInput"))
        assertNull(savedStateHandle.get<String>("confirmPasswordInput"))
    }
    
    @Test
    fun `updatePasswords updates password fields`() = runTest {
        val password = "newpassword".toCharArray()
        val confirmPassword = "newpassword".toCharArray()
        
        viewModel.updatePasswords(password, confirmPassword)
        
        val formState = viewModel.formState.first()
        assertTrue("Password should be updated", formState.passwordInput.contentEquals(password))
        assertTrue("Confirm password should be updated", formState.confirmPasswordInput.contentEquals(confirmPassword))
    }
    
    @Test
    fun `updatePasswords clears old password arrays`() = runTest {
        val oldPassword = "oldpassword".toCharArray()
        val oldConfirm = "oldpassword".toCharArray()
        
        viewModel.updatePasswords(oldPassword, oldConfirm)
        
        val newPassword = "newpassword".toCharArray()
        val newConfirm = "newpassword".toCharArray()
        
        // Store references before update
        val formStateBefore = viewModel.formState.first()
        val oldPasswordRef = formStateBefore.passwordInput
        val oldConfirmRef = formStateBefore.confirmPasswordInput
        
        viewModel.updatePasswords(newPassword, newConfirm)
        
        // Old arrays should be cleared
        assertTrue("Old password should be cleared", oldPasswordRef.all { it == '\u0000' })
        assertTrue("Old confirm password should be cleared", oldConfirmRef.all { it == '\u0000' })
    }
    
    @Test
    fun `updatePasswords updates only password when confirmPassword is null`() = runTest {
        val password = "password".toCharArray()
        
        viewModel.updatePasswords(password, null)
        
        val formState = viewModel.formState.first()
        assertTrue("Password should be updated", formState.passwordInput.contentEquals(password))
        // Confirm password should remain unchanged (empty in this case)
        assertEquals(0, formState.confirmPasswordInput.size)
    }
    
    @Test
    fun `updatePasswords updates only confirmPassword when password is null`() = runTest {
        val confirmPassword = "confirm".toCharArray()
        
        viewModel.updatePasswords(null, confirmPassword)
        
        val formState = viewModel.formState.first()
        // Password should remain unchanged (empty in this case)
        assertEquals(0, formState.passwordInput.size)
        assertTrue("Confirm password should be updated", formState.confirmPasswordInput.contentEquals(confirmPassword))
    }

    @Test
    fun `updatePasswords does not restore passwords through SavedStateHandle`() = runTest {
        viewModel.updatePasswords("secretpassword".toCharArray(), "secretpassword".toCharArray())

        val restoredViewModel = MainViewModel(mockApplication, savedStateHandle)
        val restoredFormState = restoredViewModel.formState.first()

        assertEquals(0, restoredFormState.passwordInput.size)
        assertEquals(0, restoredFormState.confirmPasswordInput.size)
    }

    @Test
    fun `passwords are not persisted to saved state`() = runTest {
        // Set a non-empty form (valid encrypt) AND a password through the VM.
        viewModel.updateFormData(
            TestDataBuilders.createEncryptFormData(
                selectedFilename = "secret.txt",
                password = "",
                confirmPassword = ""
            )
        )
        viewModel.updatePasswords(
            password = "secret-pass".toCharArray(),
            confirmPassword = "secret-pass".toCharArray()
        )
        // No SavedStateHandle key may hold the password value. Only file/comment
        // keys are written (KEY_SELECTED_FILENAME, KEY_COPIED_FILE_PATH, KEY_COMMENTS),
        // so this assertion fails if updatePasswords/updateFormData ever wrote the
        // password to any key.
        for (key in savedStateHandle.keys()) {
            val stored = savedStateHandle.get<Any?>(key)
            assertFalse(
                "SavedStateHandle key '$key' must not equal the password",
                stored == "secret-pass"
            )
            if (stored is String) {
                assertFalse(
                    "SavedStateHandle key '$key' must not contain the password",
                    stored.contains("secret-pass")
                )
            }
        }

        // A freshly-constructed VM (modeling process-death recreation from the same
        // handle) must have no password.
        val recreated = MainViewModel(mockApplication, savedStateHandle)
        val recreatedState = recreated.formState.first()
        assertEquals(0, recreatedState.passwordInput.size)
        assertEquals(0, recreatedState.confirmPasswordInput.size)
    }
    
    @Test
    fun `clearSensitiveData clears passwords`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "secret",
            confirmPassword = "secret"
        )
        viewModel.updateFormData(formData)
        
        viewModel.clearSensitiveData(clearFiles = false)
        
        val formState = viewModel.formState.first()
        assertEquals(0, formState.passwordInput.size)
        assertEquals(0, formState.confirmPasswordInput.size)
    }
    
    @Test
    fun `clearSensitiveData clears files when clearFiles is true`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            selectedFilename = "test.txt",
            copiedFilePath = "/path/to/file.txt",
            comments = "Comments"
        )
        viewModel.updateFormData(formData)
        
        viewModel.clearSensitiveData(clearFiles = true)
        
        val formState = viewModel.formState.first()
        assertEquals("", formState.selectedFilename)
        assertEquals("", formState.copiedFilePath)
        assertEquals("", formState.comments)
        assertEquals(emptyList<KeyfileInfo>(), formState.keyfileFilenames)
        assertNull(formState.decryptionInfo)
    }
    
    @Test
    fun `clearSensitiveData preserves files when clearFiles is false`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            selectedFilename = "test.txt",
            copiedFilePath = "/path/to/file.txt",
            comments = "Comments"
        )
        viewModel.updateFormData(formData)
        
        viewModel.clearSensitiveData(clearFiles = false)
        
        val formState = viewModel.formState.first()
        assertEquals("test.txt", formState.selectedFilename)
        assertEquals("/path/to/file.txt", formState.copiedFilePath)
        assertEquals("Comments", formState.comments)
    }
    
    @Test
    fun `clearSensitiveData removes from SavedStateHandle when clearFiles is true`() = runTest {
        savedStateHandle["selected_filename"] = "test.txt"
        savedStateHandle["copied_file_path"] = "/path.txt"
        savedStateHandle["comments"] = "Comments"
        
        viewModel.clearSensitiveData(clearFiles = true)
        
        // updateFormData is called at the end, which sets empty strings
        // So we check for empty strings instead of null
        assertEquals("", savedStateHandle.get<String>("selected_filename"))
        assertEquals("", savedStateHandle.get<String>("copied_file_path"))
        assertEquals("", savedStateHandle.get<String>("comments"))
    }
    
    @Test
    fun `resetFormToDefaults resets all fields`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            comments = "Comments",
            reedSolomon = true,
            paranoid = true,
            deniability = true,
            keyfiles = listOf(TestDataBuilders.createKeyfileInfo()),
            keyfileOrdered = true
        )
        viewModel.updateFormData(formData)
        
        viewModel.resetFormToDefaults()
        
        val formState = viewModel.formState.first()
        assertEquals("", formState.comments)
        assertEquals(0, formState.passwordInput.size)
        assertEquals(0, formState.confirmPasswordInput.size)
        assertEquals(false, formState.reedSolomon)
        assertEquals(false, formState.paranoid)
        assertEquals(false, formState.deniability)
        assertEquals(emptyList<KeyfileInfo>(), formState.keyfileFilenames)
        assertEquals(false, formState.keyfileOrdered)
        assertNull(formState.decryptionInfo)
    }
    
    @Test
    fun `setError sets error message`() = runTest {
        val error = AppError.ValidationError.NoFileSelected
        
        viewModel.setError(error)
        
        val errorMessage = viewModel.errorMessage.first()
        assertEquals(error, errorMessage)
    }
    
    @Test
    fun `clearError clears error message`() = runTest {
        val error = AppError.ValidationError.InvalidPassword
        viewModel.setError(error)
        
        viewModel.clearError()
        
        val errorMessage = viewModel.errorMessage.first()
        assertNull("Error should be cleared", errorMessage)
    }
    
    @Test
    fun `errorMessage is initially null`() = runTest {
        val errorMessage = viewModel.errorMessage.first()
        assertNull("Error message should be null initially", errorMessage)
    }

    @Test
    fun `claimed PCV3 transfers strict request and mutable credentials exactly once`() {
        val source = "/app-private/claimed-input"
        val keyfiles = listOf(
            KeyfileInfo("/app-private/key-b", "key-b"),
            KeyfileInfo("/app-private/duplicate", "duplicate-one"),
            KeyfileInfo("/app-private/duplicate", "duplicate-two"),
            KeyfileInfo("/app-private/key-a", "key-a"),
        )

        viewModel.claimPcv3Normal("misleading.txt", source)
        viewModel.updateFormData(
            viewModel.formState.value.copy(
                pcv3Intent = viewModel.formState.value.pcv3Intent?.copy(
                    action = Pcv3ActionIntent.FORCE_AUTHENTICATED_ONLY,
                ),
            ),
        )
        assertNull(
            "generic form copies must not select a PCV3 operation action",
            viewModel.formState.value.pcv3Intent?.action,
        )
        viewModel.setPcv3Action(Pcv3ActionIntent.FORCE_WITH_UNVERIFIED_CONSENT)
        viewModel.setPcv3FactorPolicy(Pcv3FactorPolicyIntent.PASSWORD_AND_KEYFILES)
        viewModel.setPcv3KeyfileOrder(Pcv3KeyfileOrderIntent.SELECTED)
        viewModel.updateFormData(viewModel.formState.value.copy(keyfileFilenames = keyfiles))
        viewModel.updatePasswords(password = "owned password".toCharArray())
        val ownedPassword = viewModel.formState.value.passwordInput

        val transfer = requireNotNull(viewModel.takePcv3Operation("/app-private/output"))

        assertEquals(Pcv3FormatIntent.NORMAL, transfer.intent.format)
        assertEquals(Pcv3ActionIntent.FORCE_WITH_UNVERIFIED_CONSENT, transfer.intent.action)
        assertEquals("force-unverified-normal", transfer.request.mode)
        assertEquals("password-and-keyfiles", transfer.request.factorPolicy)
        assertEquals("ordered", transfer.request.keyfileOrder)
        assertEquals(source, transfer.request.source)
        assertEquals("/app-private/output", transfer.request.target)
        assertEquals(keyfiles.map(KeyfileInfo::internalPath), transfer.request.keyfiles)
        assertSame("the mutable password owner must move rather than be copied", ownedPassword, transfer.password)
        assertArrayEquals("owned password".toCharArray(), transfer.password)

        val afterTransfer = viewModel.formState.value
        assertEquals("", afterTransfer.selectedFilename)
        assertEquals(0, afterTransfer.passwordInput.size)
        assertTrue(afterTransfer.keyfileFilenames.isEmpty())
        assertFalse(afterTransfer.isPcv3Selection)
        assertFalse(afterTransfer.isEncrypt)
        assertFalse(afterTransfer.isDecrypt)
        assertFalse(afterTransfer.isFormValid)
        assertNull("the content-owned source must not transfer twice", viewModel.takePcv3Operation("/other"))

        transfer.password.fill('\u0000')
    }

    @Test
    fun `replacement releases each app owned legacy and PCV3 source once and zeros credentials`() {
        val legacySource = "/app-private/input_file.txt"
        val pcv3Source = "/app-private/input_file.pcv"
        viewModel.updateFormData(
            TestDataBuilders.createEncryptFormData(
                selectedFilename = "plain.txt",
                copiedFilePath = legacySource,
            ),
        )

        assertEquals(listOf(legacySource), viewModel.resetFormToDefaults())
        viewModel.claimPcv3Normal("volume.bin", pcv3Source)
        viewModel.updatePasswords(
            password = "secret".toCharArray(),
            confirmPassword = "secret".toCharArray(),
        )
        val passwordOwner = viewModel.formState.value.passwordInput
        val confirmationOwner = viewModel.formState.value.confirmPasswordInput

        assertEquals(listOf(pcv3Source), viewModel.resetFormToDefaults())
        assertEquals("the same source must not be released twice", emptyList<String>(), viewModel.resetFormToDefaults())
        assertTrue(passwordOwner.all { it == '\u0000' })
        assertTrue(confirmationOwner.all { it == '\u0000' })
        assertFalse(viewModel.formState.value.isPcv3Selection)
    }

    @Test
    fun `explicit D1 moves one legacy candidate without filename inference or remembered intent`() {
        val source = "/app-private/arbitrary-name.txt"
        viewModel.updateFormData(
            TestDataBuilders.createEncryptFormData(
                selectedFilename = "arbitrary-name.txt",
                copiedFilePath = source,
                password = "",
                confirmPassword = "",
            ),
        )

        viewModel.updatePasswords(confirmPassword = "orphan confirmation".toCharArray())
        assertFalse("D1 must be chosen before either credential field is populated", viewModel.selectPcv3D1())
        viewModel.updatePasswords(confirmPassword = CharArray(0))
        assertTrue(viewModel.selectPcv3D1())
        val selected = viewModel.formState.value
        assertEquals(Pcv3FormatIntent.D1, selected.pcv3Intent?.format)
        assertNull(selected.pcv3Intent?.action)
        assertNull(selected.pcv3Intent?.factorPolicy)
        assertNull(selected.pcv3Intent?.keyfileOrder)
        assertEquals("", selected.copiedFilePath)
        assertTrue(selected.hasSelectedInput)
        assertFalse(selected.isEncrypt)
        assertFalse(selected.isDecrypt)
        assertFalse(selected.isFormValid)
        assertFalse(savedStateHandle.keys().contains("copied_file_path"))

        val recreated = MainViewModel(mockApplication, savedStateHandle).formState.value
        assertFalse("D1 intent must never survive process recreation", recreated.isPcv3Selection)
        assertEquals("", recreated.selectedFilename)
    }

    @Test
    fun `refused PCV3 remains visible and releases its source for immediate cleanup only once`() {
        val source = "/app-private/invalid-claimed-input"
        val error = AppError.OperationError.PCVUnavailable(technicalMessage = "PCV3_INVALID_STRUCTURE")

        assertEquals(
            listOf(source),
            viewModel.retainRefusedPcv3("damaged.bin", source, error),
        )
        viewModel.setPcv3Action(Pcv3ActionIntent.DECRYPT)
        viewModel.setPcv3FactorPolicy(Pcv3FactorPolicyIntent.PASSWORD_ONLY)
        val rejectedPassword = "secret".toCharArray()
        viewModel.updatePasswords(password = rejectedPassword)
        viewModel.updateFormData(
            viewModel.formState.value.copy(
                keyfileFilenames = listOf(KeyfileInfo("/app-private/key", "key")),
            ),
        )

        val refused = viewModel.formState.value
        assertTrue(refused.isPcv3Selection)
        assertTrue(refused.pcvUnavailable)
        assertNull("an unavailable route must not accept action intent", refused.pcv3Intent?.action)
        assertNull("an unavailable route must not accept factor intent", refused.pcv3Intent?.factorPolicy)
        assertFalse("an unavailable route must not retain a password", refused.hasPassword)
        assertTrue("a rejected mutable password must be zeroed", rejectedPassword.all { it == '\u0000' })
        assertTrue("an unavailable route must not retain keyfiles", refused.keyfileFilenames.isEmpty())
        assertFalse(refused.isFormValid)
        assertNull(viewModel.takePcv3Operation("/app-private/output"))
        assertSame(error, viewModel.errorMessage.value)
        assertNull("the refused source was already released for immediate cleanup", viewModel.clearSensitiveData(clearFiles = true))
        assertNull(viewModel.clearSensitiveData(clearFiles = true))
    }

    @Test
    fun `strict transfer preserves each factor policy and unordered duplicate descriptors`() {
        val duplicateKeyfiles = listOf(
            KeyfileInfo("/app-private/key-b", "first"),
            KeyfileInfo("/app-private/key-b", "duplicate"),
            KeyfileInfo("/app-private/key-a", "last"),
        )
        viewModel.claimPcv3Normal("claimed.bin", "/app-private/keyfile-source")
        viewModel.setPcv3Action(Pcv3ActionIntent.DECRYPT)
        viewModel.setPcv3FactorPolicy(Pcv3FactorPolicyIntent.KEYFILES_ONLY)
        viewModel.setPcv3KeyfileOrder(Pcv3KeyfileOrderIntent.ANY)
        viewModel.updateFormData(viewModel.formState.value.copy(keyfileFilenames = duplicateKeyfiles))

        val keyfileTransfer = requireNotNull(viewModel.takePcv3Operation("/app-private/keyfile-output"))
        assertEquals("keyfiles", keyfileTransfer.request.factorPolicy)
        assertEquals("unordered", keyfileTransfer.request.keyfileOrder)
        assertEquals(duplicateKeyfiles.map(KeyfileInfo::internalPath), keyfileTransfer.request.keyfiles)
        assertEquals(0, keyfileTransfer.password.size)

        val passwordViewModel = MainViewModel(mockApplication, SavedStateHandle())
        // A provider display name is untrusted metadata, not start authority.
        passwordViewModel.claimPcv3Normal("", "/app-private/password-source")
        passwordViewModel.setPcv3Action(Pcv3ActionIntent.DECRYPT)
        passwordViewModel.setPcv3FactorPolicy(Pcv3FactorPolicyIntent.PASSWORD_ONLY)
        passwordViewModel.updatePasswords(password = "secret".toCharArray())

        val passwordTransfer = requireNotNull(
            passwordViewModel.takePcv3Operation("/app-private/password-output"),
        )
        assertEquals("password", passwordTransfer.request.factorPolicy)
        assertEquals("none", passwordTransfer.request.keyfileOrder)
        assertTrue(passwordTransfer.request.keyfiles.isEmpty())
        passwordTransfer.password.fill('\u0000')
    }
}
