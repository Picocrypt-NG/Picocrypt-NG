package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import io.mockk.slot
import java.io.File
import kotlin.coroutines.cancellation.CancellationException
import kotlin.io.path.createTempDirectory

/**
 * Unit tests for OperationManager.
 * 
 * Note: OperationManager uses GoBridge and FileCopyService which are objects.
 * Full integration testing requires instrumented tests. These unit tests focus
 * on validation logic and state management that can be tested without full integration.
 */
class OperationManagerTest {
    
    private lateinit var mockContext: Context
    private lateinit var pcv3ReceiptDirectory: File
    private lateinit var pcv3ReceiptFile: File
    
    @Before
    fun setUp() = runTest {
        mockContext = mockk<Context>(relaxed = true)
        pcv3ReceiptDirectory = createTempDirectory(prefix = "pcv3_receipt").toFile()
        pcv3ReceiptFile = File(pcv3ReceiptDirectory, "deny-only.receipt")
        // Clear any existing operation state
        OperationManager.clearOperation(shouldCleanupFiles = false)
    }
    
    @After
    fun tearDown() = runTest {
        // Clean up operation state after each test
        OperationManager.clearOperation(shouldCleanupFiles = false)
        if (::pcv3ReceiptDirectory.isInitialized) pcv3ReceiptDirectory.deleteRecursively()
    }
    
    @Test
    fun `startDecrypt returns error when no file selected`() = runTest {
        val formData = TestDataBuilders.createDecryptFormData(
            copiedFilePath = "" // Empty file path
        )
        
        val result = OperationManager.startDecrypt(mockContext, formData)
        
        assertTrue("Should fail with NoFileSelected", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be NoFileSelected", error is AppError.ValidationError.NoFileSelected)
        }
    }
    
    @Test
    fun `startDecrypt returns error when password invalid`() = runTest {
        val formData = FormData(
            selectedFilename = "test.pcv",
            copiedFilePath = "/path/to/file.pcv",
            passwordInput = CharArray(0), // Empty password
            confirmPasswordInput = CharArray(0),
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false
        )
        
        val result = OperationManager.startDecrypt(mockContext, formData)
        
        assertTrue("Should fail with InvalidPassword", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be InvalidPassword", error is AppError.ValidationError.InvalidPassword)
        }
    }

    @Test
    fun `startDecrypt passes legacy deniable keyfile-only credentials to Go`() = runTest {
        val tmpDir = createTempDirectory(prefix = "opmgr_legacy_deniable_decrypt").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_legacy_decrypt")
            val passwordSlot = slot<ByteArray>()
            val optionsSlot = slot<DecryptOptions>()
            every {
                GoBridge.startDecrypt(
                    any(),
                    any(),
                    any(),
                    capture(passwordSlot),
                    capture(optionsSlot),
                )
            } returns Result.success(Unit)

            val keyfile = TestDataBuilders.createKeyfileInfo(
                internalPath = "/data/test/keyfile_0",
            )
            val result = OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData(
                    password = "",
                    keyfiles = listOf(keyfile),
                    decryptionInfo = TestDataBuilders.createDecryptionInfo(
                        keyfilesRequired = true,
                        deniability = true,
                        readable = false,
                    ),
                ),
            )

            assertTrue("legacy keyfile-only deniable decryption should start", result.isSuccess)
            assertTrue("legacy empty outer password must reach the reader", passwordSlot.captured.isEmpty())
            assertEquals(listOf(keyfile.internalPath), optionsSlot.captured.keyfiles)
            assertTrue(optionsSlot.captured.deniability)
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `startDecrypt does not invoke Go when pre-start cleanup fails`() = runTest {
        mockkObject(FileCopyService)
        mockkObject(GoBridge)
        try {
            coEvery {
                FileCopyService.cleanupOperationFilesBeforeStart(mockContext)
            } returns false
            every {
                FileCopyService.getOutputFilePath(mockContext, any(), isEncrypt = false)
            } returns "/output"
            every { GoBridge.startOperation() } returns Result.success("must_not_start")
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), any())
            } returns Result.success(Unit)

            val result = OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData(),
            )

            verify(exactly = 0) { GoBridge.startOperation() }
            verify(exactly = 0) {
                GoBridge.startDecrypt(any(), any(), any(), any(), any())
            }
            assertTrue("Cleanup failure must fail the operation start", result.isFailure)
            assertTrue(
                "Cleanup failure must surface as a file deletion error",
                result.exceptionOrNull() is AppError.FileError.DeleteFailed,
            )
        } finally {
            unmockkObject(GoBridge)
            unmockkObject(FileCopyService)
        }
    }
    
    @Test
    fun `cancelOperation returns error when no active operation`() = runTest {
        // Ensure no operation is active
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.cancelOperation()
        
        assertTrue("Should fail with no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
            assertEquals(R.string.error_no_active_operation, (error as AppError).messageResId)
        }
    }

    @Test
    fun `cancelOperation preserves the terminal state returned by Go`() = runTest {
        setCurrentOperationForTest(
            TestDataBuilders.createOperationState(
                id = "op_completed",
                status = OperationStatusData(OperationStatus.ENCRYPTING_RATE),
                progress = 0.9f,
                done = false,
            )
        )

        mockkObject(GoBridge)
        try {
            every { GoBridge.cancelOperation("op_completed") } returns Result.success(
                ProgressState(
                    status = OperationStatusData(OperationStatus.COMPLETED),
                    detail = OperationProgressDetail(OperationProgress.NONE),
                    progress = 1f,
                    done = true,
                )
            )

            val result = OperationManager.cancelOperation()
            val state = OperationManager.currentOperation.value

            assertTrue("Cancel request should succeed", result.isSuccess)
            assertEquals(OperationStatus.COMPLETED, state?.status?.code)
            assertEquals(1f, state?.progress ?: -1f, 0.001f)
            assertTrue("Native terminal state must remain terminal", state?.done == true)
        } finally {
            unmockkObject(GoBridge)
        }
    }

    @Test
    fun `cancelOperation classifies a terminal error returned by Go`() = runTest {
        setCurrentOperationForTest(
            TestDataBuilders.createOperationState(
                id = "op_failed",
                type = OperationType.DECRYPT,
                done = false,
            )
        )

        mockkObject(GoBridge)
        try {
            every { GoBridge.cancelOperation("op_failed") } returns Result.success(
                ProgressState(
                    status = OperationStatusData(OperationStatus.ERROR),
                    detail = OperationProgressDetail(OperationProgress.NONE),
                    progress = 0.4f,
                    done = true,
                    technicalError = "diagnostic auth failure",
                    errorCode = "AUTH_FAILED",
                )
            )

            val result = OperationManager.cancelOperation()
            val state = OperationManager.currentOperation.value

            assertTrue("Cancel request should return the native terminal snapshot", result.isSuccess)
            assertEquals(OperationStatus.ERROR, state?.status?.code)
            assertTrue(state?.error is AppError.OperationError.PasswordAuth)
            assertEquals("diagnostic auth failure", state?.error?.technicalMessage)
        } finally {
            unmockkObject(GoBridge)
        }
    }

    @Test
    fun `cancelOperation does not overwrite a concurrently replaced operation`() = runTest {
        setCurrentOperationForTest(
            TestDataBuilders.createOperationState(id = "op_old", done = false)
        )
        val replacement = TestDataBuilders.createOperationState(
            id = "op_new",
            status = OperationStatusData(OperationStatus.STARTING),
            done = false,
        )

        mockkObject(GoBridge)
        try {
            every { GoBridge.cancelOperation("op_old") } answers {
                setCurrentOperationForTest(replacement)
                Result.success(
                    ProgressState(
                        status = OperationStatusData(OperationStatus.CANCELLED),
                        detail = OperationProgressDetail(OperationProgress.NONE),
                        progress = 0f,
                        done = true,
                    )
                )
            }

            val result = OperationManager.cancelOperation()

            assertTrue("Cancel request should succeed", result.isSuccess)
            assertSame(
                "A newer operation must not be clobbered by an older cancel response",
                replacement,
                OperationManager.currentOperation.value,
            )
        } finally {
            unmockkObject(GoBridge)
        }
    }
    
    @Test
    fun `pollProgress returns null when no active operation`() = runTest {
        // Ensure no operation is active
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.pollProgress()
        
        assertNull("Should return null when no operation", result)
    }

    @Test
    fun `pollProgress projects semantic status and detail into operation state`() = runTest {
        val status = OperationStatusData(
            OperationStatus.ENCRYPTING_RATE,
            speedMiBPerSecond = 12.34,
            eta = "01:02:03",
        )
        val detail = OperationProgressDetail("ITEM_COUNT", current = 3, total = 10)
        setCurrentOperationForTest(
            TestDataBuilders.createOperationState(
                id = "op_semantic",
                status = OperationStatusData(OperationStatus.STARTING),
                detail = OperationProgressDetail("NONE"),
                progress = 0f,
            )
        )

        mockkObject(GoBridge)
        try {
            every { GoBridge.getProgress("op_semantic") } returns Result.success(
                ProgressState(status, detail, progress = 0.3f, done = false)
            )

            val result = OperationManager.pollProgress()

            assertEquals(status, result?.status)
            assertEquals(detail, result?.detail)
            assertEquals(0.3f, result?.progress ?: -1f, 0.001f)
        } finally {
            unmockkObject(GoBridge)
        }
    }

    @Test
    fun `raw cancelled diagnostic cannot override a non-cancelled semantic status`() = runTest {
        setCurrentOperationForTest(
            TestDataBuilders.createOperationState(
                id = "op_not_cancelled",
                status = OperationStatusData(OperationStatus.STARTING),
                done = false,
            )
        )

        mockkObject(GoBridge)
        try {
            every { GoBridge.getProgress("op_not_cancelled") } returns Result.success(
                ProgressState(
                    status = OperationStatusData(OperationStatus.UNKNOWN),
                    detail = OperationProgressDetail("NONE"),
                    progress = 1f,
                    done = true,
                    technicalError = "Cancelled",
                    errorCode = "CANCELLED",
                )
            )

            val result = OperationManager.pollProgress()

            assertNull("Non-ERROR semantic status must not create an AppError", result?.error)
            assertEquals(OperationUiState.Success(OperationType.ENCRYPT), result.toUiState())
        } finally {
            unmockkObject(GoBridge)
        }
    }

    @Test
    fun `semantic error status classifies the distinct technical error and code`() = runTest {
        setCurrentOperationForTest(
            TestDataBuilders.createOperationState(
                id = "op_error",
                type = OperationType.DECRYPT,
                status = OperationStatusData(OperationStatus.STARTING),
                done = false,
            )
        )

        mockkObject(GoBridge)
        try {
            every { GoBridge.getProgress("op_error") } returns Result.success(
                ProgressState(
                    status = OperationStatusData(OperationStatus.ERROR),
                    detail = OperationProgressDetail("NONE"),
                    progress = 0.4f,
                    done = true,
                    technicalError = "diagnostic auth failure",
                    errorCode = "AUTH_FAILED",
                )
            )

            val result = OperationManager.pollProgress()

            assertTrue(result?.error is AppError.OperationError.PasswordAuth)
            assertEquals("diagnostic auth failure", result?.error?.technicalMessage)
        } finally {
            unmockkObject(GoBridge)
        }
    }
    
    @Test
    fun `pollProgress does not overwrite a terminal (done) state with a stale poll`() = runTest {
        // GoBridge is an object backed by the Go mobile AAR, which is absent on the JVM
        // unit-test classpath. Mock it so we can (a) drive _currentOperation to a real
        // done=true state via the only public seam (startDecrypt + pollProgress), then
        // (b) prove the done-guard rejects a later stale poll. This is the narrowest
        // reachable level: there is no public setter for _currentOperation.
        // startDecrypt resolves an output path under context.filesDir; the relaxed mock
        // returns null for it, so back it with a real temp dir.
        val tmpDir = createTempDirectory(prefix = "opmgr_test").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_test")
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), any())
            } returns Result.success(Unit)

            // Establish an active (non-done) operation.
            val started = OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData()
            )
            assertTrue("startDecrypt should succeed", started.isSuccess)

            // First poll transitions the operation to a terminal done=true state.
            every { GoBridge.getProgress("op_test") } returns Result.success(
                ProgressState(
                    status = OperationStatusData(OperationStatus.COMPLETED),
                    detail = OperationProgressDetail("NONE"),
                    progress = 1f,
                    done = true,
                )
            )
            val terminal = OperationManager.pollProgress()
            assertNotNull("Poll should return the terminal state", terminal)
            assertTrue("State should be done after terminal poll", terminal!!.done)

            // A later (slow/concurrent) poll reports a stale, non-terminal progress.
            every { GoBridge.getProgress("op_test") } returns Result.success(
                ProgressState(
                    status = OperationStatusData(OperationStatus.UNKNOWN),
                    detail = OperationProgressDetail("UNKNOWN"),
                    progress = 0.42f,
                    done = false,
                )
            )
            val afterStale = OperationManager.pollProgress()

            // The done-guard must keep the terminal state intact, not regress it.
            assertNotNull(afterStale)
            assertTrue("Done flag must remain true", afterStale!!.done)
            assertEquals(
                "Status must not regress",
                OperationStatusData(OperationStatus.COMPLETED),
                afterStale.status,
            )
            assertEquals("Progress must not regress", 1f, afterStale.progress, 0.001f)
            assertSame(
                "Terminal state must be returned unchanged",
                terminal,
                afterStale
            )
            assertSame(
                "currentOperation must still hold the terminal state",
                terminal,
                OperationManager.currentOperation.value
            )
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `pollProgress does not resurrect a concurrently-cleared operation`() = runTest {
        // RACE: the FGS (1000ms) and the ViewModel (500ms) both poll concurrently.
        // pollProgress is a read-modify-write: it captures _currentOperation, then
        // suspends in GoBridge.getProgress (I/O). If another coroutine calls
        // clearOperation() during that window (_currentOperation -> null), an
        // UNCONDITIONAL write of the captured op would RESURRECT the cleared op as a
        // phantom non-done state. The write must no-op instead.
        //
        // Deterministic, not timing-based: model the concurrent clear as a SIDE EFFECT
        // of the getProgress stub -- it nulls _currentOperation (exactly what
        // clearOperation does to the flow; done directly because clearOperation is a
        // suspend fun and the MockK answers block is not a coroutine body), THEN
        // returns a non-done progress. After pollProgress, _currentOperation must
        // still be null. GoBridge is the Go mobile AAR (absent on the JVM classpath),
        // so mock it. startDecrypt resolves an output path under context.filesDir;
        // back it with a real temp dir since the relaxed mock returns null.
        val tmpDir = createTempDirectory(prefix = "opmgr_resurrect_test").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_clear")
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), any())
            } returns Result.success(Unit)

            // Establish an active (non-done) operation through the public seam.
            val started = OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData()
            )
            assertTrue("startDecrypt should succeed", started.isSuccess)
            assertNotNull("operation should be active", OperationManager.currentOperation.value)

            val stateField = OperationManager::class.java.getDeclaredField("_currentOperation")
            stateField.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val flow = stateField.get(OperationManager)
                as kotlinx.coroutines.flow.MutableStateFlow<OperationState?>

            // getProgress simulates a concurrent clear during its I/O, then returns a
            // live, non-terminal progress for the now-stale captured operation.
            every { GoBridge.getProgress("op_clear") } answers {
                flow.value = null
                Result.success(
                    ProgressState(
                        status = OperationStatusData(OperationStatus.ENCRYPTING_RATE, 12.34, "01:02:03"),
                        detail = OperationProgressDetail("NONE"),
                        progress = 0.5f,
                        done = false,
                    )
                )
            }

            val result = OperationManager.pollProgress()

            assertNull("Cleared operation must not be resurrected (return)", result)
            assertNull(
                "Cleared operation must not be resurrected (currentOperation)",
                OperationManager.currentOperation.value
            )
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `pollProgress does not clobber a replaced operation`() = runTest {
        // Same race window, different concurrent action: instead of clearing,
        // another coroutine REPLACES _currentOperation with a different-id op (e.g. a
        // new operation started while a slow poll was in flight). The unconditional
        // write of the captured op would clobber the newer op; the id-guard must
        // leave the replacement untouched.
        val tmpDir = createTempDirectory(prefix = "opmgr_clobber_test").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_old")
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), any())
            } returns Result.success(Unit)

            val started = OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData()
            )
            assertTrue("startDecrypt should succeed", started.isSuccess)

            // A different-id operation installed concurrently during getProgress I/O.
            val replacement = TestDataBuilders.createOperationState(
                id = "op_new",
                type = OperationType.ENCRYPT,
                status = OperationStatusData(OperationStatus.STARTING),
                progress = 0f,
                done = false
            )
            val stateField = OperationManager::class.java.getDeclaredField("_currentOperation")
            stateField.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val flow = stateField.get(OperationManager)
                as kotlinx.coroutines.flow.MutableStateFlow<OperationState?>

            every { GoBridge.getProgress("op_old") } answers {
                flow.value = replacement
                Result.success(
                    ProgressState(
                        status = OperationStatusData(OperationStatus.ENCRYPTING_RATE, 12.34, "01:02:03"),
                        detail = OperationProgressDetail("NONE"),
                        progress = 0.5f,
                        done = false,
                    )
                )
            }

            val result = OperationManager.pollProgress()

            assertSame("Replacement op must be returned unchanged", replacement, result)
            assertSame(
                "currentOperation must still hold the replacement op",
                replacement,
                OperationManager.currentOperation.value
            )
            assertEquals("Replacement id must be intact", "op_new", result!!.id)
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `clearOperation clears passwords from form data`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "testpassword",
            confirmPassword = "testpassword"
        )
        val operationState = TestDataBuilders.createOperationState(
            formData = formData
        )
        assertTrue("password precondition should contain non-zero chars", formData.passwordInput.any { it != '\u0000' })
        assertTrue("confirm precondition should contain non-zero chars", formData.confirmPasswordInput.any { it != '\u0000' })

        val stateField = OperationManager::class.java.getDeclaredField("_currentOperation")
        stateField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val flow = stateField.get(OperationManager)
            as kotlinx.coroutines.flow.MutableStateFlow<OperationState?>
        flow.value = operationState

        OperationManager.clearOperation(shouldCleanupFiles = false)

        assertNull("Operation should be null after clearing", OperationManager.currentOperation.first())
        assertTrue("Password should be cleared by OperationManager.clearOperation", formData.passwordInput.all { it == '\u0000' })
        assertTrue("Confirm password should be cleared by OperationManager.clearOperation", formData.confirmPasswordInput.all { it == '\u0000' })
    }

    @Test
    fun `clearOperation keeps selection closed while owned cleanup is suspended`() = runTest {
        val filesDir = createTempDirectory(prefix = "opmgr_clear_owned").toFile()
        val source = File(filesDir, "picocrypt_files/input_file.pcv")
        val staged = File(filesDir, "picocrypt_files/staging/plaintext.txt")
        val cleanupEntered = CompletableDeferred<Unit>()
        val cleanupRelease = CompletableDeferred<Unit>()
        every { mockContext.filesDir } returns filesDir
        mockkObject(GoBridge, FileCopyService)
        every { GoBridge.startOperation() } returns Result.success("owned-cleanup")
        every { GoBridge.startDecrypt(any(), any(), any(), any(), any()) } returns Result.success(Unit)
        coEvery { FileCopyService.cleanupOperationFiles(any(), any(), any(), any()) } coAnswers {
            cleanupEntered.complete(Unit)
            cleanupRelease.await()
            source.delete()
        }
        try {
            assertTrue(source.parentFile!!.mkdirs())
            source.writeText("old encrypted input")
            assertTrue(OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData(copiedFilePath = source.absolutePath),
            ).isSuccess)
            assertTrue(staged.parentFile!!.mkdirs())
            staged.writeText("old staged plaintext")
            val cleaning = async(start = CoroutineStart.UNDISPATCHED) {
                OperationManager.clearOperation(mockContext)
            }
            cleanupEntered.await()
            val dismissing = async(start = CoroutineStart.UNDISPATCHED) {
                OperationManager.clearOperation(shouldCleanupFiles = false)
            }
            try {
                assertEquals(
                    "A duplicate dismissal must not enable a new selection before old cleanup ends",
                    "owned-cleanup",
                    OperationManager.currentOperation.value?.id,
                )
                assertTrue("The blocked owner has not removed its plaintext yet", staged.exists())
            } finally {
                cleanupRelease.complete(Unit)
                cleaning.await()
                dismissing.await()
            }
            assertNull(OperationManager.currentOperation.value)
            assertFalse("The owner must finish its actual staging cleanup", staged.exists())
        } finally {
            cleanupRelease.complete(Unit)
            unmockkObject(GoBridge, FileCopyService)
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun `clearOperation retains failed state and still wipes staging when an operation file cannot be deleted`() = runTest {
        val filesDir = createTempDirectory(prefix = "opmgr_clear_file_failure").toFile()
        val sourceDir = java.io.File(filesDir, "source")
        val inputFile = java.io.File(sourceDir, "plaintext.txt")
        val stagedFile = java.io.File(filesDir, "picocrypt_files/staging/copy.txt")
        val formData = TestDataBuilders.createEncryptFormData(
            copiedFilePath = inputFile.absolutePath,
            password = "testpassword",
            confirmPassword = "testpassword",
        )
        val operationState = TestDataBuilders.createOperationState(
            inputFile = inputFile.absolutePath,
            formData = formData,
        )
        every { mockContext.filesDir } returns filesDir

        val stateField = OperationManager::class.java.getDeclaredField("_currentOperation")
        stateField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val flow = stateField.get(OperationManager)
            as kotlinx.coroutines.flow.MutableStateFlow<OperationState?>
        flow.value = operationState

        try {
            assertTrue(sourceDir.mkdirs())
            inputFile.writeText("original plaintext")
            assertTrue(stagedFile.parentFile!!.mkdirs())
            stagedFile.writeText("staged plaintext")
            assertTrue(sourceDir.setWritable(false, false))

            val failed = OperationManager.clearOperation(mockContext, shouldCleanupFiles = true)

            assertTrue("A real deletion failure must be returned", failed.isFailure)
            assertTrue(
                "Cleanup failure must keep its typed error",
                failed.exceptionOrNull() is AppError.FileError.DeleteFailed,
            )
            assertNotNull(
                "Operation state must remain so cleanup can be retried",
                OperationManager.currentOperation.value,
            )
            assertTrue(
                "The retained state must visibly surface cleanup failure",
                OperationManager.currentOperation.value?.error is AppError.FileError.DeleteFailed,
            )
            assertTrue("The undeletable operation input must remain", inputFile.exists())
            assertFalse(
                "Staging cleanup must still run even when operation-file cleanup fails",
                java.io.File(filesDir, "picocrypt_files/staging").exists(),
            )
            assertTrue("Passwords must still be zeroed on cleanup failure", formData.passwordInput.all { it == '\u0000' })

            assertTrue(sourceDir.setWritable(true, false))
            val retried = OperationManager.clearOperation(mockContext, shouldCleanupFiles = true)
            assertTrue("Cleanup must be retryable after the filesystem problem is fixed", retried.isSuccess)
            assertFalse("The real input must be deleted by the successful retry", inputFile.exists())
            assertNull("Successful retry must finally clear operation state", OperationManager.currentOperation.value)
        } finally {
            sourceDir.setWritable(true, false)
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun `clearOperation retains failed state when real staging plaintext cannot be deleted`() = runTest {
        val filesDir = createTempDirectory(prefix = "opmgr_clear_staging_failure").toFile()
        val internalDir = java.io.File(filesDir, "picocrypt_files")
        val stagingDir = java.io.File(internalDir, "staging")
        val stagedFile = java.io.File(stagingDir, "plaintext.txt")
        val formData = TestDataBuilders.createEncryptFormData(
            password = "testpassword",
            confirmPassword = "testpassword",
        )
        val operationState = TestDataBuilders.createOperationState(formData = formData)
        every { mockContext.filesDir } returns filesDir

        val stateField = OperationManager::class.java.getDeclaredField("_currentOperation")
        stateField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val flow = stateField.get(OperationManager)
            as kotlinx.coroutines.flow.MutableStateFlow<OperationState?>
        flow.value = operationState

        try {
            assertTrue(stagingDir.mkdirs())
            stagedFile.writeText("staged plaintext")
            assertTrue(stagingDir.setWritable(false, false))
            assertTrue(internalDir.setWritable(false, false))

            val failed = OperationManager.clearOperation(mockContext, shouldCleanupFiles = true)

            assertTrue("A real staging deletion failure must be returned", failed.isFailure)
            assertTrue(failed.exceptionOrNull() is AppError.FileError.DeleteFailed)
            assertTrue("The undeletable plaintext proves cleanup failed", stagedFile.exists())
            assertTrue(
                "The retained state must let the user retry cleanup",
                OperationManager.currentOperation.value?.error is AppError.FileError.DeleteFailed,
            )

            stagingDir.setWritable(true, false)
            internalDir.setWritable(true, false)
            val retried = OperationManager.clearOperation(mockContext, shouldCleanupFiles = true)
            assertTrue("Cleanup must succeed after permissions are restored", retried.isSuccess)
            assertFalse("The staged plaintext must be gone after retry", stagedFile.exists())
            assertNull(OperationManager.currentOperation.value)
        } finally {
            stagingDir.setWritable(true, false)
            internalDir.setWritable(true, false)
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun `clearOperation fails loud without context when cleanup was requested`() = runTest {
        val operationState = TestDataBuilders.createOperationState(
            formData = TestDataBuilders.createEncryptFormData(),
        )
        val stateField = OperationManager::class.java.getDeclaredField("_currentOperation")
        stateField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val flow = stateField.get(OperationManager)
            as kotlinx.coroutines.flow.MutableStateFlow<OperationState?>
        flow.value = operationState

        val result = OperationManager.clearOperation(context = null, shouldCleanupFiles = true)

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is AppError.FileError.DeleteFailed)
        assertNotNull("State must remain when requested cleanup cannot run", OperationManager.currentOperation.value)
    }
    
    @Test
    fun `retryDecryptWithForce returns error when no active operation`() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.retryDecryptWithForce(mockContext)
        
        assertTrue("Should fail with no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
            assertEquals(R.string.error_no_active_operation, (error as AppError).messageResId)
        }
    }
    
    @Test
    fun `retryDecryptWithForce fails loud when stored formData has an empty password`() = runTest {
        // Force-decrypt BYPASSES integrity/RS checks, so running without either
        // credential after the stored password was cleared would silently produce
        // garbage. GoBridge is the Go mobile AAR (absent on the JVM classpath), so
        // mock it -- the guard must short-circuit before a retry reaches Go.
        val tmpDir = createTempDirectory(prefix = "opmgr_force_test").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_force")
            every { GoBridge.startDecrypt(any(), any(), any(), any(), any()) } returns Result.success(Unit)

            // Establish an active DECRYPT operation with a valid password.
            val started = OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData()
            )
            assertTrue("startDecrypt should succeed", started.isSuccess)

            val established = OperationManager.currentOperation.value
            assertNotNull("operation should be established", established)
            val clearedForm = established!!.formData!!
            clearedForm.clearPasswords()
            assertTrue(
                "real clearPasswords keeps allocated password storage",
                clearedForm.passwordInput.isNotEmpty(),
            )
            assertTrue(
                "real clearPasswords must overwrite every password character",
                clearedForm.passwordInput.all { it == '\u0000' },
            )
            assertFalse("cleared formData without keyfiles must be invalid", clearedForm.isPasswordValid)

            val result = OperationManager.retryDecryptWithForce(mockContext)

            assertTrue("Force-decrypt with an empty password must fail loud", result.isFailure)
            result.onFailure { error ->
                assertTrue(
                    "Error should be InvalidPassword",
                    error is AppError.ValidationError.InvalidPassword
                )
            }

            // The guard must short-circuit before touching the Go bridge on the retry:
            // exactly one startOperation + one startDecrypt, both from the setup call.
            verify(exactly = 1) { GoBridge.startOperation() }
            verify(exactly = 1) { GoBridge.startDecrypt(any(), any(), any(), any(), any()) }
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `retryDecryptWithForce does not invoke Go when real pre-start cleanup fails`() = runTest {
        val tmpDir = createTempDirectory(prefix = "opmgr_force_cleanup_failure").toFile()
        val internalDir = java.io.File(tmpDir, "picocrypt_files")
        val staleIncomplete = java.io.File(internalDir, "stale-retry.incomplete")
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_force_cleanup")
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), any())
            } returns Result.success(Unit)

            assertTrue(
                "A valid decrypt must establish the failed operation being retried",
                OperationManager.startDecrypt(
                    mockContext,
                    TestDataBuilders.createDecryptFormData(),
                ).isSuccess,
            )
            assertTrue("Test setup should create the runtime directory", internalDir.mkdirs())
            staleIncomplete.writeBytes(byteArrayOf(1))
            assertTrue(
                "Test setup should make the runtime directory read-only",
                internalDir.setWritable(false, false),
            )

            val result = OperationManager.retryDecryptWithForce(mockContext)

            assertTrue("A pre-start cleanup failure must stop force-decrypt retry", result.isFailure)
            assertTrue(
                "Force-retry cleanup failure must retain the typed deletion error",
                result.exceptionOrNull() is AppError.FileError.DeleteFailed,
            )
            assertTrue(
                "The undeletable file proves that production cleanup really failed",
                staleIncomplete.exists(),
            )
            verify(exactly = 1) { GoBridge.startOperation() }
            verify(exactly = 1) {
                GoBridge.startDecrypt(any(), any(), any(), any(), any())
            }
        } finally {
            internalDir.setWritable(true, false)
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `retryDecryptWithForce returns error when operation is not decrypt`() = runTest {
        // The guard at OperationManager.retryDecryptWithForce rejects a non-DECRYPT
        // operation (operation.type != DECRYPT -> GenericOperation with
        // error_decrypt_retry_only). It short-circuits BEFORE any decrypt-side GoBridge
        // call, so the Go AAR is not needed — establish an ENCRYPT op through the public
        // seam (GoBridge mocked) and assert the rejection. startDecrypt resolves an
        // output path under context.filesDir; back it with a real temp dir.
        val tmpDir = createTempDirectory(prefix = "opmgr_notdecrypt").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_enc")
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), any())
            } returns Result.success(Unit)

            setCurrentOperationForTest(TestDataBuilders.createOperationState(id = "op_enc", type = OperationType.ENCRYPT))
            assertEquals(OperationType.ENCRYPT, OperationManager.currentOperation.value?.type)

            val result = OperationManager.retryDecryptWithForce(mockContext)

            assertTrue("Force-decrypt retry on an encrypt op must fail", result.isFailure)
            result.onFailure { error ->
                assertTrue(
                    "Error should be GenericOperation",
                    error is AppError.OperationError.GenericOperation
                )
                assertEquals(R.string.error_decrypt_retry_only, (error as AppError).messageResId)
            }
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }
    
    @Test
    fun `OperationState has correct structure`() {
        val formData = TestDataBuilders.createEncryptFormData()
        val status = OperationStatusData(OperationStatus.ENCRYPTING_RATE, 12.34, "01:02:03")
        val detail = OperationProgressDetail("ITEM_COUNT", 3, 10)
        val operationState = TestDataBuilders.createOperationState(
            id = "op_123",
            type = OperationType.ENCRYPT,
            inputFile = "/input.txt",
            outputFile = "/output.pcv",
            status = status,
            detail = detail,
            progress = 0.5f,
            done = false,
            formData = formData
        )
        
        assertEquals("op_123", operationState.id)
        assertEquals(OperationType.ENCRYPT, operationState.type)
        assertEquals("/input.txt", operationState.inputFile)
        assertEquals("/output.pcv", operationState.outputFile)
        assertEquals(status, operationState.status)
        assertEquals(0.5f, operationState.progress, 0.001f)
        assertEquals(detail, operationState.detail)
        assertEquals(false, operationState.done)
        assertEquals(formData, operationState.formData)
    }
    
    @Test
    fun `OperationType enum values are correct`() {
        assertEquals("ENCRYPT", OperationType.ENCRYPT.name)
        assertEquals("DECRYPT", OperationType.DECRYPT.name)
    }

    @Test
    fun `startDecrypt passes verifyFirst from formData into DecryptOptions`() = runTest {
        // verifyFirst is a security option (integrity-verify-before-write). It is wired
        // through the Go bridge (GoBridge.DecryptOptions.verifyFirst -> android.go) but
        // OperationManager historically hardcoded it false. Capture the DecryptOptions
        // handed to GoBridge.startDecrypt and prove the form value flows through.
        // GoBridge is the Go mobile AAR (absent on the JVM classpath), so mock it;
        // startDecrypt resolves an output path under context.filesDir, so back it with
        // a real temp dir (the relaxed mock returns null otherwise).
        val tmpDir = createTempDirectory(prefix = "opmgr_verifyfirst").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_vf")
            val optionsSlot = slot<DecryptOptions>()
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), capture(optionsSlot))
            } returns Result.success(Unit)

            val formData = TestDataBuilders.createDecryptFormData().copy(verifyFirst = true)
            val result = OperationManager.startDecrypt(mockContext, formData)

            assertTrue("startDecrypt should succeed", result.isSuccess)
            assertTrue("DecryptOptions must be captured", optionsSlot.isCaptured)
            assertTrue(
                "verifyFirst must flow from formData into the Go bridge call",
                optionsSlot.captured.verifyFirst
            )
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `startDecrypt does not auto-unzip so zip volumes stay exportable`() = runTest {
        // INTEROP (core value): a desktop volume made from multiple files / compression
        // decrypts to a .zip. Go's auto-unzip extracts to a SUBDIRECTORY and DELETES the
        // zip (decrypt.go:816,847); Android then exports a single fixed output path, so
        // the export reads a now-missing/directory path -> SaveFailed. Until a SAF
        // tree-export exists, Android must NOT auto-unzip: the intact .zip stays the one
        // exportable output (matches the CLI --auto-unzip default of false, decrypt.go:94).
        // Capture the DecryptOptions handed to the Go bridge and prove autoUnzip is off.
        val tmpDir = createTempDirectory(prefix = "opmgr_autounzip").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_unzip")
            val optionsSlot = slot<DecryptOptions>()
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), capture(optionsSlot))
            } returns Result.success(Unit)

            val result = OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData()
            )

            assertTrue("startDecrypt should succeed", result.isSuccess)
            assertTrue("DecryptOptions must be captured", optionsSlot.isCaptured)
            assertFalse(
                "auto-unzip must be OFF on Android (no SAF tree-export; the zip volume must stay exportable)",
                optionsSlot.captured.autoUnzip
            )
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `retryDecryptWithForce does not auto-unzip`() = runTest {
        // Same interop invariant as startDecrypt, on the force-decrypt retry path
        // (retryDecryptWithForce builds its own DecryptOptions). The slot captures the
        // last GoBridge.startDecrypt call -- the retry -- which must set forceDecrypt
        // (proving it is the retry) and keep autoUnzip off.
        val tmpDir = createTempDirectory(prefix = "opmgr_autounzip_force").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_unzip_force")
            val optionsSlot = slot<DecryptOptions>()
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), capture(optionsSlot))
            } returns Result.success(Unit)

            assertTrue(
                "startDecrypt setup should succeed",
                OperationManager.startDecrypt(
                    mockContext,
                    TestDataBuilders.createDecryptFormData()
                ).isSuccess
            )
            val retry = OperationManager.retryDecryptWithForce(mockContext)

            assertTrue("retryDecryptWithForce should succeed", retry.isSuccess)
            assertTrue("DecryptOptions must be captured", optionsSlot.isCaptured)
            assertTrue("retry path must set forceDecrypt", optionsSlot.captured.forceDecrypt)
            assertFalse(
                "auto-unzip must be OFF on the force-retry path too",
                optionsSlot.captured.autoUnzip
            )
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `startDecrypt fails loud on a split-volume chunk`() = runTest {
        // A desktop split volume selected on Android (secret.pcv.0) cannot be decrypted
        // without recombining its sibling chunks, which Android has no way to supply.
        // Fail loud instead of running the Go op on one chunk (confusing corrupt error).
        mockkObject(GoBridge)
        try {
            val formData = TestDataBuilders.createDecryptFormData(
                selectedFilename = "secret.pcv.0",
                copiedFilePath = "/data/test/input_file"
            )
            val result = OperationManager.startDecrypt(mockContext, formData)

            assertTrue("Split chunk must fail", result.isFailure)
            result.onFailure {
                assertTrue(
                    "Error should be SplitVolumeNotSupported",
                    it is AppError.ValidationError.SplitVolumeNotSupported
                )
            }
            verify(exactly = 0) { GoBridge.startOperation() }
        } finally {
            unmockkObject(GoBridge)
        }
    }

    @Test
    fun `PCV3 clean retained output stays live and blocks release`() = runTest {
        val operation = ContractOperation("pcv3-output-pending", pcv3CleanSnapshot())
        val output = ContractOutput(operation)
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        val presentation = lifecycle.start(
            pcv3Request(),
            "password".toCharArray(),
            pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Live

        assertTrue("the authority-free scalar must expose the exact pending decision", presentation.outputPending)
        assertFalse(presentation.outputActionInFlight)
        assertSame(output, presentation.outputHandle)
        assertEquals("Release must remain last while output authority is live", 0, operation.releaseCalls)

        val refreshed = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Live
        assertTrue(refreshed.outputPending)
        assertEquals(0, operation.releaseCalls)
    }

    @Test
    fun `PCV3 failed ciphertext save retains the exact capability for another destination`() = runTest {
        val operation = ContractOperation("pcv3-ciphertext-retry", pcv3CleanSnapshot())
        val output = ContractOutput(operation, saveResult = Pcv3OutputResultData("save-failed", false),
            retainAfterSaveForContradiction = true)
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val live = lifecycle.start(
            Pcv3WriteRequest("write-normal", "password", "none", "input", "output", emptyList(), "", "standard", false),
            "password".toCharArray(), pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Live
        lifecycle.savePcv3Output(live.operationId, live.generation, mockk(relaxed = true))
        val retry = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Live
        assertSame(output, retry.outputHandle)
        assertTrue(retry.outputPending)
        assertEquals(0, output.discardCalls)
        assertEquals(0, operation.releaseCalls)
        lifecycle.savePcv3Output(retry.operationId, retry.generation, mockk(relaxed = true))
        assertEquals(2, output.saveCalls)
        assertEquals(0, output.discardCalls)
        lifecycle.discardPcv3Output(retry.operationId, retry.generation).getOrThrow()
        val discarded = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals("discarded", discarded.outputAction?.code)
        assertEquals(1, output.discardCalls)
    }

    @Test
    fun `PCV3 successful ciphertext retry replaces save failure with terminal saved result`() = runTest {
        for (savedCode in listOf("saved", "saved-cleanup-incomplete")) {
            val operation = ContractOperation("pcv3-retry-$savedCode", pcv3CleanSnapshot())
            val output = ContractOutput(operation, saveResult = Pcv3OutputResultData("save-failed", false),
                retainAfterSaveForContradiction = true)
            operation.installOutput(output)
            val lifecycle = lifecycleFor(ContractTransport(operation))
            val live = lifecycle.start(
                Pcv3WriteRequest("write-normal", "password", "none", "input", "output", emptyList(), "", "standard", false),
                "password".toCharArray(), pcv3ReceiptFile,
            ).getOrThrow() as Pcv3Presentation.Live
            assertTrue(lifecycle.savePcv3Output(live.operationId, live.generation, mockk(relaxed = true)).isFailure)
            val retry = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Live
            assertSame(output, retry.outputHandle)
            output.saveResult = Pcv3OutputResultData(savedCode, savedCode != "saved")
            output.retainAfterSaveForContradiction = false
            lifecycle.savePcv3Output(retry.operationId, retry.generation, mockk(relaxed = true)).getOrThrow()
            val terminal = lifecycle.presentation.value as Pcv3Presentation.Final
            assertEquals(savedCode, terminal.outputAction?.code)
            assertEquals(savedCode != "saved", terminal.outputAction?.cleanupIncomplete)
            assertEquals(2, output.saveCalls)
            assertEquals(0, output.discardCalls)
            assertEquals(1, operation.releaseCalls)
        }
    }

    @Test
    fun `PCV3 failed plaintext save still discards a surviving capability`() = runTest {
        val operation = ContractOperation("pcv3-plaintext-no-retry", pcv3CleanSnapshot())
        val output = ContractOutput(operation, saveResult = Pcv3OutputResultData("save-failed", false),
            retainAfterSaveForContradiction = true)
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val live = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile)
            .getOrThrow() as Pcv3Presentation.Live
        assertTrue(lifecycle.savePcv3Output(live.operationId, live.generation, mockk(relaxed = true)).isFailure)
        assertEquals(1, output.discardCalls)
        assertEquals(1, operation.releaseCalls)
        assertTrue(lifecycle.presentation.value is Pcv3Presentation.Final)
    }

    @Test
    fun `PCV3 stale output tickets close Save destinations and leave Discard inert`() = runTest {
        val operation = ContractOperation("pcv3-output-stale", pcv3CleanSnapshot())
        val output = ContractOutput(operation)
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val live = lifecycle.start(
            pcv3Request(),
            "password".toCharArray(),
            pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Live
        val staleDestination = mockk<ParcelFileDescriptor>(relaxed = true)

        val staleSave = lifecycle.savePcv3Output(
            expectedOperationId = "another-operation",
            expectedGeneration = live.generation,
            destination = staleDestination,
        )
        val staleDiscard = lifecycle.discardPcv3Output(
            expectedOperationId = live.operationId,
            expectedGeneration = live.generation + 1,
        )

        assertTrue(staleSave.isFailure)
        assertTrue(staleDiscard.isFailure)
        verify(exactly = 1) { staleDestination.close() }
        assertEquals(0, output.saveCalls)
        assertEquals(0, output.discardCalls)
        assertEquals(0, operation.releaseCalls)
        assertTrue((lifecycle.presentation.value as Pcv3Presentation.Live).outputPending)
    }

    @Test
    fun `PCV3 concurrent output actions admit one Save and publish in-flight before native entry`() = runTest {
        val events = mutableListOf<String>()
        val saveEntered = CompletableDeferred<Unit>()
        val releaseSave = CompletableDeferred<Unit>()
        val operation = ContractOperation("pcv3-output-save", pcv3CleanSnapshot(), events)
        val output = ContractOutput(
            operation = operation,
            saveEntered = saveEntered,
            saveRelease = releaseSave,
            events = events,
        )
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val live = lifecycle.start(
            pcv3Request(),
            "password".toCharArray(),
            pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Live
        val acceptedDestination = mockk<ParcelFileDescriptor>(relaxed = true)
        val rejectedDestination = mockk<ParcelFileDescriptor>(relaxed = true)

        val accepted = async(Dispatchers.Default) {
            lifecycle.savePcv3Output(live.operationId, live.generation, acceptedDestination)
        }
        saveEntered.await()

        val inFlight = lifecycle.presentation.value as Pcv3Presentation.Live
        assertFalse("the public handle is consumed before external effects", inFlight.outputPending)
        assertTrue("in-flight truth is visible before the fake native action blocks", inFlight.outputActionInFlight)
        assertEquals(0, operation.releaseCalls)

        val concurrentSave = lifecycle.savePcv3Output(
            live.operationId,
            live.generation,
            rejectedDestination,
        )
        val concurrentDiscard = lifecycle.discardPcv3Output(live.operationId, live.generation)
        assertTrue(concurrentSave.isFailure)
        assertTrue(concurrentDiscard.isFailure)
        verify(exactly = 1) { rejectedDestination.close() }

        releaseSave.complete(Unit)
        assertTrue(accepted.await().isSuccess)

        val final = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals(Pcv3OutputResultView("saved", cleanupIncomplete = false), final.outputAction)
        assertEquals(1, output.saveCalls)
        assertEquals(0, output.discardCalls)
        assertEquals(1, operation.releaseCalls)
        assertEquals(listOf("save-enter", "save-return", "release"), events)
    }

    @Test
    fun `PCV3 exact Discard records its closed result before one release`() = runTest {
        val events = mutableListOf<String>()
        val operation = ContractOperation("pcv3-output-discard", pcv3CleanSnapshot(), events)
        val output = ContractOutput(operation = operation, events = events)
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val live = lifecycle.start(
            pcv3Request(),
            "password".toCharArray(),
            pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Live

        assertTrue(lifecycle.discardPcv3Output(live.operationId, live.generation).isSuccess)

        val final = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals(Pcv3OutputResultView("discarded", cleanupIncomplete = false), final.outputAction)
        assertEquals(listOf("discard", "release"), events)
        assertEquals(1, output.discardCalls)
        assertEquals(1, operation.releaseCalls)
        assertTrue("a consumed Discard ticket cannot replay", lifecycle.discardPcv3Output(live.operationId, live.generation).isFailure)
        assertEquals(1, output.discardCalls)
    }

    @Test
    fun `PCV3 contradictory post-Save handle preserves a closed cleanup-incomplete code`() = runTest {
        val operation = ContractOperation("pcv3-output-save-contradiction", pcv3CleanSnapshot())
        val output = ContractOutput(
            operation = operation,
            retainAfterSaveForContradiction = true,
        )
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val live = lifecycle.start(
            pcv3Request(),
            "password".toCharArray(),
            pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Live

        val result = lifecycle.savePcv3Output(
            live.operationId,
            live.generation,
            mockk(relaxed = true),
        )

        assertTrue(result.isFailure)
        val final = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals(
            Pcv3OutputResultView("saved-cleanup-incomplete", cleanupIncomplete = true),
            final.outputAction,
        )
        assertEquals(1, output.saveCalls)
        assertEquals(1, output.discardCalls)
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 cancelled Save finishes under owner custody and keeps cleanup failure visible`() = runTest {
        val saveEntered = CompletableDeferred<Unit>()
        val releaseSave = CompletableDeferred<Unit>()
        val operation = ContractOperation("pcv3-output-cancelled", pcv3CleanSnapshot())
        val output = ContractOutput(
            operation = operation,
            saveResult = Pcv3OutputResultData("save-failed-cleanup-incomplete", cleanupIncomplete = true),
            saveEntered = saveEntered,
            saveRelease = releaseSave,
        )
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val live = lifecycle.start(
            pcv3Request(),
            "password".toCharArray(),
            pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Live
        val destination = mockk<ParcelFileDescriptor>(relaxed = true)

        val action = async(Dispatchers.Default) {
            lifecycle.savePcv3Output(live.operationId, live.generation, destination)
        }
        saveEntered.await()
        val cancellation = CancellationException("caller left while provider write was in flight")
        action.cancel(cancellation)
        releaseSave.complete(Unit)
        action.join()

        var thrown: CancellationException? = null
        try {
            action.await()
        } catch (error: CancellationException) {
            thrown = error
        }

        assertTrue(
            "caller cancellation must remain the exact propagated cause after non-cancellable custody cleanup",
            thrown === cancellation || thrown?.cause === cancellation,
        )
        val final = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals(
            Pcv3OutputResultView("save-failed-cleanup-incomplete", cleanupIncomplete = true),
            final.outputAction,
        )
        assertEquals(1, output.saveCalls)
        assertEquals(1, operation.releaseCalls)
        assertFalse("settled output ownership must not leave the lifecycle busy", lifecycle.busy.value)
    }

    @Test
    fun `PCV3 native Save cancellation preserves its exact exception after custody cleanup`() = runTest {
        val operation = ContractOperation("pcv3-output-native-cancelled", pcv3CleanSnapshot())
        val output = ContractOutput(operation)
        val cancellation = CancellationException("native SaveFD cancelled after ownership transfer")
        output.saveFailure = cancellation
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val live = lifecycle.start(
            pcv3Request(),
            "password".toCharArray(),
            pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Live

        val thrown = runCatching {
            lifecycle.savePcv3Output(live.operationId, live.generation, mockk(relaxed = true))
        }.exceptionOrNull()

        assertTrue(
            "native cancellation must remain the exact propagated cause after custody cleanup",
            thrown === cancellation || thrown?.cause === cancellation,
        )
        val final = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals(
            Pcv3OutputResultView("save-failed-cleanup-incomplete", cleanupIncomplete = true),
            final.outputAction,
        )
        assertEquals(1, output.saveCalls)
        assertEquals(1, operation.releaseCalls)
        assertFalse(lifecycle.busy.value)
    }

    @Test
    fun `PCV3 private drain discards output before release and preserves cleanup uncertainty`() = runTest {
        val events = mutableListOf<String>()
        val operation = ContractOperation("pcv3-output-drain", pcv3CleanSnapshot(), events)
        val output = ContractOutput(
            operation = operation,
            discardResult = Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true),
            events = events,
        )
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        operation.failNextSnapshots(1)
        val failedRefresh = lifecycle.refreshPcv3()

        assertTrue(failedRefresh.isFailure)
        val final = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals(
            Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = true),
            final.outputAction,
        )
        assertEquals(listOf("discard", "release"), events)
        assertEquals(1, output.discardCalls)
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 drain never attempts Release while Discard leaves output live`() = runTest {
        val operation = ContractOperation("pcv3-output-drain-live", pcv3CleanSnapshot())
        val output = ContractOutput(operation = operation, retainAfterDiscardForDrain = true)
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        operation.failNextSnapshots(1)

        val failedRefresh = lifecycle.refreshPcv3()

        assertTrue(failedRefresh.isFailure)
        assertEquals(1, output.discardCalls)
        assertEquals("Release requires proof that exact output authority is gone", 0, operation.releaseCalls)
        assertTrue("unconsumed output remains private and blocks new work", lifecycle.busy.value)
        assertNull(lifecycle.presentation.value)
    }

    @Test
    fun `PCV3 drain skips Release when the post-Discard output accessor fails`() = runTest {
        val operation = ContractOperation("pcv3-output-drain-accessor", pcv3CleanSnapshot())
        val output = ContractOutput(operation)
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        operation.failOutputAccessorAfterNextAccess(NoSuchMethodError("stale output accessor"))
        operation.failNextSnapshots(1)

        val failedRefresh = lifecycle.refreshPcv3()

        assertTrue(failedRefresh.isFailure)
        assertEquals(1, output.discardCalls)
        assertEquals("unreadable post-Discard authority is cleanup-incomplete, not releasable", 0, operation.releaseCalls)
        assertTrue(lifecycle.busy.value)
        assertNull(lifecycle.presentation.value)

        val final = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Final
        assertEquals(
            Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = true),
            final.outputAction,
        )
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 drain records a Discard linkage failure as bounded cleanup truth`() = runTest {
        val operation = ContractOperation("pcv3-output-drain-discard-linkage", pcv3CleanSnapshot())
        val output = ContractOutput(operation)
        output.discardFailure = NoSuchMethodError("stale discard ABI")
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        operation.failNextSnapshots(1)

        assertTrue(lifecycle.refreshPcv3().isFailure)
        val final = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals(
            Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = true),
            final.outputAction,
        )
        assertEquals(1, output.discardCalls)
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 drain retains output result across a post-Discard archive linkage failure`() = runTest {
        val operation = ContractOperation("pcv3-output-drain-archive-linkage", pcv3CleanSnapshot())
        val output = ContractOutput(
            operation = operation,
            discardResult = Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true),
        )
        val archive = ContractArchive(
            operation = operation,
            entered = CompletableDeferred<Unit>(),
            release = CompletableDeferred<Unit>().also { it.complete(Unit) },
        )
        archive.closeFailure = NoSuchMethodError("stale archive ABI")
        operation.installOutput(output)
        operation.installArchive(archive)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        val first = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile)

        assertTrue(first.isFailure)
        assertEquals(1, output.discardCalls)
        assertEquals(0, operation.releaseCalls)
        assertTrue(lifecycle.busy.value)

        archive.closeFailure = null
        val final = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Final
        assertEquals(
            Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = true),
            final.outputAction,
        )
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 drain retains output result across a post-Discard snapshot linkage failure`() = runTest {
        val operation = ContractOperation("pcv3-output-drain-snapshot-linkage", pcv3CleanSnapshot())
        val output = ContractOutput(
            operation = operation,
            discardResult = Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true),
        )
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        operation.failSnapshots(
            IllegalStateException("initial snapshot failed"),
            NoSuchMethodError("stale snapshot ABI"),
        )

        val first = lifecycle.refreshPcv3()

        assertTrue(first.isFailure)
        assertEquals(1, output.discardCalls)
        assertEquals(0, operation.releaseCalls)
        assertTrue(lifecycle.busy.value)

        val final = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Final
        assertEquals(
            Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = true),
            final.outputAction,
        )
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 drain retains output result across a Release linkage failure`() = runTest {
        val operation = ContractOperation("pcv3-output-drain-release-linkage", pcv3CleanSnapshot())
        val output = ContractOutput(
            operation = operation,
            discardResult = Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true),
        )
        operation.installOutput(output)
        operation.releaseFailures += NoSuchMethodError("stale release ABI")
        val lifecycle = lifecycleFor(ContractTransport(operation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        operation.failNextSnapshots(1)

        val first = lifecycle.refreshPcv3()

        assertTrue(first.isFailure)
        assertEquals(1, output.discardCalls)
        assertEquals(1, operation.releaseCalls)
        assertTrue(lifecycle.busy.value)

        val final = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Final
        assertEquals(
            Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = true),
            final.outputAction,
        )
        assertEquals(2, operation.releaseCalls)
    }

    @Test
    fun `PCV3 worker completion between snapshot and capabilities retains each native result`() = runTest {
        data class Case(val name: String, val snapshot: Pcv3SnapshotData, val metadata: Pcv3ArtifactMetadataData? = null)
        val cases = listOf(
            Case("creation", pcv3CleanSnapshot()),
            Case("read", pcv3CleanSnapshot()),
            Case("degraded", pcv3AuthenticatedDegradedSnapshot()),
            Case("partial", pcv3WarningSnapshot(), pcv3PartialArtifactMetadata()),
            Case("unverified", pcv3ForceUnverifiedSnapshot(), pcv3UnverifiedArtifactMetadata()),
            Case("archive", pcv3ArchivePendingSnapshot()),
        )
        for (case in cases) for (afterOutput in listOf(false, true)) {
            val operation = ContractOperation("pcv3-race-${case.name}-$afterOutput", pcv3WorkingSnapshot())
            val output = ContractOutput(operation)
            val archive = ContractArchive(operation, CompletableDeferred(), CompletableDeferred())
            var complete = false
            fun finishWorker() {
                if (!complete) return
                complete = false
                operation.replaceSnapshot(case.snapshot)
                if (case.name == "archive") operation.installArchive(archive) else operation.installOutput(output)
                case.metadata?.let { operation.installArtifactInspection(ContractArtifactInspection(it)) }
            }
            val boundary = object : Pcv3OperationCapability by operation {
                override fun snapshot(): Pcv3SnapshotData = operation.snapshot().also {
                    if (!afterOutput) finishWorker()
                }
                override fun output(): Pcv3OutputCapability? = operation.output().also {
                    if (afterOutput) finishWorker()
                }
            }
            val lifecycle = lifecycleFor(ContractTransport(boundary))
            val request = if (case.name == "creation") {
                Pcv3WriteRequest("write-normal", "password", "none", "input", "output", emptyList(), "", "standard", false)
            } else pcv3Request()
            lifecycle.start(request, "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
            complete = true

            val live = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Live

            assertEquals("${case.name}: completion is not a discard decision", 0, output.discardCalls)
            assertEquals("${case.name}: archive remains available for explicit export or close", 0, archive.closeCalls)
            assertEquals("${case.name}: live follow-up must block release", 0, operation.releaseCalls)
            assertEquals(case.snapshot.completionClass, live.snapshot.completionClass)
            if (case.name == "archive") assertSame(archive, live.archiveHandle) else assertSame(output, live.outputHandle)
            assertEquals(case.metadata?.toView(), live.artifactMetadata)
            assertTrue(lifecycle.refreshPcv3().getOrThrow() is Pcv3Presentation.Live)
        }
    }

    @Test
    fun `PCV3 consent arriving after a running snapshot remains selectable without cancelling work`() = runTest {
        val operation = ContractOperation("pcv3-consent-arrival", pcv3WorkingSnapshot())
        val consent = ContractConsent(operation, "force-unverified-normal", listOf("primary", "backup"))
        var arrive = false
        val boundary = object : Pcv3OperationCapability by operation {
            override fun snapshot(): Pcv3SnapshotData = operation.snapshot().also {
                if (arrive) {
                    arrive = false
                    operation.installConsent(consent)
                }
            }
        }
        val lifecycle = lifecycleFor(ContractTransport(boundary))
        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        arrive = true
        val live = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Live
        assertSame(consent, live.consentHandle)
        assertEquals(listOf("primary", "backup"), live.consent?.allowedRoles)
        assertTrue(lifecycle.selectPcv3ConsentRole("backup").isSuccess)
        assertEquals(0, operation.cancelCalls)
        assertEquals(0, operation.releaseCalls)
    }

    @Test
    fun `PCV3 uncertain creation keeps ciphertext live until explicit save or discard then persists its receipt`() = runTest {
        for (mode in listOf("write-normal", "write-d1")) for (save in listOf(false, true)) {
            val events = mutableListOf<String>()
            val snapshot = pcv3SafTerminalSnapshot()
            val operation = ContractOperation("pcv3-uncertain-$mode-$save", snapshot, events)
            val output = ContractOutput(operation, events = events)
            operation.installOutput(output)
            val persistence = RecordingReceiptPersistence(events)
            val lifecycle = lifecycleFor(ContractTransport(operation), persistence)
            val live = lifecycle.start(
                Pcv3WriteRequest(mode, "password", "none", "input", "output", emptyList(), "", "paranoid", false),
                "password".toCharArray(), pcv3ReceiptFile,
            ).getOrThrow() as Pcv3Presentation.Live

            assertEquals("durability uncertainty cannot revoke retained ciphertext", 0, output.discardCalls)
            assertEquals(0, operation.releaseCalls)
            assertSame(output, live.outputHandle)
            assertTrue(live.outputPending)
            assertEquals("durability-uncertain", live.snapshot.completionClass)
            assertFalse(lifecycle.dismissPcv3(live.operationId, live.generation))
            if (save) lifecycle.savePcv3Output(live.operationId, live.generation, mockk(relaxed = true)).getOrThrow()
            else lifecycle.discardPcv3Output(live.operationId, live.generation).getOrThrow()

            val final = lifecycle.presentation.value as Pcv3Presentation.Final
            assertEquals(if (save) "saved" else "discarded", final.outputAction?.code)
            assertEquals("durability-uncertain", final.snapshot.completionClass)
            assertEquals(snapshot.restoredReceipt, persistence.savedReceipt)
            assertTrue(events.indexOf("receipt-save") in 0 until events.indexOf("release"))
            assertEquals(1, operation.releaseCalls)
        }
    }

    @Test
    fun `PCV3 uncertainty never authorizes plaintext Force indeterminate or receiptless creation output`() = runTest {
        val uncertain = pcv3SafTerminalSnapshot()
        val cases = listOf(
            pcv3Request() to uncertain,
            pcv3Request() to uncertain.copy(outcome = "force-partial", code = "PCV3_FORCE_PARTIAL", forceProvenance = "partial"),
            Pcv3WriteRequest("write-normal", "password", "none", "input", "output", emptyList(), "", "standard", false) to
                uncertain.copy(restoredReceipt = ""),
            Pcv3WriteRequest("write-normal", "password", "none", "input", "output", emptyList(), "", "standard", false) to
                pcv3SafActiveSnapshot(),
            pcv3Request() to pcv3WorkingSnapshot(),
        )
        for ((index, case) in cases.withIndex()) {
            val operation = ContractOperation("pcv3-invalid-output-$index", case.second)
            val output = ContractOutput(operation)
            operation.installOutput(output)
            val lifecycle = lifecycleFor(ContractTransport(operation), RecordingReceiptPersistence(mutableListOf()))
            assertTrue(lifecycle.start(case.first, "password".toCharArray(), pcv3ReceiptFile).isFailure)
            assertEquals("a stable contradiction must still be drained", 1, output.discardCalls)
            assertTrue(lifecycle.presentation.value !is Pcv3Presentation.Live)
        }
    }

    @Test
    fun `PCV3 warning output survives ordinary dismissal without implicit discard`() = runTest {
        val operation = ContractOperation("pcv3-output-warning", pcv3WarningSnapshot())
        val output = ContractOutput(operation)
        operation.installArtifactInspection(ContractArtifactInspection(pcv3PartialArtifactMetadata()))
        operation.installOutput(output)
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val live = lifecycle.start(
            pcv3Request(),
            "password".toCharArray(),
            pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Live

        assertTrue(live.outputPending)
        assertFalse(lifecycle.dismissPcv3(live.operationId, live.generation))
        assertTrue((lifecycle.presentation.value as Pcv3Presentation.Live).outputPending)
        assertEquals(0, output.discardCalls)
        assertEquals(0, operation.releaseCalls)
    }

    @Test
    fun `PCV3 contradictory archive and output tuple drains both capabilities fail closed`() = runTest {
        val operation = ContractOperation("pcv3-output-contradiction", pcv3CleanSnapshot())
        val output = ContractOutput(operation)
        val archive = ContractArchive(
            operation = operation,
            entered = CompletableDeferred<Unit>(),
            release = CompletableDeferred<Unit>().also { it.complete(Unit) },
        )
        operation.installOutput(output)
        operation.installArchive(archive)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        val result = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile)

        assertTrue(result.isFailure)
        assertTrue(lifecycle.presentation.value is Pcv3Presentation.Final)
        assertEquals(1, output.discardCalls)
        assertEquals(1, archive.closeCalls)
        assertEquals(1, operation.releaseCalls)
        assertEquals(
            Pcv3OutputResultView("discarded", cleanupIncomplete = false),
            (lifecycle.presentation.value as Pcv3Presentation.Final).outputAction,
        )
    }

    @Test
    fun `PCV3 delayed core state moves from initial to consent to terminal only through refresh`() = runTest {
        val operation = ContractOperation("pcv3-async", pcv3WorkingSnapshot())
        val consent = ContractConsent(operation, "force-unverified-normal", listOf("primary", "backup"))
        val lifecycle = lifecycleFor(ContractTransport(operation))

        val initial = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow() as Pcv3Presentation.Live
        assertEquals("unknown", initial.snapshot.completionClass)
        assertEquals(null, initial.consent)

        operation.installConsent(consent)
        val waiting = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Live
        assertEquals(listOf("primary", "backup"), waiting.consent?.allowedRoles)
        assertTrue(lifecycle.selectPcv3ConsentRole("backup").isSuccess)
        assertTrue(lifecycle.confirmPcv3Consent().isSuccess)
        assertTrue("choice is a request; Go remains authoritative until a later poll", lifecycle.presentation.value is Pcv3Presentation.Live)

        operation.replaceSnapshot(pcv3CleanSnapshot())
        val terminal = lifecycle.refreshPcv3().getOrThrow()
        assertTrue(terminal is Pcv3Presentation.Final)
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 dismissal clears only the exact released terminal generation`() = runTest {
        val operation = ContractOperation("pcv3-dismiss", pcv3WorkingSnapshot())
        val lifecycle = lifecycleFor(ContractTransport(operation))

        val live = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        assertFalse("a live native handle cannot be dismissed", lifecycle.dismissPcv3(live.operationId, live.generation))
        assertSame(live, lifecycle.presentation.value)

        operation.replaceSnapshot(pcv3CleanSnapshot())
        val terminal = lifecycle.refreshPcv3().getOrThrow()
        assertTrue(terminal is Pcv3Presentation.Final)
        assertFalse(lifecycle.dismissPcv3("wrong-operation", terminal.generation))
        assertFalse(lifecycle.dismissPcv3(terminal.operationId, terminal.generation + 1))
        assertSame("stale UI tickets must not clear the current terminal record", terminal, lifecycle.presentation.value)

        assertTrue(lifecycle.dismissPcv3(terminal.operationId, terminal.generation))
        assertNull(lifecycle.presentation.value)
        assertFalse("the same terminal ticket is one-shot", lifecycle.dismissPcv3(terminal.operationId, terminal.generation))
    }

    @Test
    fun `PCV3 concurrent start is refused while starting and retains the first handle`() = runTest {
        val entered = CompletableDeferred<Unit>()
        val releaseStart = CompletableDeferred<Unit>()
        val operation = ContractOperation("pcv3-first", pcv3WorkingSnapshot())
        val transport = ContractTransport(operation, startEntered = entered, startRelease = releaseStart)
        val lifecycle = lifecycleFor(transport)

        val first = async(Dispatchers.Default) {
            lifecycle.start(pcv3Request(), "first".toCharArray(), pcv3ReceiptFile)
        }
        entered.await()
        val concurrent = lifecycle.start(pcv3Request(), "second".toCharArray(), pcv3ReceiptFile)
        assertTrue("a second start cannot replace an in-flight generation", concurrent.isFailure)
        assertEquals("PCV3_OPERATION_UNAVAILABLE", concurrent.exceptionOrNull()?.message)

        releaseStart.complete(Unit)
        val active = first.await().getOrThrow() as Pcv3Presentation.Live
        assertEquals("pcv3-first", active.operationId)
        assertEquals(1, transport.startCalls)
        assertTrue(lifecycle.presentation.value is Pcv3Presentation.Live)
    }

    @Test
    fun `PCV3 restore is refused while a live generation owns the handle`() = runTest {
        val operation = ContractOperation("pcv3-active", pcv3WorkingSnapshot())
        val transport = ContractTransport(operation)
        val lifecycle = lifecycleFor(transport)

        val active = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        val restored = lifecycle.restorePcv3Receipt("receipt-wire", pcv3ReceiptFile)

        assertTrue(active is Pcv3Presentation.Live)
        assertTrue(restored.isFailure)
        assertEquals(0, transport.restoreCalls)
        assertEquals(active.generation, lifecycle.presentation.value?.generation)
    }

    @Test
    fun `PCV3 invalid consent roles are refused once then reconciled without a capability`() = runTest {
        val operation = ContractOperation("pcv3-invalid-consent", pcv3WorkingSnapshot())
        val invalid = ContractConsent(
            operation = operation,
            modeValue = "force-unverified-normal",
            rolesValue = listOf("primary"),
        )
        operation.installConsent(invalid)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        val first = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow() as Pcv3Presentation.Live
        val second = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Live

        assertEquals(1, invalid.refuseCalls)
        assertEquals(null, first.consent)
        assertEquals(null, first.consentHandle)
        assertEquals(null, second.consent)
        assertEquals(null, second.consentHandle)
    }

    @Test
    fun `PCV3 cancellation while native consent blocks retains private drain ownership`() = runTest {
        val operation = ContractOperation("pcv3-consent-exception", pcv3WorkingSnapshot())
        val consent = ContractConsent(operation, "force-unverified-normal", listOf("primary", "backup"))
        val chooseEntered = CompletableDeferred<Unit>()
        val releaseChoose = CompletableDeferred<Unit>()
        consent.blockChoose(chooseEntered, releaseChoose)
        operation.installConsent(consent)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        lifecycle.selectPcv3ConsentRole("primary").getOrThrow()
        val action = async(Dispatchers.Default) { lifecycle.confirmPcv3Consent() }
        chooseEntered.await()
        action.cancel(CancellationException("cancel consent owner after native state changed"))
        releaseChoose.complete(Unit)
        action.join()
        var thrown: CancellationException? = null
        try {
            action.await()
        } catch (error: CancellationException) {
            thrown = error
        }

        assertNotNull("structured cancellation must propagate after cleanup", thrown)
        assertNull("the still-live native operation must remain private while draining", lifecycle.presentation.value)
        assertEquals("cleanup must request core cancellation exactly once", 1, operation.cancelCalls)
        assertEquals(0, operation.releaseCalls)

        operation.replaceSnapshot(pcv3CancelledSnapshot())
        assertTrue(lifecycle.refreshPcv3().getOrThrow() is Pcv3Presentation.Final)
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 consent action exception transfers authority to private drain`() = runTest {
        val operation = ContractOperation("pcv3-consent-failure", pcv3WorkingSnapshot())
        val consent = ContractConsent(operation, "force-unverified-normal", listOf("primary", "backup"))
        consent.chooseFailure = IllegalStateException("native action state is uncertain")
        operation.installConsent(consent)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        lifecycle.selectPcv3ConsentRole("primary").getOrThrow()
        val result = lifecycle.confirmPcv3Consent()

        assertTrue(result.isFailure)
        assertEquals("PCV3_OPERATION_FAILURE", result.exceptionOrNull()?.message)
        assertEquals("an uncertain action is cancelled exactly once in its first drain pass", 1, operation.cancelCalls)
        assertNull("uncertain native authority must not remain publicly actionable", lifecycle.presentation.value)

        operation.replaceSnapshot(pcv3CancelledSnapshot())
        assertTrue(lifecycle.refreshPcv3().getOrThrow() is Pcv3Presentation.Final)
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 concurrent SAF export consumes one exact handle once`() = runTest {
        val entered = CompletableDeferred<Unit>()
        val releaseExtract = CompletableDeferred<Unit>()
        val operation = ContractOperation("pcv3-archive", pcv3ArchivePendingSnapshot())
        val archive = ContractArchive(operation, entered, releaseExtract)
        operation.installArchive(archive)
        val lifecycle = safLifecycleFor(ContractTransport(operation))

        val live = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        val first = async(Dispatchers.Default) {
            lifecycle.exportPcv3Archive(live.operationId, live.generation, opaqueSafRoot(), ReadySafPublisher)
        }
        entered.await()
        val concurrent = lifecycle.exportPcv3Archive(
            live.operationId,
            live.generation,
            opaqueSafRoot(),
            ReadySafPublisher,
        )
        assertTrue("the in-flight archive handle is not reusable", concurrent.isFailure)

        releaseExtract.complete(Unit)
        assertTrue(first.await().isSuccess)
        assertEquals(1, archive.beginCalls)
        assertTrue(lifecycle.presentation.value is Pcv3Presentation.Final)
    }

    @Test
    fun `PCV3 fake Release denies nonterminal in-flight archive and repeated calls`() = runTest {
        val entered = CompletableDeferred<Unit>()
        val settleArchive = CompletableDeferred<Unit>()
        val operation = ContractOperation("pcv3-archive-release", pcv3ArchivePendingSnapshot())
        val archive = ContractArchive(operation, entered, settleArchive)
        operation.installArchive(archive)

        val action = async(Dispatchers.Default) { archive.beginSaf().session!!.finish() }
        entered.await()
        try {
            assertNull("the blocking point is after one-shot capability consumption", operation.archive())
            assertEquals(
                "Release must remain denied after capability consumption until the archive effect settles",
                "PCV3_OPERATION_RELEASE_DENIED",
                operation.release(),
            )
        } finally {
            settleArchive.complete(Unit)
        }
        action.await()

        assertEquals("", operation.release())
        assertEquals(
            "a successfully released operation is no longer registered",
            "PCV3_OPERATION_RELEASE_DENIED",
            operation.release(),
        )

        val nonterminal = ContractOperation("pcv3-working-release", pcv3WorkingSnapshot())
        assertEquals(
            "a live nonterminal operation cannot be released",
            "PCV3_OPERATION_RELEASE_DENIED",
            nonterminal.release(),
        )
    }

    @Test
    fun `PCV3 cancel requests core cancellation then terminal poll releases once`() = runTest {
        val operation = ContractOperation("pcv3-cancel", pcv3WorkingSnapshot())
        val lifecycle = lifecycleFor(ContractTransport(operation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        assertTrue(lifecycle.cancelPcv3().isSuccess)
        assertEquals(1, operation.cancelCalls)
        assertTrue("cancel does not invent a terminal presentation", lifecycle.presentation.value is Pcv3Presentation.Live)

        operation.replaceSnapshot(pcv3CancelledSnapshot())
        assertTrue(lifecycle.refreshPcv3().getOrThrow() is Pcv3Presentation.Final)
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 captures receipt before one release and restores its deny-only identity`() = runTest {
        val receiptId = "r_00112233445566778899aabbccddeeff"
        val operationId = "op_1700000000000000000_7"
        val receipt = """{"version":1,"receiptID":"r_00112233445566778899aabbccddeeff","operationID":"op_1700000000000000000_7","outcome":7,"stage":0,"code":7,"forceProvenance":1,"d1BootstrapProvenance":3,"detailStage":13,"publicationAttempted":true,"publicationState":3,"publicationStage":24,"publicationCode":9,"args":[7,11,13,17],"warnings":[6,4],"diagnostic":0}"""
        val operation = ContractOperation(
            operationId,
            pcv3DurabilityUncertainSnapshot(receipt),
        )
        val restoredSnapshot = pcv3DurabilityUncertainSnapshot(receipt)
        val transport = ContractTransport(
            operation = operation,
            restored = Pcv3RestoredReceiptData("", receiptId, operationId, restoredSnapshot),
        )
        val lifecycle = lifecycleFor(
            transport,
            RecordingReceiptPersistence(mutableListOf()),
        )

        val terminal = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow() as Pcv3Presentation.Final
        assertEquals("none", terminal.snapshot.statusCode)
        assertEquals(emptyList<String>(), terminal.snapshot.statusArgs)
        assertEquals(receipt, terminal.snapshot.restoredReceipt)
        assertEquals("success", terminal.snapshot.semantic.outcome)
        assertEquals("none", terminal.snapshot.semantic.stage)
        assertEquals("PCV3_SUCCESS", terminal.snapshot.semantic.code)
        assertEquals("verified", terminal.snapshot.forceProvenance)
        assertEquals("matching", terminal.snapshot.d1BootstrapProvenance)
        assertEquals("metadata", terminal.snapshot.detailStage)
        assertTrue(terminal.snapshot.publication.attempted)
        assertEquals("published-durability-uncertain", terminal.snapshot.publication.state)
        assertEquals("directory-sync", terminal.snapshot.publication.stage)
        assertEquals("PCV3_PUBLICATION_DURABILITY_UNCERTAIN", terminal.snapshot.publication.code)
        assertEquals("none", terminal.snapshot.diagnostic)
        assertEquals(listOf("7", "11", "13", "17"), terminal.snapshot.resultArgs)
        assertEquals(listOf("cleanup-incomplete", "durability-uncertain"), terminal.snapshot.warnings)
        assertEquals("durability-uncertain", terminal.snapshot.completionClass)
        assertFalse(terminal.snapshot.archivePending)
        assertEquals(1, operation.releaseCalls)
        assertTrue(lifecycle.refreshPcv3().getOrThrow() is Pcv3Presentation.Final)
        assertEquals("release is never retried after a final presentation", 1, operation.releaseCalls)

        assertTrue(lifecycle.dismissPcv3(terminal.operationId, terminal.generation))
        val restored = lifecycle.restorePcv3Receipt(receipt, pcv3ReceiptFile).getOrThrow() as Pcv3Presentation.Restored
        assertEquals(receipt, transport.restoredInput)
        assertEquals(receiptId, restored.receiptId)
        assertEquals(operationId, restored.operationId)
        assertEquals("the restored frozen tuple must preserve every scalar axis", terminal.snapshot, restored.snapshot)
        assertNull("a deny-only restored receipt cannot recreate artifact inspection", restored.artifactMetadata)
        assertEquals(Pcv3ArtifactDetailsUiState.Closed, lifecycle.artifactDetails.value)
        val restoredPresentation: Pcv3Presentation = restored
        assertTrue("restored state has no live Go capability", restoredPresentation !is Pcv3Presentation.Live)
        assertTrue(lifecycle.cancelPcv3().isFailure)
        assertFalse(lifecycle.dismissPcv3("wrong-operation", restored.generation))
        assertTrue(lifecycle.dismissPcv3(restored.operationId, restored.generation))
        assertNull(lifecycle.presentation.value)
    }

    @Test
    fun `PCV3 captures passive artifact before release and pages it after Save and Discard`() = runTest {
        listOf("save", "discard").forEach { action ->
            val events = mutableListOf<String>()
            val operation = ContractOperation("pcv3-artifact-$action", pcv3WarningSnapshot(), events)
            val inspection = ContractArtifactInspection(
                metadataValue = pcv3PartialArtifactMetadata(),
                pages = mapOf("0" to pcv3ArtifactPage("0")),
                events = events,
            )
            val output = ContractOutput(operation = operation, events = events)
            operation.installArtifactInspection(inspection)
            operation.installOutput(output)
            val lifecycle = lifecycleFor(ContractTransport(operation))

            val live = lifecycle.start(
                pcv3Request(),
                "password".toCharArray(),
                pcv3ReceiptFile,
            ).getOrThrow() as Pcv3Presentation.Live

            assertEquals(pcv3PartialArtifactMetadata().toView(), live.artifactMetadata)
            assertTrue(live.outputPending)
            assertEquals(0, operation.releaseCalls)
            if (action == "save") {
                assertTrue(
                    lifecycle.savePcv3Output(
                        live.operationId,
                        live.generation,
                        mockk(relaxed = true),
                    ).isSuccess,
                )
            } else {
                assertTrue(lifecycle.discardPcv3Output(live.operationId, live.generation).isSuccess)
            }

            val final = lifecycle.presentation.value as Pcv3Presentation.Final
            assertEquals(pcv3PartialArtifactMetadata().toView(), final.artifactMetadata)
            assertEquals(1, operation.releaseCalls)
            assertTrue(
                "artifact metadata must be captured while native ownership is live",
                events.indexOf("artifact-metadata") in 0 until events.indexOf("release"),
            )

            val page = lifecycle.loadPcv3ArtifactPage(
                final.operationId,
                final.generation,
                "0",
                128,
            ).getOrThrow()
            assertEquals(pcv3ArtifactPage("0").toView(), page)
            assertEquals(
                Pcv3ArtifactDetailsUiState.Ready(final.artifactMetadata!!, page),
                lifecycle.artifactDetails.value,
            )
            assertEquals("the captured passive handle remains readable after Release", 1, inspection.pageCalls)
        }
    }

    @Test
    fun `PCV3 artifact inspection accepts only the exact durable Force tuple`() = runTest {
        data class Case(
            val name: String,
            val snapshot: Pcv3SnapshotData,
            val metadata: Pcv3ArtifactMetadataData?,
            val accepted: Boolean,
        )

        val cases = listOf(
            Case("partial", pcv3WarningSnapshot(), pcv3PartialArtifactMetadata(), true),
            Case("unverified", pcv3ForceUnverifiedSnapshot(), pcv3UnverifiedArtifactMetadata(), true),
            Case("clean absent", pcv3CleanSnapshot(), null, true),
            Case("authenticated degraded absent", pcv3AuthenticatedDegradedSnapshot(), null, true),
            Case("clean contradiction", pcv3CleanSnapshot(), pcv3PartialArtifactMetadata(), false),
            Case("degraded contradiction", pcv3AuthenticatedDegradedSnapshot(), pcv3PartialArtifactMetadata(), false),
            Case(
                "partial noncanonical provenance",
                pcv3WarningSnapshot().copy(forceProvenance = "verified"),
                pcv3PartialArtifactMetadata(),
                false,
            ),
            Case("partial kind mismatch", pcv3WarningSnapshot(), pcv3UnverifiedArtifactMetadata(), false),
            Case("unverified kind mismatch", pcv3ForceUnverifiedSnapshot(), pcv3PartialArtifactMetadata(), false),
            Case("partial missing inspection", pcv3WarningSnapshot(), null, false),
        )

        cases.forEachIndexed { index, case ->
            val operation = ContractOperation("pcv3-artifact-tuple-$index", case.snapshot)
            case.metadata?.let { operation.installArtifactInspection(ContractArtifactInspection(it)) }
            val lifecycle = lifecycleFor(ContractTransport(operation))

            val result = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile)
            val final = lifecycle.presentation.value as? Pcv3Presentation.Final

            assertEquals("${case.name} result", case.accepted, result.isSuccess)
            assertNotNull("${case.name} must settle without retaining native authority", final)
            assertEquals("${case.name} release count", 1, operation.releaseCalls)
            assertEquals(
                "${case.name} inspection projection",
                case.metadata?.takeIf { case.accepted }?.toView(),
                final?.artifactMetadata,
            )
            assertFalse("a passive inspection cannot keep lifecycle ownership busy", lifecycle.busy.value)
        }
    }

    @Test
    fun `PCV3 probes inspection before receipt persistence and exposes none after restore`() = runTest {
        val events = mutableListOf<String>()
        val receipt = "deny-only-receipt"
        val operation = ContractOperation(
            "pcv3-artifact-receipt-order",
            pcv3DurabilityUncertainSnapshot(receipt),
            events,
            recordArtifactAccess = true,
        )
        val persistence = RecordingReceiptPersistence(events)
        val transport = ContractTransport(
            operation = operation,
            restored = Pcv3RestoredReceiptData(
                code = "",
                receiptId = "r_artifact_order",
                operationId = operation.id,
                snapshot = pcv3DurabilityUncertainSnapshot(receipt),
            ),
        )
        val lifecycle = lifecycleFor(transport, persistence)

        val final = lifecycle.start(
            pcv3Request(),
            "password".toCharArray(),
            pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Final

        assertNull(final.artifactMetadata)
        assertEquals(listOf("artifact-access", "receipt-save", "release"), events)
        assertTrue(lifecycle.dismissPcv3(final.operationId, final.generation))
        val restored = lifecycle.restorePcv3Receipt(receipt, pcv3ReceiptFile).getOrThrow()
        assertTrue(restored is Pcv3Presentation.Restored)
        assertNull(restored.artifactMetadata)
        assertEquals(Pcv3ArtifactDetailsUiState.Closed, lifecycle.artifactDetails.value)
    }

    @Test
    fun `PCV3 delayed artifact page cannot overwrite a newer page across output completion or generation`() = runTest {
        val pageEntered = CompletableDeferred<Unit>()
        val releasePage = CompletableDeferred<Unit>()
        val outputRacePageEntered = CompletableDeferred<Unit>()
        val releaseOutputRacePage = CompletableDeferred<Unit>()
        val first = ContractOperation("pcv3-artifact-race-first", pcv3WarningSnapshot())
        val metadata = pcv3PartialArtifactMetadata().copy(rangeCount = "3", missingCount = "2")
        val firstInspection = ContractArtifactInspection(
            metadataValue = metadata,
            pages = mapOf(
                "0" to pcv3ArtifactPage("0", recordIndex = "10"),
                "1" to pcv3ArtifactPage("1", recordIndex = "11"),
                "2" to pcv3ArtifactPage("2", recordIndex = "12"),
            ),
            blockedOffset = "0",
            pageEntered = pageEntered,
            pageRelease = releasePage,
        )
        first.installArtifactInspection(firstInspection)
        first.installOutput(ContractOutput(first))
        val second = ContractOperation("pcv3-artifact-race-second", pcv3WarningSnapshot())
        second.installArtifactInspection(ContractArtifactInspection(pcv3PartialArtifactMetadata()))
        val lifecycle = lifecycleFor(
            SequencedContractTransport(ArrayDeque(listOf(first, second))),
        )
        val live = lifecycle.start(
            pcv3Request(),
            "password".toCharArray(),
            pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Live
        val metadataView = requireNotNull(live.artifactMetadata)

        val delayed = async(Dispatchers.Default) {
            lifecycle.loadPcv3ArtifactPage(live.operationId, live.generation, "0", 1)
        }
        pageEntered.await()
        assertEquals(Pcv3ArtifactDetailsUiState.Loading, lifecycle.artifactDetails.value)

        val newest = lifecycle.loadPcv3ArtifactPage(live.operationId, live.generation, "1", 1).getOrThrow()
        assertEquals("11", newest.ranges.single().recordIndex)
        assertEquals(
            Pcv3ArtifactDetailsUiState.Ready(metadataView, newest),
            lifecycle.artifactDetails.value,
        )
        releasePage.complete(Unit)
        assertTrue("a superseded request must fail", delayed.await().isFailure)
        assertEquals(
            "a superseded request must not overwrite the newest Ready page",
            Pcv3ArtifactDetailsUiState.Ready(metadataView, newest),
            lifecycle.artifactDetails.value,
        )

        firstInspection.blockPage("2", outputRacePageEntered, releaseOutputRacePage)
        val delayedAcrossOutput = async(Dispatchers.Default) {
            lifecycle.loadPcv3ArtifactPage(live.operationId, live.generation, "2", 1)
        }
        outputRacePageEntered.await()
        assertEquals(Pcv3ArtifactDetailsUiState.Loading, lifecycle.artifactDetails.value)

        assertTrue(lifecycle.discardPcv3Output(live.operationId, live.generation).isSuccess)
        val final = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals(1, first.releaseCalls)
        releaseOutputRacePage.complete(Unit)
        assertTrue(
            "an output transition must invalidate an already delayed page",
            delayedAcrossOutput.await().isFailure,
        )
        assertEquals(Pcv3ArtifactDetailsUiState.Closed, lifecycle.artifactDetails.value)

        val newer = lifecycle.loadPcv3ArtifactPage(final.operationId, final.generation, "1", 1).getOrThrow()
        assertEquals("11", newer.ranges.single().recordIndex)
        assertEquals(
            Pcv3ArtifactDetailsUiState.Ready(final.artifactMetadata!!, newer),
            lifecycle.artifactDetails.value,
        )

        assertTrue(lifecycle.dismissPcv3(final.operationId, final.generation))
        val next = lifecycle.start(
            pcv3Request(),
            "password".toCharArray(),
            pcv3ReceiptFile,
        ).getOrThrow() as Pcv3Presentation.Final
        assertNotEquals(live.generation, next.generation)
        assertTrue(
            lifecycle.loadPcv3ArtifactPage(live.operationId, live.generation, "1", 1).isFailure,
        )
        assertEquals(
            "a stale generation must not change the new terminal detail state",
            Pcv3ArtifactDetailsUiState.Closed,
            lifecycle.artifactDetails.value,
        )
    }

    @Test
    fun `PCV3 artifact page failures publish only one bounded authority-free code`() = runTest {
        val sentinel = "content://private.provider/raw-artifact-path"
        listOf<Throwable>(IllegalStateException(sentinel), NoSuchMethodError(sentinel)).forEachIndexed { index, failure ->
            val operation = ContractOperation("pcv3-artifact-page-failure-$index", pcv3WarningSnapshot())
            val inspection = ContractArtifactInspection(pcv3PartialArtifactMetadata())
            inspection.pageFailure = failure
            operation.installArtifactInspection(inspection)
            val lifecycle = lifecycleFor(ContractTransport(operation))
            val final = lifecycle.start(
                pcv3Request(),
                "password".toCharArray(),
                pcv3ReceiptFile,
            ).getOrThrow() as Pcv3Presentation.Final

            val result = lifecycle.loadPcv3ArtifactPage(final.operationId, final.generation, "0", 1)

            assertTrue(result.isFailure)
            assertEquals("PCV3_ARTIFACT_INSPECTION_UNAVAILABLE", result.exceptionOrNull()?.message)
            val failed = lifecycle.artifactDetails.value as Pcv3ArtifactDetailsUiState.Failed
            assertEquals("PCV3_ARTIFACT_INSPECTION_UNAVAILABLE", failed.code)
            assertFalse(failed.toString().contains(sentinel))
            assertEquals(1, operation.releaseCalls)
        }
    }

    @Test
    fun `PCV3 release denial enters private draining and retries once on a later refresh`() = runTest {
        val operation = ContractOperation("pcv3-release-denied", pcv3CleanSnapshot())
        operation.releaseCodes += listOf("PCV3_OPERATION_RELEASE_DENIED", "")
        val lifecycle = lifecycleFor(ContractTransport(operation))

        assertFalse(lifecycle.busy.value)
        val start = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile)
        assertTrue(start.isFailure)
        assertNull("a draining handle must not remain public", lifecycle.presentation.value)
        assertTrue("private native ownership must keep replacement inputs disabled", lifecycle.busy.value)
        assertEquals(1, operation.releaseCalls)

        val poll = lifecycle.refreshPcv3().getOrThrow()
        assertTrue(poll is Pcv3Presentation.Final)
        assertFalse("released terminal ownership must unblock new input", lifecycle.busy.value)
        assertEquals("one later refresh performs one release retry", 2, operation.releaseCalls)
    }

    @Test
    fun `PCV3 start code with a handle cancels and later drains without exposing authority`() = runTest {
        val operation = ContractOperation("pcv3-start-code", pcv3WorkingSnapshot())
        val lifecycle = lifecycleFor(ContractTransport(operation, startCode = "PCV3_BRIDGE_INPUT_UNAVAILABLE"))

        val result = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile)

        assertTrue(result.isFailure)
        assertEquals("PCV3_BRIDGE_INPUT_UNAVAILABLE", result.exceptionOrNull()?.message)
        assertEquals("the contradictory handle is cancelled immediately", 1, operation.cancelCalls)
        assertNull("a contradictory handle must remain private while draining", lifecycle.presentation.value)
        assertEquals(0, operation.releaseCalls)

        operation.replaceSnapshot(pcv3CancelledSnapshot())
        assertTrue(lifecycle.refreshPcv3().getOrThrow() is Pcv3Presentation.Final)
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 accessor failure cancels private ownership and a later refresh drains it`() = runTest {
        val operation = ContractOperation("pcv3-accessor-failure", pcv3WorkingSnapshot())
        operation.failNextSnapshots(1)
        val lifecycle = lifecycleFor(ContractTransport(operation))

        val result = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile)

        assertTrue(result.isFailure)
        assertEquals(1, operation.cancelCalls)
        assertNull("failed projection must expose no stale live capability", lifecycle.presentation.value)

        operation.replaceSnapshot(pcv3CancelledSnapshot())
        assertTrue(lifecycle.refreshPcv3().getOrThrow() is Pcv3Presentation.Final)
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 archive action atomically accepts its returned terminal snapshot`() = runTest {
        val operation = ContractOperation("pcv3-archive-return", pcv3ArchivePendingSnapshot())
        val entered = CompletableDeferred<Unit>()
        val releaseExtract = CompletableDeferred<Unit>().also { it.complete(Unit) }
        val archive = ContractArchive(operation, entered, releaseExtract, failFreshSnapshot = true)
        operation.installArchive(archive)
        val lifecycle = safLifecycleFor(ContractTransport(operation))

        val live = lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        val result = lifecycle.exportPcv3Archive(
            live.operationId,
            live.generation,
            opaqueSafRoot(),
            ReadySafPublisher,
        )

        assertTrue("the exact action return replaces archive-pending", result.isSuccess)
        assertTrue(lifecycle.presentation.value is Pcv3Presentation.Final)
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `PCV3 archive close publishes Go no-output result and consumes capability once`() = runTest {
        val operation = ContractOperation("pcv3-archive-close", pcv3ArchivePendingSnapshot())
        val archive = ContractArchive(
            operation = operation,
            entered = CompletableDeferred<Unit>(),
            release = CompletableDeferred<Unit>().also { it.complete(Unit) },
            terminalSnapshot = pcv3ArchiveClosedSnapshot(),
        )
        operation.installArchive(archive)
        val lifecycle = safLifecycleFor(ContractTransport(operation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        assertTrue(lifecycle.closePcv3Archive().isSuccess)

        val final = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals("operation-failed", final.snapshot.semantic.outcome)
        assertEquals("output-publication", final.snapshot.semantic.stage)
        assertEquals("PCV3_OPERATION_FAILED", final.snapshot.semantic.code)
        assertEquals("none", final.snapshot.diagnostic)
        assertEquals("no-output", final.snapshot.completionClass)
        assertEquals(listOf("cleanup-incomplete"), final.snapshot.warnings)
        assertFalse(final.snapshot.publication.attempted)
        assertFalse(final.snapshot.archivePending)
        assertEquals(1, archive.closeCalls)
        assertEquals(1, operation.releaseCalls)
        assertTrue("the consumed Close authority cannot run twice", lifecycle.closePcv3Archive().isFailure)
        assertEquals(1, archive.closeCalls)
    }

    @Test
    fun `PCV3 resource pump reads only for challenges and serializes two fresh one-shot submissions`() = runTest {
        val operation = ContractOperation("pcv3-resource", pcv3WorkingSnapshot())
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val observations = ArrayDeque(
            listOf(
                resourceObservation(available = 3_000L, lowMemory = false),
                resourceObservation(available = 2_500L, lowMemory = true),
            ),
        )
        val reader = RecordingResourceReader { observations.removeFirstOrNull() }

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        assertTrue(lifecycle.installResourceObservationReader(reader))

        lifecycle.refreshPcv3().getOrThrow()
        assertEquals("no challenge must not sample device state", 0, reader.calls)

        val first = ContractResourceChallenge(operation)
        operation.installResourceChallenge(first)
        lifecycle.refreshPcv3().getOrThrow()

        val second = ContractResourceChallenge(operation)
        operation.installResourceChallenge(second)
        val refreshes = listOf(
            async(Dispatchers.Default) { lifecycle.refreshPcv3() },
            async(Dispatchers.Default) { lifecycle.refreshPcv3() },
        )
        refreshes.forEach { assertTrue(it.await().isSuccess) }

        assertEquals(2, reader.calls)
        assertEquals(listOf(resourceObservation(3_000L, false)), first.submissions)
        assertEquals(listOf(resourceObservation(2_500L, true)), second.submissions)
        assertEquals("the consumed challenge is not retained or replayed", 1, second.submitCalls)
    }

    @Test
    fun `PCV3 resource boundary failure stops only that generation and a later generation resets`() = runTest {
        val first = ContractOperation("pcv3-resource-failed", pcv3WorkingSnapshot())
        val second = ContractOperation("pcv3-resource-next", pcv3WorkingSnapshot())
        val transport = SequencedContractTransport(ArrayDeque(listOf(first, second)))
        val lifecycle = lifecycleFor(transport)
        val failedReader = RecordingResourceReader { null }

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        first.installResourceChallenge(ContractResourceChallenge(first))
        assertTrue(lifecycle.installResourceObservationReader(failedReader))
        lifecycle.refreshPcv3().getOrThrow()
        lifecycle.refreshPcv3().getOrThrow()
        assertEquals("a null observation disables retries for the generation", 1, failedReader.calls)
        assertFalse(
            "a stopped generation cannot be re-armed with another reader",
            lifecycle.installResourceObservationReader(
                RecordingResourceReader { resourceObservation(3_500L, false) },
            ),
        )
        assertTrue(lifecycle.presentation.value is Pcv3Presentation.Live)

        first.replaceSnapshot(pcv3CleanSnapshot())
        assertTrue(lifecycle.refreshPcv3().getOrThrow() is Pcv3Presentation.Final)
        val terminal = lifecycle.presentation.value as Pcv3Presentation.Final
        assertTrue(lifecycle.dismissPcv3(terminal.operationId, terminal.generation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        val nextChallenge = ContractResourceChallenge(second)
        second.installResourceChallenge(nextChallenge)
        val nextReader = RecordingResourceReader { resourceObservation(2_000L, false) }
        assertTrue(lifecycle.installResourceObservationReader(nextReader))
        lifecycle.refreshPcv3().getOrThrow()

        assertEquals(1, nextReader.calls)
        assertEquals(1, nextChallenge.submitCalls)
        assertTrue("a pump boundary failure never invents a terminal result", lifecycle.presentation.value is Pcv3Presentation.Live)
    }

    @Test
    fun `PCV3 resource accessor and submit failures are bounded without retries or terminal invention`() = runTest {
        listOf<Throwable>(
            IllegalStateException("memory service failed"),
            NoClassDefFoundError("stale Android observation boundary"),
        ).forEachIndexed { index, failure ->
            val operation = ContractOperation("pcv3-reader-$index", pcv3WorkingSnapshot())
            val challenge = ContractResourceChallenge(operation)
            val lifecycle = lifecycleFor(ContractTransport(operation))
            val reader = RecordingResourceReader { throw failure }
            lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
            operation.installResourceChallenge(challenge)
            assertTrue(lifecycle.installResourceObservationReader(reader))

            assertTrue(lifecycle.refreshPcv3().isSuccess)
            assertTrue(lifecycle.refreshPcv3().isSuccess)
            assertEquals("failed reader must not be retried", 1, reader.calls)
            assertEquals(0, challenge.submitCalls)
            assertFalse(
                "reader failure retires the generation's installation right",
                lifecycle.installResourceObservationReader(
                    RecordingResourceReader { resourceObservation(3_500L, false) },
                ),
            )
            assertTrue(lifecycle.presentation.value is Pcv3Presentation.Live)
        }

        val failures = listOf<Throwable>(
            IllegalStateException("native accessor failed"),
            NoSuchMethodError("resourceChallenge absent from stale AAR"),
        )
        failures.forEachIndexed { index, failure ->
            val operation = ContractOperation("pcv3-accessor-$index", pcv3WorkingSnapshot())
            val lifecycle = lifecycleFor(ContractTransport(operation))
            val reader = RecordingResourceReader { resourceObservation(3_000L, false) }
            lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
            assertTrue(lifecycle.installResourceObservationReader(reader))
            operation.resourceFailure = failure

            assertTrue(lifecycle.refreshPcv3().isSuccess)
            assertTrue(lifecycle.refreshPcv3().isSuccess)
            assertEquals(0, reader.calls)
            assertEquals("failed accessor must not be retried", 1, operation.resourceAccesses)
            assertFalse(
                "accessor failure retires the generation's installation right",
                lifecycle.installResourceObservationReader(
                    RecordingResourceReader { resourceObservation(3_500L, false) },
                ),
            )
            assertTrue(lifecycle.presentation.value is Pcv3Presentation.Live)
        }

        listOf<Throwable?>(null, IllegalStateException("submit failed"), NoSuchMethodError("stale submit")).forEachIndexed {
                index, failure ->
            val operation = ContractOperation("pcv3-submit-$index", pcv3WorkingSnapshot())
            val challenge = ContractResourceChallenge(operation, consumed = false, failure = failure)
            val lifecycle = lifecycleFor(ContractTransport(operation))
            val reader = RecordingResourceReader { resourceObservation(3_000L, false) }
            lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
            operation.installResourceChallenge(challenge)
            assertTrue(lifecycle.installResourceObservationReader(reader))

            assertTrue(lifecycle.refreshPcv3().isSuccess)
            assertTrue(lifecycle.refreshPcv3().isSuccess)
            assertEquals("failed submission must not resample or retry", 1, reader.calls)
            assertEquals(1, challenge.submitCalls)
            assertFalse(
                "submit refusal retires the generation's installation right",
                lifecycle.installResourceObservationReader(
                    RecordingResourceReader { resourceObservation(3_500L, false) },
                ),
            )
            assertTrue(lifecycle.presentation.value is Pcv3Presentation.Live)
        }
    }

    @Test
    fun `PCV3 resource cancellation propagates exactly and disables that generation`() = runTest {
        val operation = ContractOperation("pcv3-resource-cancel", pcv3WorkingSnapshot())
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val cancellation = CancellationException("cancel resource observation")
        val reader = RecordingResourceReader { throw cancellation }
        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        operation.installResourceChallenge(ContractResourceChallenge(operation))
        assertTrue(lifecycle.installResourceObservationReader(reader))

        val thrown = runCatching { lifecycle.refreshPcv3() }.exceptionOrNull()
        assertSame(cancellation, thrown)
        assertFalse(
            "cancellation retires the generation's installation right",
            lifecycle.installResourceObservationReader(
                RecordingResourceReader { resourceObservation(3_500L, false) },
            ),
        )
        assertTrue(lifecycle.refreshPcv3().isSuccess)
        assertEquals(1, reader.calls)
        assertTrue(lifecycle.presentation.value is Pcv3Presentation.Live)
    }

    @Test
    fun `PCV3 action ticket blocks normal refresh after the preparation pump has retired`() = runTest {
        val operation = ContractOperation("pcv3-resource-action", pcv3ArchivePendingSnapshot())
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        operation.installArchive(ContractArchive(operation, entered, release))
        val challenge = ContractResourceChallenge(operation)
        val reader = RecordingResourceReader { resourceObservation(3_000L, false) }
        val lifecycle = lifecycleFor(ContractTransport(operation))
        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        assertTrue(lifecycle.installResourceObservationReader(reader))

        val live = lifecycle.presentation.value as Pcv3Presentation.Live
        val action = async(Dispatchers.Default) {
            lifecycle.exportPcv3Archive(live.operationId, live.generation, opaqueSafRoot(), ReadySafPublisher)
        }
        entered.await()
        // This challenge is published after Begin has handed off and its pump
        // has joined; provider/terminal work cannot keep polling observations.
        operation.installResourceChallenge(challenge)
        try {
            assertTrue(lifecycle.refreshPcv3().isFailure)
            assertEquals(0, reader.calls)
            assertEquals(0, challenge.submitCalls)
        } finally {
            release.complete(Unit)
        }
        action.await()
    }

    @Test
    fun `PCV3 cancel draining final and stale generations never submit a resource challenge`() = runTest {
        val cancelledOperation = ContractOperation("pcv3-resource-cancel-action", pcv3WorkingSnapshot())
        val cancelledChallenge = ContractResourceChallenge(cancelledOperation)
        val cancelledReader = RecordingResourceReader { resourceObservation(3_000L, false) }
        val cancelledLifecycle = lifecycleFor(ContractTransport(cancelledOperation))
        cancelledLifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        cancelledOperation.installResourceChallenge(cancelledChallenge)
        assertTrue(cancelledLifecycle.installResourceObservationReader(cancelledReader))
        cancelledLifecycle.cancelPcv3()
        assertEquals(0, cancelledChallenge.submitCalls)

        val drainingOperation = ContractOperation("pcv3-resource-drain", pcv3WorkingSnapshot())
        val drainingChallenge = ContractResourceChallenge(drainingOperation)
        drainingOperation.installResourceChallenge(drainingChallenge)
        val drainingLifecycle = lifecycleFor(
            ContractTransport(drainingOperation, startCode = "PCV3_BRIDGE_INPUT_UNAVAILABLE"),
        )
        assertTrue(drainingLifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).isFailure)
        assertFalse(drainingLifecycle.installResourceObservationReader(cancelledReader))
        drainingLifecycle.refreshPcv3()
        assertEquals(0, drainingChallenge.submitCalls)

        val oldOperation = ContractOperation("pcv3-resource-old", pcv3WorkingSnapshot())
        val newOperation = ContractOperation("pcv3-resource-new", pcv3WorkingSnapshot())
        val transport = SequencedContractTransport(ArrayDeque(listOf(oldOperation, newOperation)))
        val lifecycle = lifecycleFor(transport)
        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        oldOperation.replaceSnapshot(pcv3CleanSnapshot())
        val final = lifecycle.refreshPcv3().getOrThrow() as Pcv3Presentation.Final
        val staleChallenge = ContractResourceChallenge(oldOperation)
        oldOperation.installResourceChallenge(staleChallenge)
        lifecycle.refreshPcv3()
        assertEquals(0, staleChallenge.submitCalls)
        assertTrue(lifecycle.dismissPcv3(final.operationId, final.generation))

        lifecycle.start(pcv3Request(), "password".toCharArray(), pcv3ReceiptFile).getOrThrow()
        val nextReader = RecordingResourceReader { resourceObservation(2_000L, false) }
        assertTrue(lifecycle.installResourceObservationReader(nextReader))
        lifecycle.refreshPcv3()
        assertEquals(0, staleChallenge.submitCalls)
        assertEquals("the stale challenge never causes a new-generation observation", 0, nextReader.calls)
    }

    @Test
    fun `PCV3 cancellation while waiting for lifecycle ownership clears caller password`() = runTest {
        val snapshotEntered = CompletableDeferred<Unit>()
        val releaseSnapshot = CompletableDeferred<Unit>()
        val operation = ContractOperation("pcv3-blocked-snapshot", pcv3WorkingSnapshot())
        operation.blockNextSnapshot(snapshotEntered, releaseSnapshot)
        val lifecycle = lifecycleFor(ContractTransport(operation))
        val first = async(Dispatchers.Default) {
            lifecycle.start(pcv3Request(), "first".toCharArray(), pcv3ReceiptFile)
        }
        snapshotEntered.await()

        val waitingPassword = "must-clear".toCharArray()
        // UNDISPATCHED guarantees the caller actually parks at the lifecycle
        // mutex before cancelAndJoin; a plain launch races the cancellation and
        // can leave the blocked snapshot gate (and runTest) hanging forever.
        val waiting = launch(Dispatchers.Default, start = CoroutineStart.UNDISPATCHED) {
            lifecycle.start(pcv3Request(), waitingPassword, pcv3ReceiptFile)
        }
        waiting.cancelAndJoin()

        try {
            assertTrue("mutex cancellation must not retain caller password", waitingPassword.all { it == '\u0000' })
        } finally {
            releaseSnapshot.complete(Unit)
        }
        assertTrue(first.await().isSuccess)
    }

    private fun lifecycleFor(
        transport: Pcv3Transport,
        receiptPersistence: Pcv3ReceiptPersistence? = null,
    ): Pcv3Lifecycle = if (receiptPersistence == null) {
        Pcv3Lifecycle(Pcv3Bridge(transport))
    } else {
        Pcv3Lifecycle(Pcv3Bridge(transport), receiptPersistence)
    }

    private fun safLifecycleFor(transport: Pcv3Transport): Pcv3Lifecycle = Pcv3Lifecycle(
        bridge = Pcv3Bridge(transport),
        receiptCustodyFactory = Pcv3ReceiptCustodyFactory { _, initial ->
            InMemoryReceiptCustody(initial)
        },
    )

    private fun opaqueSafRoot(): Uri = mockk(relaxed = true)

    private object ReadySafPublisher : Pcv3SafPublisher {
        override fun newCancellation(): Pcv3SafCancellation = object : Pcv3SafCancellation {
            @Volatile
            private var cancelled = false
            override fun isCancelled(): Boolean = cancelled
            override fun cancel() {
                cancelled = true
            }
        }

        override fun publish(
            root: Uri,
            manifest: Pcv3SafManifest,
            session: Pcv3SafEntrySession,
            cancellation: Pcv3SafCancellation,
        ): Pcv3SafPublicationResult = if (cancellation.isCancelled()) {
            Pcv3SafPublicationResult.NEEDS_ABORT
        } else {
            Pcv3SafPublicationResult.READY_TO_FINISH
        }
    }

    private class InMemoryReceiptCustody(
        initial: ReceiptCustody,
    ) : Pcv3ReceiptCustodyCapability {
        override var custody: ReceiptCustody = initial
            private set

        override fun transition(desiredReceipt: String?): ReceiptCustody {
            if (custody === ReceiptCustody.Unknown) return custody
            custody = desiredReceipt?.let(ReceiptCustody::Exact) ?: ReceiptCustody.None
            return custody
        }
    }

    private fun resourceObservation(available: Long, lowMemory: Boolean) = Pcv3AndroidResourceObservation(
        totalRamBytes = 8_000L,
        effectiveAvailableBytes = available,
        platformThresholdBytes = 500L,
        processFootprintBytes = 200L,
        processIs64Bit = true,
        lowMemory = lowMemory,
    )

    private fun pcv3Request() = Pcv3Request(
        mode = "read-normal",
        factorPolicy = "password",
        keyfileOrder = "none",
        source = "input",
        target = "output",
        keyfiles = emptyList(),
    )

    private fun pcv3WorkingSnapshot(): Pcv3SnapshotData = Pcv3SnapshotData(
        statusCode = "none",
        statusArgs = emptyList(),
        outcome = "unknown-outcome",
        stage = "none",
        code = "PCV3_UNKNOWN",
        forceProvenance = "none",
        d1BootstrapProvenance = "none",
        detailStage = "none",
        publicationAttempted = false,
        publicationState = "none",
        publicationStage = "none",
        publicationCode = "none",
        diagnostic = "none",
        completionClass = "unknown",
        args = emptyList(),
        warnings = emptyList(),
        archivePending = false,
    )

    private fun pcv3ArchivePendingSnapshot(): Pcv3SnapshotData = Pcv3SnapshotData(
        statusCode = "none", statusArgs = emptyList(), outcome = "success", stage = "none", code = "PCV3_SUCCESS",
        forceProvenance = "none", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = false, publicationState = "none", publicationStage = "none", publicationCode = "none",
        diagnostic = "none", completionClass = "archive-pending", args = emptyList(), warnings = emptyList(), archivePending = true,
    )

    private fun pcv3SafActiveSnapshot(): Pcv3SnapshotData = Pcv3SnapshotData(
        statusCode = "publishing", statusArgs = emptyList(), outcome = "success", stage = "none", code = "PCV3_SUCCESS",
        forceProvenance = "none", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = true, publicationState = "publication-indeterminate",
        publicationStage = "output-publication", publicationCode = "PCV3_PUBLICATION_INDETERMINATE",
        diagnostic = "none", completionClass = "publication-indeterminate", args = emptyList(),
        warnings = listOf("publication-indeterminate"),
        archivePending = false, restoredReceipt = "active-receipt",
    )

    private fun pcv3SafTerminalSnapshot(): Pcv3SnapshotData = Pcv3SnapshotData(
        statusCode = "none", statusArgs = emptyList(), outcome = "success", stage = "none", code = "PCV3_SUCCESS",
        forceProvenance = "none", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = true, publicationState = "published-durability-uncertain",
        publicationStage = "directory-sync", publicationCode = "PCV3_PUBLICATION_DURABILITY_UNCERTAIN",
        diagnostic = "none", completionClass = "durability-uncertain", args = emptyList(),
        warnings = listOf("durability-uncertain"), archivePending = false, restoredReceipt = "terminal-receipt",
    )

    private fun pcv3CleanSnapshot(): Pcv3SnapshotData = Pcv3SnapshotData(
        statusCode = "none", statusArgs = emptyList(), outcome = "success", stage = "none", code = "PCV3_SUCCESS",
        forceProvenance = "none", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = true, publicationState = "published-durable", publicationStage = "none",
        publicationCode = "PCV3_PUBLICATION_PUBLISHED_DURABLE", diagnostic = "none", completionClass = "clean",
        args = emptyList(), warnings = emptyList(), archivePending = false,
    )

    private fun pcv3WarningSnapshot(): Pcv3SnapshotData = Pcv3SnapshotData(
        statusCode = "none", statusArgs = emptyList(), outcome = "force-partial", stage = "record-auth", code = "PCV3_FORCE_PARTIAL",
        forceProvenance = "partial", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = true, publicationState = "published-durable", publicationStage = "none",
        publicationCode = "PCV3_PUBLICATION_PUBLISHED_DURABLE", diagnostic = "none", completionClass = "warning",
        args = emptyList(), warnings = listOf("force-partial"), archivePending = false,
    )

    private fun pcv3ForceUnverifiedSnapshot(): Pcv3SnapshotData = pcv3WarningSnapshot().copy(
        outcome = "force-unverified",
        code = "PCV3_FORCE_UNVERIFIED",
        forceProvenance = "unverified",
        warnings = listOf("force-unverified"),
    )

    private fun pcv3AuthenticatedDegradedSnapshot(): Pcv3SnapshotData = pcv3WarningSnapshot().copy(
        outcome = "authenticated-degraded",
        code = "PCV3_AUTHENTICATED_DEGRADED",
        forceProvenance = "none",
        warnings = listOf("authenticated-degraded"),
    )

    private fun pcv3PartialArtifactMetadata() = Pcv3ArtifactMetadataData(
        kind = "partial",
        role = "none",
        plaintextLength = "18446744073709551615",
        finalStatus = "missing",
        rangeCount = "2",
        verifiedCount = "1",
        unverifiedCount = "0",
        missingCount = "1",
    )

    private fun pcv3UnverifiedArtifactMetadata() = Pcv3ArtifactMetadataData(
        kind = "unverified-forensic",
        role = "backup",
        plaintextLength = "17",
        finalStatus = "unverified",
        rangeCount = "2",
        verifiedCount = "0",
        unverifiedCount = "2",
        missingCount = "0",
    )

    private fun pcv3ArtifactPage(
        offset: String,
        recordIndex: String = "0",
    ) = Pcv3ArtifactPageData(
        offsetDecimal = offset,
        ranges = listOf(
            Pcv3ArtifactRangeData(recordIndex, "0", "7", "verified"),
        ),
    )

    private fun pcv3CancelledSnapshot(): Pcv3SnapshotData = Pcv3SnapshotData(
        statusCode = "none", statusArgs = emptyList(), outcome = "operation-failed", stage = "cancellation",
        code = "PCV3_OPERATION_FAILED", forceProvenance = "none", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = false, publicationState = "none", publicationStage = "none", publicationCode = "none",
        diagnostic = "cancellation", completionClass = "refused", args = emptyList(), warnings = emptyList(), archivePending = false,
    )

    private fun pcv3ArchiveClosedSnapshot(): Pcv3SnapshotData = Pcv3SnapshotData(
        statusCode = "none", statusArgs = emptyList(), outcome = "operation-failed", stage = "output-publication",
        code = "PCV3_OPERATION_FAILED", forceProvenance = "none", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = false, publicationState = "none", publicationStage = "none", publicationCode = "none",
        diagnostic = "none", completionClass = "no-output", args = emptyList(),
        warnings = listOf("cleanup-incomplete"), archivePending = false,
    )

    private fun pcv3DurabilityUncertainSnapshot(receipt: String): Pcv3SnapshotData = Pcv3SnapshotData(
        statusCode = "none", statusArgs = emptyList(), outcome = "success", stage = "none", code = "PCV3_SUCCESS",
        forceProvenance = "verified", d1BootstrapProvenance = "matching", detailStage = "metadata",
        publicationAttempted = true, publicationState = "published-durability-uncertain", publicationStage = "directory-sync",
        publicationCode = "PCV3_PUBLICATION_DURABILITY_UNCERTAIN", diagnostic = "none",
        completionClass = "durability-uncertain", args = listOf("7", "11", "13", "17"),
        warnings = listOf("cleanup-incomplete", "durability-uncertain"), archivePending = false, restoredReceipt = receipt,
    )

    private class ContractTransport(
        private val operation: Pcv3OperationCapability?,
        private val startCode: String = "",
        private val restored: Pcv3RestoredReceiptData = Pcv3RestoredReceiptData("PCV3_RECEIPT_INVALID", "", "", null),
        private val startEntered: CompletableDeferred<Unit>? = null,
        private val startRelease: CompletableDeferred<Unit>? = null,
    ) : Pcv3Transport {
        var startCalls = 0
        var restoreCalls = 0
        var restoredInput: String? = null

        override fun start(requestJson: String, password: ByteArray): Pcv3StartData {
            startCalls += 1
            startEntered?.complete(Unit)
            startRelease?.let { runBlocking { it.await() } }
            return Pcv3StartData(startCode, operation)
        }

        override fun restoreReceipt(receipt: String): Pcv3RestoredReceiptData {
            restoreCalls += 1
            restoredInput = receipt
            return restored
        }
    }

    private class SequencedContractTransport(
        private val operations: ArrayDeque<Pcv3OperationCapability>,
    ) : Pcv3Transport {
        override fun start(requestJson: String, password: ByteArray): Pcv3StartData =
            Pcv3StartData("", operations.removeFirst())

        override fun restoreReceipt(receipt: String) =
            Pcv3RestoredReceiptData("PCV3_RECEIPT_INVALID", "", "", null)
    }

    private class ContractOperation(
        override val id: String,
        initialSnapshot: Pcv3SnapshotData,
        private val events: MutableList<String>? = null,
        private val recordArtifactAccess: Boolean = false,
    ) : Pcv3OperationCapability {
        private val lock = Any()
        private var snapshotData = initialSnapshot
        private var terminal = initialSnapshot.completionClass != "unknown"
        private var released = false
        private var consentCapability: ContractConsent? = null
        private var archiveCapability: ContractArchive? = null
        private var outputCapability: ContractOutput? = null
        private var resourceChallengeCapability: ContractResourceChallenge? = null
        private var artifactInspectionCapability: ContractArtifactInspection? = null

        var cancelCalls = 0
            private set
        var releaseCalls = 0
            private set
        var releaseCode: String = ""
        val releaseCodes = mutableListOf<String>()
        val releaseFailures = mutableListOf<Throwable>()
        private var snapshotFailures = 0
        private val snapshotFailureQueue = mutableListOf<Throwable>()
        private var outputAccesses = 0
        private var outputFailureOnAccess: Pair<Int, Throwable>? = null
        private var archiveActionInFlight = false
        private var outputActionInFlight = false
        private var snapshotEntered: CompletableDeferred<Unit>? = null
        private var snapshotRelease: CompletableDeferred<Unit>? = null
        var resourceAccesses = 0
            private set
        var resourceFailure: Throwable? = null
        var artifactAccesses = 0
            private set
        var artifactFailure: Throwable? = null

        fun replaceSnapshot(next: Pcv3SnapshotData) = synchronized(lock) {
            snapshotData = next
            terminal = terminal || next.completionClass != "unknown"
        }
        fun installConsent(consent: ContractConsent) = synchronized(lock) { consentCapability = consent }
        fun clearConsent(consent: ContractConsent) = synchronized(lock) {
            if (consentCapability === consent) consentCapability = null
        }
        fun installArchive(archive: ContractArchive) = synchronized(lock) { archiveCapability = archive }
        fun installOutput(output: ContractOutput) = synchronized(lock) { outputCapability = output }
        fun installResourceChallenge(challenge: ContractResourceChallenge) = synchronized(lock) {
            resourceChallengeCapability = challenge
        }
        fun installArtifactInspection(inspection: ContractArtifactInspection) = synchronized(lock) {
            artifactInspectionCapability = inspection
        }
        fun clearResourceChallenge(challenge: ContractResourceChallenge) = synchronized(lock) {
            if (resourceChallengeCapability === challenge) resourceChallengeCapability = null
        }
        fun clearOutput(output: ContractOutput) = synchronized(lock) {
            if (outputCapability === output) outputCapability = null
        }
        fun failNextSnapshots(count: Int) = synchronized(lock) { snapshotFailures = count }
        fun failSnapshots(vararg failures: Throwable) = synchronized(lock) {
            snapshotFailureQueue.addAll(failures.toList())
        }
        fun failOutputAccessorAfterNextAccess(failure: Throwable) = synchronized(lock) {
            outputFailureOnAccess = (outputAccesses + 2) to failure
        }
        fun beginArchiveAction(archive: ContractArchive): Boolean = synchronized(lock) {
            if (released || archiveCapability !== archive || archiveActionInFlight) return@synchronized false
            archiveCapability = null
            archiveActionInFlight = true
            true
        }
        fun finishArchiveAction() = synchronized(lock) { archiveActionInFlight = false }
        fun beginOutputAction() = synchronized(lock) { outputActionInFlight = true }
        fun finishOutputAction() = synchronized(lock) { outputActionInFlight = false }
        fun blockNextSnapshot(entered: CompletableDeferred<Unit>, release: CompletableDeferred<Unit>) = synchronized(lock) {
            snapshotEntered = entered
            snapshotRelease = release
        }

        override fun snapshot(): Pcv3SnapshotData {
            val gate = synchronized(lock) {
                if (snapshotFailures > 0) {
                    snapshotFailures -= 1
                    throw IllegalStateException("bounded snapshot failure")
                }
                if (snapshotFailureQueue.isNotEmpty()) throw snapshotFailureQueue.removeAt(0)
                val value = snapshotEntered to snapshotRelease
                snapshotEntered = null
                snapshotRelease = null
                value
            }
            gate.first?.complete(Unit)
            gate.second?.let { runBlocking { it.await() } }
            return synchronized(lock) { snapshotData }
        }
        override fun consent(): Pcv3ConsentCapability? = synchronized(lock) { consentCapability?.takeIf { it.live } }
        override fun archive(): Pcv3ArchiveCapability? = synchronized(lock) { archiveCapability?.takeIf { it.live } }
        override fun output(): Pcv3OutputCapability? = synchronized(lock) {
            outputAccesses += 1
            outputFailureOnAccess?.let { (access, failure) ->
                if (outputAccesses == access) throw failure
            }
            outputCapability?.takeIf { it.live }
        }
        override fun resourceChallenge(): Pcv3ResourceChallengeCapability? = synchronized(lock) {
            resourceAccesses += 1
            resourceFailure?.let { throw it }
            resourceChallengeCapability?.takeIf { it.live }
        }
        override fun artifactInspection(): Pcv3ArtifactInspectionCapability? = synchronized(lock) {
            artifactAccesses += 1
            if (recordArtifactAccess) events?.let { synchronized(it) { it += "artifact-access" } }
            artifactFailure?.let { throw it }
            artifactInspectionCapability
        }
        override fun cancel(): Pcv3SnapshotData = synchronized(lock) {
            cancelCalls += 1
            snapshotData
        }
        override fun release(): String = synchronized(lock) {
            releaseCalls += 1
            events?.let { synchronized(it) { it += "release" } }
            if (released || !terminal || archiveActionInFlight || outputActionInFlight ||
                consentCapability?.live == true || archiveCapability?.live == true || outputCapability?.live == true
            ) {
                return "PCV3_OPERATION_RELEASE_DENIED"
            }
            if (releaseFailures.isNotEmpty()) throw releaseFailures.removeAt(0)
            val code = if (releaseCodes.isNotEmpty()) releaseCodes.removeAt(0) else releaseCode
            if (code.isEmpty()) released = true
            code
        }
    }

    private class ContractResourceChallenge(
        private val operation: ContractOperation,
        private val consumed: Boolean = true,
        private val failure: Throwable? = null,
    ) : Pcv3ResourceChallengeCapability {
        var live = true
            private set
        var submitCalls = 0
            private set
        val submissions = mutableListOf<Pcv3AndroidResourceObservation>()

        override fun submit(observation: Pcv3AndroidResourceObservation): Boolean {
            submitCalls += 1
            failure?.let { throw it }
            submissions += observation
            if (consumed) {
                live = false
                operation.clearResourceChallenge(this)
            }
            return consumed
        }
    }

    private class RecordingResourceReader(
        private val readBlock: () -> Pcv3AndroidResourceObservation?,
    ) : Pcv3ResourceObservationReader {
        var calls = 0
            private set

        override fun read(): Pcv3AndroidResourceObservation? {
            calls += 1
            return readBlock()
        }
    }

    private class ContractArtifactInspection(
        private val metadataValue: Pcv3ArtifactMetadataData,
        private val pages: Map<String, Pcv3ArtifactPageData> = emptyMap(),
        private val events: MutableList<String>? = null,
        private val blockedOffset: String? = null,
        private val pageEntered: CompletableDeferred<Unit>? = null,
        private val pageRelease: CompletableDeferred<Unit>? = null,
    ) : Pcv3ArtifactInspectionCapability {
        private val blockLock = Any()
        private var blockedOffsetValue = blockedOffset
        private var pageEnteredValue = pageEntered
        private var pageReleaseValue = pageRelease
        var metadataCalls = 0
            private set
        var pageCalls = 0
            private set
        var metadataFailure: Throwable? = null
        var pageFailure: Throwable? = null

        fun blockPage(
            offset: String,
            entered: CompletableDeferred<Unit>,
            release: CompletableDeferred<Unit>,
        ) = synchronized(blockLock) {
            blockedOffsetValue = offset
            pageEnteredValue = entered
            pageReleaseValue = release
        }

        override fun metadata(): Pcv3ArtifactMetadataData? {
            metadataCalls += 1
            events?.let { synchronized(it) { it += "artifact-metadata" } }
            metadataFailure?.let { throw it }
            return metadataValue
        }

        override fun page(offsetDecimal: String, limit: Int): Pcv3ArtifactPageData? {
            pageCalls += 1
            pageFailure?.let { throw it }
            val block = synchronized(blockLock) {
                if (offsetDecimal == blockedOffsetValue) pageEnteredValue to pageReleaseValue else null
            }
            if (block != null) {
                block.first?.complete(Unit)
                block.second?.let { runBlocking { it.await() } }
            }
            return pages[offsetDecimal]
        }
    }

    private class RecordingReceiptPersistence(
        private val events: MutableList<String>,
    ) : Pcv3ReceiptPersistence {
        var savedReceipt: String? = null
            private set

        override fun save(file: File, receipt: String): Boolean {
            events += "receipt-save"
            savedReceipt = receipt
            return true
        }

        override fun clear(file: File): Boolean = true
    }

    private class ContractOutput(
        private val operation: ContractOperation,
        var saveResult: Pcv3OutputResultData = Pcv3OutputResultData("saved", cleanupIncomplete = false),
        private val discardResult: Pcv3OutputResultData = Pcv3OutputResultData("discarded", cleanupIncomplete = false),
        private val saveEntered: CompletableDeferred<Unit>? = null,
        private val saveRelease: CompletableDeferred<Unit>? = null,
        private val events: MutableList<String>? = null,
        var retainAfterSaveForContradiction: Boolean = false,
        private val retainAfterDiscardForDrain: Boolean = false,
    ) : Pcv3OutputCapability {
        private val lock = Any()
        @Volatile
        var live = true
            private set
        var saveCalls = 0
            private set
        var discardCalls = 0
            private set
        var saveFailure: Throwable? = null
        var discardFailure: Throwable? = null

        override fun save(destination: ParcelFileDescriptor): Pcv3OutputResultData {
            operation.beginOutputAction()
            synchronized(lock) {
                saveCalls += 1
                if (!retainAfterSaveForContradiction) live = false
            }
            if (!retainAfterSaveForContradiction) operation.clearOutput(this)
            return try {
                events?.let { synchronized(it) { it += "save-enter" } }
                saveEntered?.complete(Unit)
                saveRelease?.let { runBlocking { it.await() } }
                events?.let { synchronized(it) { it += "save-return" } }
                saveFailure?.let { throw it }
                saveResult
            } finally {
                operation.finishOutputAction()
            }
        }

        override fun discard(): Pcv3OutputResultData {
            operation.beginOutputAction()
            synchronized(lock) {
                discardCalls += 1
                if (!retainAfterDiscardForDrain) live = false
            }
            if (!retainAfterDiscardForDrain) operation.clearOutput(this)
            return try {
                events?.let { synchronized(it) { it += "discard" } }
                discardFailure?.let { throw it }
                discardResult
            } finally {
                operation.finishOutputAction()
            }
        }
    }

    private class ContractConsent(
        private val operation: ContractOperation,
        private val modeValue: String,
        private val rolesValue: List<String>,
    ) : Pcv3ConsentCapability {
        var live = true
        var chooseCalls = 0
            private set
        var refuseCalls = 0
            private set
        var chooseFailure: Throwable? = null
        var afterChoose: (() -> Unit)? = null
        private var chooseEntered: CompletableDeferred<Unit>? = null
        private var chooseRelease: CompletableDeferred<Unit>? = null

        fun blockChoose(entered: CompletableDeferred<Unit>, release: CompletableDeferred<Unit>) {
            chooseEntered = entered
            chooseRelease = release
        }

        override fun mode(): String = modeValue
        override fun roles(): List<String> = rolesValue
        override fun choose(role: String): String {
            chooseCalls += 1
            live = false
            operation.clearConsent(this)
            afterChoose?.invoke()
            chooseEntered?.complete(Unit)
            chooseRelease?.let { runBlocking { it.await() } }
            chooseFailure?.let { throw it }
            return ""
        }
        override fun refuse(): String {
            refuseCalls += 1
            live = false
            operation.clearConsent(this)
            return ""
        }
    }

    private inner class ContractArchive(
        private val operation: ContractOperation,
        private val entered: CompletableDeferred<Unit>,
        private val release: CompletableDeferred<Unit>,
        private val failFreshSnapshot: Boolean = false,
        private val terminalSnapshot: Pcv3SnapshotData? = null,
    ) : Pcv3ArchiveCapability {
        override fun cancelPreparation() = Unit
        @Volatile
        var live = true
            private set
        var beginCalls = 0
            private set
        var closeCalls = 0
            private set
        var closeFailure: Throwable? = null

        override fun close(): Pcv3SnapshotData {
            closeCalls += 1
            closeFailure?.let { throw it }
            return performAction(::finish)
        }

        override fun beginSaf(): Pcv3ArchiveBeginData {
            beginCalls += 1
            if (!operation.beginArchiveAction(this)) {
                return Pcv3ArchiveBeginData("expired", "expired", null, null)
            }
            live = false
            val active = pcv3SafActiveSnapshot()
            operation.replaceSnapshot(active)
            return Pcv3ArchiveBeginData("session", "", Session(), active)
        }

        private fun performAction(effect: () -> Pcv3SnapshotData): Pcv3SnapshotData {
            if (!operation.beginArchiveAction(this)) return operation.snapshot()
            live = false
            return try {
                effect()
            } finally {
                operation.finishArchiveAction()
            }
        }

        private fun finish(): Pcv3SnapshotData {
            return finishWith(pcv3CleanSnapshot())
        }

        private fun finishSaf(): Pcv3SnapshotData {
            return finishWith(pcv3SafTerminalSnapshot())
        }

        private fun finishWith(defaultTerminal: Pcv3SnapshotData): Pcv3SnapshotData {
            val terminal = terminalSnapshot ?: defaultTerminal
            operation.replaceSnapshot(terminal)
            if (failFreshSnapshot) operation.failNextSnapshots(1)
            return terminal
        }

        private inner class Session : Pcv3ArchiveSessionCapability {
            override fun hostMemoryBudgetBytes(): Long = PCV3_SAF_MAX_WORKING_BYTES
            override fun entryCount(): Long = 1
            override fun entry(index: Long): Pcv3ArchiveEntryData? =
                Pcv3ArchiveEntryData("file", -1, isDirectory = false, size = 1).takeIf { index == 0L }

            override fun confirmCrashReceiptPersisted(receipt: String): Pcv3ArchiveStepData =
                if (receipt == "active-receipt") {
                    Pcv3ArchiveStepData("ready", 0)
                } else {
                    Pcv3ArchiveStepData("rejected", -1)
                }

            override fun attempt(index: Long) = Pcv3ArchiveStepData("attempted", index)
            override fun ackDirectory(index: Long) = Pcv3ArchiveStepData("ready", index + 1)
            override fun writeFd(index: Long, descriptor: Long) = Pcv3ArchiveStepData("ready", index + 1)
            override fun cancel() = Pcv3ArchiveStepData("poisoned", -1)

            override fun finish(): Pcv3SnapshotData = complete()
            override fun abort(): Pcv3SnapshotData = complete()

            private fun complete(): Pcv3SnapshotData = try {
                entered.complete(Unit)
                runBlocking { release.await() }
                this@ContractArchive.finishSaf()
            } finally {
                operation.finishArchiveAction()
            }
        }
    }

    private fun setCurrentOperationForTest(state: OperationState?) {
        val stateField = OperationManager::class.java.getDeclaredField("_currentOperation")
        stateField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val flow = stateField.get(OperationManager)
            as kotlinx.coroutines.flow.MutableStateFlow<OperationState?>
        flow.value = state
    }
}
