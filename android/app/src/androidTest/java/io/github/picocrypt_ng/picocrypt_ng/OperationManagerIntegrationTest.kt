package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * On-device integration coverage for the Kotlin -> gomobile/JNI -> Go crypto path.
 * JVM tests cover validation and state-management branches; this class keeps only
 * the behavior that requires a real Android runtime and the native AAR.
 */
@RunWith(AndroidJUnit4::class)
class OperationManagerIntegrationTest {
    
    private lateinit var context: Context

    private fun encryptFormData(
        copiedFilePath: String
    ) = FormData(
        selectedFilename = "test.txt",
        copiedFilePath = copiedFilePath,
        comments = "",
        passwordInput = "testpassword".toCharArray(),
        confirmPasswordInput = "testpassword".toCharArray(),
        reedSolomon = false,
        paranoid = false,
        deniability = false,
        keyfileFilenames = emptyList(),
        keyfileOrdered = false,
        decryptionInfo = null
    )

    private fun decryptFormData(
        copiedFilePath: String
    ) = FormData(
        selectedFilename = "test.pcv",
        copiedFilePath = copiedFilePath,
        comments = "",
        passwordInput = "testpassword".toCharArray(),
        confirmPasswordInput = "testpassword".toCharArray(),
        reedSolomon = false,
        paranoid = false,
        deniability = false,
        keyfileFilenames = emptyList(),
        keyfileOrdered = false,
        decryptionInfo = null
    )
    
    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        // Clean up any existing operations and files
        runTest {
            OperationManager.clearOperation(context, shouldCleanupFiles = true)
            FileCopyService.cleanupAllFiles(context)
        }
    }
    
    @After
    fun tearDown() {
        // Clean up after each test
        runTest {
            OperationManager.clearOperation(context, shouldCleanupFiles = true)
            FileCopyService.cleanupAllFiles(context)
        }
    }
    
    @Test
    fun encrypt_then_decrypt_recovers_the_original_bytes() = runBlocking {
        // The point of an ON-DEVICE gate: prove that real bytes survive
        // encrypt -> gomobile/JNI bridge -> native crypto -> decrypt on an actual device.
        // `go test` already covers the crypto math but never crosses the bridge, so this is
        // the only place that proves the bridge + AAR + KDF/cipher actually round-trip.
        // runBlocking (not runTest) so the wait runs in real wall-clock time.
        val original = (
            "Picocrypt-NG on-device roundtrip — éçü 0123456789 " +
                "the quick brown fox jumps over the lazy dog"
            ).toByteArray(Charsets.UTF_8)
        val internalDir = File(context.filesDir, "picocrypt_files").apply { mkdirs() }
        val plaintext = File(internalDir, "roundtrip_input.txt")
        plaintext.writeBytes(original)

        // Encrypt.
        val encStart = OperationManager.startEncrypt(
            context,
            encryptFormData(copiedFilePath = plaintext.absolutePath)
        )
        assertTrue("encrypt should start: ${encStart.exceptionOrNull()}", encStart.isSuccess)
        assertTrue(
            "encrypt operation ID must not be empty",
            encStart.getOrThrow().isNotEmpty()
        )
        val encState = waitForOperationToFinish()
        assertNull("encrypt must not finish with an error", encState.error)
        assertEquals(OperationStatus.COMPLETED, encState.status.code)
        val encryptedFile = File(encState.outputFile)
        assertTrue("encrypted volume must exist", encryptedFile.exists())
        assertFalse(
            "ciphertext must differ from plaintext (data was actually encrypted)",
            encryptedFile.readBytes().contentEquals(original)
        )

        // Exercise the real generated CancelOperation binding and ProgressResult
        // getters. Completion already won, so a late cancel must return the canonical
        // COMPLETED snapshot rather than fabricate CANCELLED in Kotlin.
        val lateCancel = GoBridge.cancelOperation(encStart.getOrThrow()).getOrThrow()
        assertEquals(OperationStatus.COMPLETED, lateCancel.status.code)
        assertEquals(1f, lateCancel.progress, 0.001f)
        assertTrue("late cancel must preserve the completed terminal snapshot", lateCancel.done)
        assertEquals("", lateCancel.technicalError)
        assertEquals("", lateCancel.errorCode)
        OperationManager.clearOperation(context, shouldCleanupFiles = false)

        // Re-stage the ciphertext as a decrypt INPUT, mirroring the real app: a picked
        // .pcv is copied to input_file.<ext>. startDecrypt's pre-clean wipes output_file.*
        // (never input_file.*), so feeding the raw encrypt output back in would delete it.
        val decryptInput = File(internalDir, "input_file.pcv")
        encryptedFile.copyTo(decryptInput, overwrite = true)

        // Decrypt the volume we just produced.
        val decStart = OperationManager.startDecrypt(
            context,
            decryptFormData(copiedFilePath = decryptInput.absolutePath)
        )
        assertTrue("decrypt should start: ${decStart.exceptionOrNull()}", decStart.isSuccess)
        assertTrue(
            "decrypt operation ID must not be empty",
            decStart.getOrThrow().isNotEmpty()
        )
        val decState = waitForOperationToFinish()
        assertNull("decrypt must not finish with an error", decState.error)
        val decryptedFile = File(decState.outputFile)
        assertTrue("decrypted output must exist", decryptedFile.exists())

        // The assertion that actually matters: the bytes came back intact.
        assertArrayEquals(
            "decrypted bytes must equal the original plaintext",
            original,
            decryptedFile.readBytes()
        )

        // The real gomobile binding must surface a missing input as the typed error the
        // UI expects. Create and remove a unique file first so the path is known-missing.
        val missingFile = File.createTempFile("detect-missing-", ".pcv", context.cacheDir)
        assertTrue("missing-file fixture must be removable", missingFile.delete())
        assertFalse("detectOperation input must not exist", missingFile.exists())

        val detection = GoBridge.detectOperation(missingFile.absolutePath)
        assertTrue("detectOperation must fail for a missing file", detection.isFailure)
        val detectionError = detection.exceptionOrNull()
        assertTrue(
            "detectOperation failure must be a GenericOperation AppError",
            detectionError is AppError.OperationError.GenericOperation
        )
        detectionError as AppError.OperationError.GenericOperation
        assertEquals(
            R.string.error_detect_operation_type_failed,
            detectionError.messageResId
        )
    }
    
    // Polls the async Go operation to completion in REAL wall-clock time. The gomobile
    // bridge is start-then-poll by design, so polling is unavoidable; the budget is large
    // enough (~60s for an Argon2id KDF that takes seconds) that only a genuine bug -- not a
    // slow emulator -- can trip it. delay() is forced onto a real dispatcher so a
    // virtual-time test scheduler cannot collapse it to zero.
    private suspend fun waitForOperationToFinish(maxPolls: Int = 600): OperationState {
        repeat(maxPolls) {
            val state = OperationManager.pollProgress()
            if (state != null && state.done) {
                return state
            }
            withContext(Dispatchers.IO) { delay(100) }
        }
        throw AssertionError("Timed out waiting for operation to finish")
    }
}
