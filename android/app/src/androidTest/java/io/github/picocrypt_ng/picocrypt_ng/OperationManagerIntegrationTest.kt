package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Real JNI/native encryption, exact retained ciphertext retry, and decryption.
 * This mandatory positive gate fails on resource refusal; compilation alone is
 * not device execution evidence. Run with a freshly built AAR and device policy.
 */
@RunWith(AndroidJUnit4::class)
class OperationManagerIntegrationTest {
    @Test
    fun encrypt_retry_save_then_decrypt_recovers_the_original_bytes() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val directory = File(context.filesDir, "pcv3-integration-${System.nanoTime()}").apply { mkdirs() }
        val lifecycle = Pcv3Lifecycle(GoBridge.pcv3Bridge)
        val plaintext = File(directory, "source.txt")
        val original = "Picocrypt-NG native bytes — éçü 0123456789".toByteArray(Charsets.UTF_8)
        plaintext.writeBytes(original)
        try {
            val target = File(directory, "created.pcv")
            lifecycle.start(
                Pcv3WriteRequest("write-normal", "password", "none", plaintext.path, target.path,
                    emptyList(), "", "standard", false),
                "testpassword".toCharArray(), File(directory, "receipt"),
            ).getOrThrow()
            lifecycle.installResourceObservationReader(Pcv3AndroidResourceObservationReader(context))
            val encrypted = waitForNativeResult(lifecycle) as Pcv3Presentation.Live
            assertEquals("clean", encrypted.snapshot.completionClass)
            val originalCiphertext = target.readBytes()
            assertFalse(originalCiphertext.contentEquals(original))

            val pipe = ParcelFileDescriptor.createPipe()
            pipe[0].close()
            assertTrue(lifecycle.savePcv3Output(encrypted.operationId, encrypted.generation, pipe[1]).isFailure)
            val retry = lifecycle.presentation.value as Pcv3Presentation.Live
            assertTrue(retry.outputPending)
            val saved = File(directory, "saved.pcv")
            lifecycle.savePcv3Output(retry.operationId, retry.generation,
                ParcelFileDescriptor.open(saved, ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_READ_WRITE),
            ).getOrThrow()
            assertArrayEquals(originalCiphertext, saved.readBytes())
            val terminal = lifecycle.presentation.value as Pcv3Presentation.Final
            assertEquals("saved", terminal.outputAction?.code)
            assertTrue(lifecycle.dismissPcv3(terminal.operationId, terminal.generation))

            val decoded = File(directory, "decoded")
            lifecycle.start(
                Pcv3Request("read-normal", "password", "none", saved.path, decoded.path, emptyList()),
                "testpassword".toCharArray(), File(directory, "receipt"),
            ).getOrThrow()
            lifecycle.installResourceObservationReader(Pcv3AndroidResourceObservationReader(context))
            val decrypted = waitForNativeResult(lifecycle) as Pcv3Presentation.Live
            assertEquals("clean", decrypted.snapshot.completionClass)
            assertArrayEquals(original, decoded.readBytes())
            lifecycle.discardPcv3Output(decrypted.operationId, decrypted.generation).getOrThrow()
        } finally {
            lifecycle.cancelCurrentPcv3ForHost()
            lifecycle.refreshPcv3()
            if (!lifecycle.busy.value) directory.deleteRecursively()
        }
    }

    private suspend fun waitForNativeResult(lifecycle: Pcv3Lifecycle): Pcv3Presentation {
        repeat(1200) {
            val presentation = lifecycle.refreshPcv3().getOrThrow()
            if (presentation.snapshot.completionClass !in listOf("", "unknown")) return presentation
            delay(100)
        }
        throw AssertionError("Native PCV3 operation did not reach a terminal result")
    }
}
