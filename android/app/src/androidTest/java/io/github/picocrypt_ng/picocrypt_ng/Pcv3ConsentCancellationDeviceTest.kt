package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import mobile.Mobile
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Fresh JNI gate; deterministic registration interleavings are covered by the Go test. */
@RunWith(AndroidJUnit4::class)
class Pcv3ConsentCancellationDeviceTest {
    @Test fun immediateAfterStartCancellationReleasesWithoutOutput() = cancellation(waitForConsent = false)
    @Test fun registeredConsentCancellationReleasesWithoutOutput() = cancellation(waitForConsent = true)

    private fun cancellation(waitForConsent: Boolean) {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val directory = File(context.filesDir, "consent-cancel-${System.nanoTime()}").apply { mkdirs() }
        val source = File(directory, "source.pcv").apply { writeText("claimed-pcv3") }
        val key = File(directory, "factor.key").apply { writeText("public test key") }
        val target = File(directory, "plaintext")
        val password = "test password".toByteArray()
        val request = Pcv3Request("force-unverified-normal", "password-and-keyfiles", "unordered", source.path, target.path, listOf(key.path))
        val start = Mobile.startPCV3(requireNotNull(GoBridge.buildPcv3RequestJson(request)), password)
        val operation = start.operation()
        var released = false
        try {
            assertEquals("", start.code())
            assertTrue(password.all { it == 0.toByte() })
            requireNotNull(operation)
            if (waitForConsent) {
                val deadline = SystemClock.elapsedRealtime() + 10_000
                while (operation.consent() == null && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(10)
                assertNotNull("Force must expose the real registered native consent", operation.consent())
            }
            operation.cancel()
            val deadline = SystemClock.elapsedRealtime() + 10_000
            while (operation.snapshot().completionClass() == "unknown" && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(10)
            val terminal = operation.snapshot()
            assertEquals("refused", terminal.completionClass())
            assertEquals("cancellation", terminal.diagnostic())
            assertNull(operation.consent())
            assertNull(operation.output())
            assertNull(operation.archive())
            assertFalse(target.exists())
            assertEquals("", operation.release())
            released = true
        } finally {
            password.fill(0)
            if (operation != null && !released) {
                operation.cancel()
                operation.consent()?.refuse()
                val deadline = SystemClock.elapsedRealtime() + 10_000
                while (operation.snapshot().completionClass() == "unknown" && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(10)
                assertEquals("test cleanup must release its actual native operation", "", operation.release())
            }
            assertTrue(NoFollowFileTree.delete(context.filesDir, directory))
        }
    }
}
