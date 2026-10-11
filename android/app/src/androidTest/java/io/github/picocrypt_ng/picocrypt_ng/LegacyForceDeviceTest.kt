package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.os.SystemClock
import android.system.Os
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Real JNI regression: the packaged AAR must preserve the frozen legacy recovery warning. */
@RunWith(AndroidJUnit4::class)
class LegacyForceDeviceTest {
    @Test
    fun wrongKeyfileForcePreservesUnverifiedCompletion() = recover(wrongKeyfile = true)

    @Test
    fun wrongKeyfileVerifyFirstForcePreservesUnverifiedCompletion() =
        recover(wrongKeyfile = true, verifyFirst = true)

    @Test
    fun correctKeyfileForceRemainsAuthenticated() = recover(wrongKeyfile = false)

    private fun recover(wrongKeyfile: Boolean, verifyFirst: Boolean = false) {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        val directory = File(context.cacheDir, "legacy-force-${System.nanoTime()}")
        assertTrue("recovery workspace must be newly owned", directory.mkdir())
        var operationID: String? = null
        var completed = false
        try {
            val fixture = assets.open("pico_test_v2_keyfile_single.txt.pcv").use { it.readBytes() }
            val plaintext = assets.open("pico_test.txt").use { it.readBytes() }
            val source = File(directory, "source.pcv").apply { writeBytes(fixture) }
            val sourceIdentity = Os.stat(source.path)
            val keyfile = File(directory, "factor.key").apply {
                writeBytes(if (wrongKeyfile) {
                    "wrong public legacy factor".toByteArray(Charsets.UTF_8)
                } else {
                    assets.open("keyfile_alpha.bin").use { it.readBytes() }
                })
            }
            val output = File(directory, "recovered")
            val id = GoBridge.startOperation().getOrThrow()
            operationID = id
            GoBridge.startDecrypt(
                id, source.path, output.path, "test".toByteArray(Charsets.UTF_8),
                DecryptOptions(
                    keyfiles = listOf(keyfile.path), forceDecrypt = true, verifyFirst = verifyFirst,
                ),
            ).getOrThrow()
            val deadline = SystemClock.elapsedRealtime() + 180_000
            var result = GoBridge.getProgress(id).getOrThrow()
            while (!result.done && SystemClock.elapsedRealtime() < deadline) {
                SystemClock.sleep(20)
                result = GoBridge.getProgress(id).getOrThrow()
            }
            assertTrue("real JNI recovery did not terminate: $result", result.done)
            completed = true
            assertEquals("", result.technicalError)
            assertEquals("", result.errorCode)
            assertEquals(
                if (wrongKeyfile) "COMPLETED_UNVERIFIED" else "COMPLETED", result.status.code,
            )
            assertTrue("forced recovery must remain available for explicit Save", output.isFile)
            val recovered = output.readBytes()
            assertTrue("forced recovery must retain output bytes", recovered.isNotEmpty())
            if (wrongKeyfile) {
                assertFalse("wrong-factor bytes must not be mistaken for plaintext", plaintext.contentEquals(recovered))
            } else {
                assertTrue("correct factors must retain frozen compatibility", plaintext.contentEquals(recovered))
            }
            val sourceAfter = Os.stat(source.path)
            assertEquals("recovery must preserve encrypted-source device", sourceIdentity.st_dev, sourceAfter.st_dev)
            assertEquals("recovery must preserve encrypted-source inode", sourceIdentity.st_ino, sourceAfter.st_ino)
            assertTrue("recovery must preserve encrypted-source bytes", fixture.contentEquals(source.readBytes()))
        } finally {
            try {
                if (!completed) operationID?.let { GoBridge.cancelOperation(it).getOrThrow() }
            } finally {
                assertTrue("test workspace cleanup", NoFollowFileTree.delete(context.cacheDir, directory))
            }
        }
    }
}
