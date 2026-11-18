package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.content.res.Configuration
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.Locale
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LegacyMetadataDeviceTest {
    @Test
    fun frozenV1ReadAndLateCancellationKeepUnauthenticatedHeaderWarning() = readFrozen(
        "pico_test_v1.txt.pcv", "v1.49", LegacySecurityWarning.UNAUTHENTICATED_V1_HEADER,
    )

    @Test
    fun frozenV2ReadDoesNotInventAnAuthenticatedCommentWhenThereIsNoComment() = readFrozen(
        "pico_test_v2.txt.pcv", "v2.00", LegacySecurityWarning.NONE,
    )

    @Test
    fun frozenV2KeyfileReadKeepsPasswordOnlyHeaderAuthenticationWarning() = readFrozen(
        "pico_test_v2_keyfile_single.txt.pcv", "v2.08", LegacySecurityWarning.V2_PASSWORD_ONLY_AUTHENTICATION,
        keyfile = "keyfile_alpha.bin",
    )

    @Test
    fun wrongPasswordReturnsNoAuthenticationClaimOrPlaintext() = readFrozen(
        "pico_test_v2.txt.pcv", "v2.00", LegacySecurityWarning.NONE, wrongPassword = true,
    )

    @Test
    fun nativeResourceRefusalLeavesTheFrozenInputAndNoPlaintext() = readFrozen(
        "pico_test_v2.txt.pcv", "v2.00", LegacySecurityWarning.NONE, lowMemory = true,
    )

    @Test
    fun metadataPresentationResolvesEveryPackagedLocaleWithoutEnglishFallback() {
        val app = ApplicationProvider.getApplicationContext<Context>()
        val resources = listOf(R.string.comments_unverified, R.string.comment_authenticity_authenticated,
            R.string.comment_authenticity_unverified, R.string.legacy_v1_security_warning, R.string.legacy_v2_security_warning)
        fun localized(tag: String): Context = app.createConfigurationContext(Configuration(app.resources.configuration).apply {
            setLocale(Locale.forLanguageTag(tag))
        })
        val english = localized("en")
        for (tag in listOf("en", "ru", "de", "fr", "es", "zh-Hans", "hi", "ko")) {
            val context = localized(tag)
            for (resource in resources) {
                val text = context.getString(resource)
                assertTrue("$tag/$resource must be nonempty", text.isNotBlank())
                if (tag != "en") assertNotEquals("$tag/$resource must use its catalog", english.getString(resource), text)
            }
        }
    }

    private fun readFrozen(fixtureName: String, version: String, warning: LegacySecurityWarning,
        keyfile: String? = null, wrongPassword: Boolean = false, lowMemory: Boolean = false) {
        val app = ApplicationProvider.getApplicationContext<Context>()
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        val directory = File(app.cacheDir, "legacy-metadata-${System.nanoTime()}")
        assertTrue(directory.mkdir())
        var id: String? = null
        var settled = false
        try {
            val ciphertext = assets.open(fixtureName).use { it.readBytes() }
            val source = File(directory, "source.pcv").apply { writeBytes(ciphertext) }
            val target = File(directory, "plaintext")
            val factors = keyfile?.let { name -> listOf(File(directory, "factor").apply {
                writeBytes(assets.open(name).use { it.readBytes() })
            }.path) }.orEmpty()
            val preview = GoBridge.getDecryptionInfo(source.path).getOrThrow()
            assertEquals(version, preview.version)
            assertEquals(warning, preview.securityWarning)
            assertEquals("frozen fixture has no comment", "", preview.comments)
            assertEquals(CommentAuthenticity.UNAVAILABLE, preview.commentAuthenticity)

            val operation = GoBridge.startOperation().getOrThrow()
            id = operation
            GoBridge.startDecrypt(operation, source.path, target.path,
                (if (wrongPassword) "wrong password" else "test").toByteArray(Charsets.UTF_8),
                DecryptOptions(keyfiles = factors)).getOrThrow()
            val platformReader = Pcv3AndroidResourceObservationReader(app)
            val reader = if (lowMemory) {
                Pcv3ResourceObservationReader { platformReader.read()?.copy(lowMemory = true) }
            } else {
                platformReader
            }
            val deadline = SystemClock.elapsedRealtime() + 180_000
            var progress = GoBridge.getProgress(operation).getOrThrow()
            while (!progress.done && SystemClock.elapsedRealtime() < deadline) {
                GoBridge.supplyLegacyResourceObservation(operation, reader)
                SystemClock.sleep(20)
                progress = GoBridge.getProgress(operation).getOrThrow()
            }
            assertTrue("native legacy read timed out: $progress", progress.done)
            settled = true
            assertEquals(CommentAuthenticity.UNAVAILABLE, progress.commentAuthenticity)
            if (lowMemory) {
                assertEquals(OperationStatus.ERROR, progress.status.code)
                assertEquals("RESOURCE_LIMIT", progress.errorCode)
                assertFalse("resource refusal must not publish plaintext", target.exists())
            } else if (wrongPassword) {
                assertEquals(OperationStatus.ERROR, progress.status.code)
                assertEquals("AUTH_FAILED", progress.errorCode)
                assertEquals("", progress.legacyVersion)
                assertEquals(LegacySecurityWarning.NONE, progress.legacySecurityWarning)
                assertFalse("authentication failure must not publish plaintext", target.exists())
            } else {
                assertEquals(OperationStatus.COMPLETED, progress.status.code)
                assertEquals("", progress.errorCode)
                assertEquals("", progress.technicalError)
                assertEquals(version, progress.legacyVersion)
                assertEquals(warning, progress.legacySecurityWarning)
                assertArrayEquals(assets.open("pico_test.txt").use { it.readBytes() }, target.readBytes())
            }
            assertEquals("late cancellation must retain native terminal metadata", progress, GoBridge.cancelOperation(operation).getOrThrow())
            assertArrayEquals("reader must preserve frozen ciphertext", ciphertext, source.readBytes())
        } finally {
            try {
                if (!settled) id?.let { GoBridge.cancelOperation(it).getOrThrow() }
            } finally {
                assertTrue("owned test workspace cleanup", NoFollowFileTree.delete(app.cacheDir, directory))
            }
        }
    }
}
