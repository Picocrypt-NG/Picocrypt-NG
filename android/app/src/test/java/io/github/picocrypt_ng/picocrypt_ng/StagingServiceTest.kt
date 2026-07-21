package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class StagingServiceTest {
    @Test fun resolveCollision_uniqueWhenFree() {
        assertEquals("a.txt", StagingService.resolveCollision(emptySet(), "a.txt"))
    }
    @Test fun resolveCollision_appendsCounter() {
        assertEquals("a (1).txt", StagingService.resolveCollision(setOf("a.txt"), "a.txt"))
        assertEquals("a (2).txt", StagingService.resolveCollision(setOf("a.txt", "a (1).txt"), "a.txt"))
    }
    @Test fun resolveCollision_noExtension() {
        assertEquals("README (1)", StagingService.resolveCollision(setOf("README"), "README"))
    }
    @Test fun multiFileOutputName_isRandomEncryptedZipPcv() {
        assertEquals("encrypted-1700000000.zip.pcv", StagingService.multiFileOutputName(1_700_000_000L))
    }
    @Test fun folderOutputName_keepsRootName() {
        assertEquals("MyDocs.zip.pcv", StagingService.folderOutputName("MyDocs"))
    }
    @Test fun requiredBytes_isThreeXPlusMargin() {
        assertEquals(3L * 1000 + StagingService.SPACE_MARGIN_BYTES, StagingService.requiredBytes(1000))
    }
    @Test fun hasSpaceFor_refusesWhenTight() {
        assertEquals(false, StagingService.hasSpaceFor(total = 1000, usable = 3000))
        assertEquals(true, StagingService.hasSpaceFor(total = 1000, usable = 3L * 1000 + StagingService.SPACE_MARGIN_BYTES))
    }
    @Test fun insufficientStorageError_includesRequiredAndAvailableBytes() {
        val required = StagingService.requiredBytes(1000)
        val context = mockk<Context>()
        every {
            context.getString(R.string.error_insufficient_storage, required, 3000L)
        } returns "Need $required bytes; available 3000 bytes."

        val error = StagingService.insufficientStorageError(context, total = 1000, usable = 3000)

        assertEquals(R.string.error_insufficient_storage, error.messageResId)
        assertEquals(listOf(required, 3000L), error.messageArgs)
        assertEquals("Need $required bytes; available 3000 bytes.", error.localizedMessage(context))
    }

    @Test
    fun `staging failure wrappers use localized reasons and keep raw detail diagnostic only`() {
        val context = mockk<Context>()
        every {
            context.getString(R.string.error_reason_permission_denied)
        } returns "Localized permission denial"
        every {
            context.getString(R.string.error_read_folder_failed, "Localized permission denial")
        } returns "Localized folder failure: Localized permission denial"
        every {
            context.getString(R.string.error_copy_files_failed, "Localized permission denial")
        } returns "Localized copy failure: Localized permission denial"

        val raw = "raw provider detail /private/path"
        val expected = listOf(
            R.string.error_read_folder_failed to "Localized folder failure: Localized permission denial",
            R.string.error_copy_files_failed to "Localized copy failure: Localized permission denial",
        )

        expected.forEach { (wrapperResource, localizedDisplay) ->
            val error = StagingService.localizedCopyError(
                context,
                wrapperResource,
                SecurityException(raw),
            )

            assertEquals(wrapperResource, error.messageResId)
            assertEquals(listOf("Localized permission denial"), error.messageArgs)
            assertEquals(raw, error.technicalMessage)
            assertEquals(localizedDisplay, error.localizedMessage(context))
            assertFalse(error.userMessage.contains(raw))
            assertFalse(error.messageArgs.any { it.toString().contains(raw) })
        }
    }

    // sanitizeName: core security control for SAF path-traversal prevention
    @Test fun sanitizeName_normalNameUnchanged() {
        assertEquals("document.pdf", StagingService.sanitizeName("document.pdf"))
    }
    @Test fun sanitizeName_stripsLeadingPathSegments() {
        // File(name).name strips everything before the last separator
        assertEquals("passwd", StagingService.sanitizeName("../../etc/passwd"))
    }
    @Test fun sanitizeName_dotDotAloneBecomesUnderscore() {
        // ".." → File("..", "").name == "" on some JVMs → ".." stripped → "" → "_"
        // Either way must not produce a name that allows traversal
        val result = StagingService.sanitizeName("..")
        assert(result != "..") { "sanitizeName(\"..\") must not return \"..\" unchanged; got \"$result\"" }
        assert(result.isNotEmpty()) { "sanitizeName(\"..\") must not return empty string" }
    }
    @Test fun sanitizeName_embeddedDotDotRemoved() {
        // "a..b" contains ".." which should be stripped → "ab"
        assertEquals("ab", StagingService.sanitizeName("a..b"))
    }
    @Test fun sanitizeName_forwardSlashStrippedByFile() {
        // File("a/b").name == "b" on JVM: the leading path segment is stripped entirely.
        // The "/" never reaches the replace step; the result is the last component only.
        assertEquals("b", StagingService.sanitizeName("a/b"))
    }
    @Test fun sanitizeName_backslashReplaced() {
        assertEquals("a_b", StagingService.sanitizeName("a\\b"))
    }
    @Test fun sanitizeName_emptyStringBecomesUnderscore() {
        assertEquals("_", StagingService.sanitizeName(""))
    }
    @Test fun sanitizeName_onlyPathSeparatorsBecomesUnderscore() {
        // A name consisting solely of separators must not produce an empty/traversal result
        val result = StagingService.sanitizeName("/")
        assert(result.isNotEmpty()) { "sanitizeName(\"/\") must not return empty string" }
        assert(result != "/") { "sanitizeName(\"/\") must not return \"/\" unchanged" }
    }
}
