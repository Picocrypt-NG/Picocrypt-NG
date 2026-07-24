package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import io.mockk.every
import io.mockk.mockk
import java.nio.file.Files
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.io.path.createTempDirectory

class StagingServiceTest {
    @Test
    fun `wipeStaging removes a real staged plaintext tree`() {
        val filesDir = createTempDirectory(prefix = "staging_wipe_success").toFile()
        val context = mockk<Context>()
        val stagedFile = java.io.File(filesDir, "picocrypt_files/staging/folder/plaintext.txt")
        every { context.filesDir } returns filesDir

        try {
            assertTrue(stagedFile.parentFile!!.mkdirs())
            stagedFile.writeText("sensitive plaintext")

            assertTrue("Cleanup must report successful deletion", StagingService.wipeStaging(context))
            assertFalse(
                "The actual staging tree must be absent after successful cleanup",
                java.io.File(filesDir, "picocrypt_files/staging").exists(),
            )
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun `wipeStaging reports a real filesystem deletion failure`() {
        val filesDir = createTempDirectory(prefix = "staging_wipe_failure").toFile()
        val context = mockk<Context>()
        val internalDir = java.io.File(filesDir, "picocrypt_files")
        val stagingDir = java.io.File(internalDir, "staging")
        val stagedFile = java.io.File(stagingDir, "plaintext.txt")
        every { context.filesDir } returns filesDir

        try {
            assertTrue(stagingDir.mkdirs())
            stagedFile.writeText("sensitive plaintext")
            assertTrue(stagingDir.setWritable(false, false))
            assertTrue(internalDir.setWritable(false, false))

            assertFalse(
                "Cleanup must not claim success while the real staging tree remains",
                StagingService.wipeStaging(context),
            )
            assertTrue("The undeletable plaintext proves cleanup failed", stagedFile.exists())
        } finally {
            stagingDir.setWritable(true, false)
            internalDir.setWritable(true, false)
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun `wipeStaging removes an internal symlink without following it`() {
        val filesDir = createTempDirectory(prefix = "staging_wipe_link").toFile()
        val outsideDir = createTempDirectory(prefix = "staging_wipe_outside").toFile()
        val stagingDir = java.io.File(filesDir, "picocrypt_files/staging")
        val stagedFile = java.io.File(stagingDir, "plaintext.txt")
        val outsideFile = java.io.File(outsideDir, "foreign.txt")
        val link = java.io.File(stagingDir, "outside-link")
        val outsideBytes = "must survive cleanup".toByteArray()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir

        try {
            assertTrue(stagingDir.mkdirs())
            stagedFile.writeText("staged plaintext")
            outsideFile.writeBytes(outsideBytes)
            Files.createSymbolicLink(link.toPath(), outsideDir.toPath())

            assertTrue(StagingService.wipeStaging(context))

            assertFalse("The staging tree must be removed", stagingDir.exists())
            assertTrue("Cleanup must not remove the symlink target", outsideDir.isDirectory)
            assertArrayEquals(
                "Cleanup must preserve bytes outside staging",
                outsideBytes,
                outsideFile.readBytes(),
            )
        } finally {
            Files.deleteIfExists(link.toPath())
            filesDir.deleteRecursively()
            outsideDir.deleteRecursively()
        }
    }

    @Test
    fun `wipeStaging unlinks a symlinked staging root without touching its target`() {
        val filesDir = createTempDirectory(prefix = "staging_wipe_root_link").toFile()
        val outsideDir = createTempDirectory(prefix = "staging_wipe_root_outside").toFile()
        val internalDir = java.io.File(filesDir, "picocrypt_files")
        val stagingLink = java.io.File(internalDir, "staging")
        val outsideFile = java.io.File(outsideDir, "foreign.txt")
        val outsideBytes = "outside root target".toByteArray()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir

        try {
            assertTrue(internalDir.mkdirs())
            outsideFile.writeBytes(outsideBytes)
            Files.createSymbolicLink(stagingLink.toPath(), outsideDir.toPath())

            assertTrue(StagingService.wipeStaging(context))

            assertFalse("The staging root symlink itself must be removed", Files.exists(stagingLink.toPath()))
            assertTrue("The root symlink target must remain", outsideDir.isDirectory)
            assertArrayEquals(outsideBytes, outsideFile.readBytes())
        } finally {
            Files.deleteIfExists(stagingLink.toPath())
            filesDir.deleteRecursively()
            outsideDir.deleteRecursively()
        }
    }

    @Test
    fun `wipeStaging rejects an intermediate symlink without touching its target`() {
        val filesDir = createTempDirectory(prefix = "staging_wipe_intermediate_link").toFile()
        val outsideDir = createTempDirectory(prefix = "staging_wipe_intermediate_outside").toFile()
        val internalLink = java.io.File(filesDir, "picocrypt_files")
        val outsideStaging = java.io.File(outsideDir, "staging")
        val outsideFile = java.io.File(outsideStaging, "foreign.txt")
        val outsideBytes = "outside intermediate target".toByteArray()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir

        try {
            assertTrue(outsideStaging.mkdirs())
            outsideFile.writeBytes(outsideBytes)
            Files.createSymbolicLink(internalLink.toPath(), outsideDir.toPath())

            assertFalse(StagingService.wipeStaging(context))

            assertTrue("The intermediate symlink must remain visible", Files.isSymbolicLink(internalLink.toPath()))
            assertArrayEquals(
                "Cleanup must preserve bytes outside its trusted root",
                outsideBytes,
                outsideFile.readBytes(),
            )
        } finally {
            Files.deleteIfExists(internalLink.toPath())
            filesDir.deleteRecursively()
            outsideDir.deleteRecursively()
        }
    }

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
        val alternateResources = mockk<android.content.res.Resources>()
        every {
            context.getString(R.string.error_reason_permission_denied)
        } returns "Localized permission denial"
        every {
            context.getString(R.string.error_read_folder_failed, "Localized permission denial")
        } returns "Localized folder failure: Localized permission denial"
        every {
            context.getString(R.string.error_copy_files_failed, "Localized permission denial")
        } returns "Localized copy failure: Localized permission denial"
        every {
            alternateResources.getString(R.string.error_reason_permission_denied)
        } returns "Alternate permission denial"
        every {
            alternateResources.getString(R.string.error_read_folder_failed, "Alternate permission denial")
        } returns "Alternate folder failure: Alternate permission denial"
        every {
            alternateResources.getString(R.string.error_copy_files_failed, "Alternate permission denial")
        } returns "Alternate copy failure: Alternate permission denial"

        val raw = "raw provider detail /private/path"
        val expected = listOf(
            Triple(
                R.string.error_read_folder_failed,
                "Localized folder failure: Localized permission denial",
                "Alternate folder failure: Alternate permission denial",
            ),
            Triple(
                R.string.error_copy_files_failed,
                "Localized copy failure: Localized permission denial",
                "Alternate copy failure: Alternate permission denial",
            ),
        )

        expected.forEach { (wrapperResource, localizedFallback, alternateDisplay) ->
            val error = StagingService.localizedCopyError(
                context,
                wrapperResource,
                SecurityException(raw),
            )

            assertEquals(wrapperResource, error.messageResId)
            assertEquals(
                listOf(LocalizedMessageArg(R.string.error_reason_permission_denied)),
                error.messageArgs,
            )
            assertEquals(raw, error.technicalMessage)
            assertEquals(localizedFallback, error.userMessage)
            assertEquals(localizedFallback, error.localizedMessage(context))
            assertEquals(alternateDisplay, error.localizedMessage(alternateResources))
            assertFalse(error.userMessage.contains(raw))
            assertFalse(error.messageArgs.any { it.toString().contains(raw) })
            assertFalse(error.localizedMessage(alternateResources).contains("LocalizedMessageArg"))
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
