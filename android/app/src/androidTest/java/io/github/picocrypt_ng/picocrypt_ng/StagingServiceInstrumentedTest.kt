package io.github.picocrypt_ng.picocrypt_ng

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.provider.DocumentsContract
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class StagingServiceInstrumentedTest {
    private val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test fun stageTree_preservesStructure() = runBlocking {
        BoundedSafDocumentsProvider.grantAccessForTest(ctx)
        ctx.contentResolver.call(BoundedSafDocumentsProvider.tree, "bounded-test-reset", null, null)
        ctx.contentResolver.call(BoundedSafDocumentsProvider.tree, "bounded-test-seed-source", null, null)
        val tree = BoundedSafDocumentsProvider.tree
        try {
            val sel = StagingService.copyTreeToStaging(ctx, tree).getOrThrow()
            assertEquals(SelectionKind.FOLDER, sel.kind)
            assertEquals("bounded-saf-provider.zip.pcv", sel.suggestedOutputName)
            assertEquals(2, sel.inputFiles.size)
            assertEquals("a", File(sel.stagingRoot, "bounded-saf-provider/a.txt").readText())
            assertEquals("b", File(sel.stagingRoot, "bounded-saf-provider/sub/b.txt").readText())
            assertEquals(listOf(File(sel.stagingRoot, "bounded-saf-provider").path), sel.onlyFolders)
            assertTrue(StagingService.wipeStaging(ctx))
            for ((id, body) in mapOf("root/a.txt" to "a", "root/sub/b.txt" to "b")) {
                val uri = DocumentsContract.buildDocumentUriUsingTree(tree, id)
                assertEquals(body, requireNotNull(ctx.contentResolver.openInputStream(uri)).bufferedReader().use { it.readText() })
            }
        } finally {
            assertTrue(StagingService.wipeStaging(ctx))
            val cleaned = ctx.contentResolver.call(BoundedSafDocumentsProvider.tree, "bounded-test-cleanup", null, null)
            assertTrue(requireNotNull(cleaned).getBoolean("cleaned"))
        }
    }

    @Test
    fun wipeStaging_nativeCleanupRejectsIntermediateSymlink() {
        val internalLink = File(ctx.filesDir, "picocrypt_files")
        val outsideDir = File(ctx.cacheDir, "staging-intermediate-outside").apply {
            deleteRecursively()
            mkdirs()
        }
        val outsideStaging = File(outsideDir, "staging").apply { mkdirs() }
        val outsideFile = File(outsideStaging, "foreign.txt")
        val outsideBytes = "native cleanup must preserve this".toByteArray()

        assertTrue(
            runBlocking {
                FileCopyService.cleanupAllFiles(ctx)
            },
        )
        if (!internalLink.exists()) {
            assertTrue(internalLink.mkdirs())
        }
        assertTrue(internalLink.delete())
        outsideFile.writeBytes(outsideBytes)
        Os.symlink(outsideDir.absolutePath, internalLink.absolutePath)

        try {
            assertFalse(StagingService.wipeStaging(ctx))
            assertArrayEquals(outsideBytes, outsideFile.readBytes())
        } finally {
            try {
                Os.remove(internalLink.absolutePath)
            } catch (e: ErrnoException) {
                if (e.errno != OsConstants.ENOENT) throw e
            }
            outsideDir.deleteRecursively()
        }
    }
}
