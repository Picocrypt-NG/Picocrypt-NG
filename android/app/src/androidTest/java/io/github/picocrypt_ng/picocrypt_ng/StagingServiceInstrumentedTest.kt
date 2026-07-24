package io.github.picocrypt_ng.picocrypt_ng

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.documentfile.provider.DocumentFile
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
        val src = File(ctx.cacheDir, "srctree").apply { deleteRecursively(); mkdirs() }
        File(src, "sub").mkdirs()
        File(src, "a.txt").writeText("a")
        File(src, "sub/b.txt").writeText("b")

        val tree = DocumentFile.fromFile(src)
        val sel = StagingService.stageTree(ctx, tree).getOrThrow()
        assertEquals(SelectionKind.FOLDER, sel.kind)
        assertEquals("srctree.zip.pcv", sel.suggestedOutputName)
        assertEquals(2, sel.inputFiles.size)
        assertTrue(sel.inputFiles.any { it.endsWith("/srctree/a.txt") })
        assertTrue(sel.inputFiles.any { it.endsWith("/srctree/sub/b.txt") })
        assertEquals(1, sel.onlyFolders.size)
        assertTrue(sel.onlyFolders[0].endsWith("/staging/srctree"))
        assertTrue(StagingService.wipeStaging(ctx))
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
