package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import io.github.picocrypt_ng.picocrypt_ng.ui.components.cleanupReplacedSelection
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import kotlin.io.path.createTempDirectory

class FileCardStagingOwnershipTest {
    @Test
    fun `replacing folder or multi selection with a single file retires previous staged plaintext`() = runBlocking {
        for (relative in listOf("folder/old.txt", "old.txt")) {
            val root = createTempDirectory(prefix = "selection_old_staging").toFile()
            val context = mockk<Context>()
            every { context.filesDir } returns root
            val old = File(root, "picocrypt_files/staging/$relative")
            val original = File(root, "original.txt")
            try {
                assertTrue(old.parentFile!!.mkdirs())
                old.writeText("previous private plaintext")
                original.writeText("original must survive")
                assertTrue(cleanupReplacedSelection(context, emptyList()))
                assertFalse("resetting the form must not strand its old staging tree", old.exists())
                assertEquals("original must survive", original.readText())
            } finally {
                root.deleteRecursively()
            }
        }
    }

    @Test
    fun `replacement refuses an undeletable staging owner`() = runBlocking {
        val root = createTempDirectory(prefix = "selection_blocked_staging").toFile()
        val context = mockk<Context>()
        every { context.filesDir } returns root
        val parent = File(root, "picocrypt_files")
        val stage = File(parent, "staging")
        val old = File(stage, "old.txt")
        try {
            assertTrue(stage.mkdirs())
            old.writeText("retained private plaintext")
            assertTrue(stage.setWritable(false, false))
            assertTrue(parent.setWritable(false, false))
            assertFalse("failed old-owner cleanup must prevent replacement", cleanupReplacedSelection(context, emptyList()))
            assertEquals("retained private plaintext", old.readText())
        } finally {
            parent.setWritable(true, false)
            stage.setWritable(true, false)
            root.deleteRecursively()
        }
    }
}
