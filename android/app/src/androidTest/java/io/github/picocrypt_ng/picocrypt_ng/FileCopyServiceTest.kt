package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Instrumented tests for FileCopyService.
 * These tests run on Android devices/emulators and test actual file operations.
 */
@RunWith(AndroidJUnit4::class)
class FileCopyServiceTest {
    
    private lateinit var context: Context
    
    @Test
    fun pcv3OwnedDeletionUsesNativeNoFollowTreeAndTruthfulRetry() = runTest {
        val root = File(context.filesDir, "pcv3-cleanup-regression").apply { mkdirs() }
        val nested = File(root, "nested/plaintext").apply { parentFile!!.mkdirs(); writeText("private") }
        val outside = File(context.cacheDir, "pcv3-cleanup-unowned").apply { mkdirs() }
        val preserved = File(outside, "keep").apply { writeText("keep") }
        val link = File(root, "link")
        java.nio.file.Files.createSymbolicLink(link.toPath(), outside.toPath())
        try {
            assertFalse(FileCopyService.deleteFile(context, preserved.path))
            assertFalse(FileCopyService.deleteFile(context, File(link, "keep").path))
            assertTrue(nested.parentFile!!.setWritable(false, false))
            assertFalse(FileCopyService.deleteFile(context, nested.path))
            assertTrue(nested.exists())
            assertTrue(nested.parentFile!!.setWritable(true, true))
            assertTrue(FileCopyService.deleteFile(context, root.path))
            assertFalse(root.exists())
            assertEquals("keep", preserved.readText())
            assertTrue(FileCopyService.deleteFile(context, root.path))
        } finally {
            nested.parentFile!!.setWritable(true, true)
            java.nio.file.Files.deleteIfExists(link.toPath())
            root.deleteRecursively()
            outside.deleteRecursively()
        }
    }

    @Test
    fun pcv3OutputRequiresSeekableRegularDescriptor() {
        val file = File(context.cacheDir, "pcv3-descriptor-test")
        file.writeBytes(byteArrayOf(1))
        try {
            android.os.ParcelFileDescriptor.open(file, android.os.ParcelFileDescriptor.MODE_READ_WRITE).use {
                assertTrue(FileCopyService.supportsPcv3OutputDescriptor(it))
            }
            val pipe = android.os.ParcelFileDescriptor.createPipe()
            pipe[0].use { read ->
                pipe[1].use { write ->
                    assertFalse(FileCopyService.supportsPcv3OutputDescriptor(read))
                    assertFalse(FileCopyService.supportsPcv3OutputDescriptor(write))
                }
            }
        } finally { file.delete() }
    }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        // Clean up any existing test files
        runTest {
            FileCopyService.cleanupAllFiles(context)
        }
    }
    
    @After
    fun tearDown() {
        // Clean up test files after each test
        runTest {
            FileCopyService.cleanupAllFiles(context)
        }
    }
    
    @Test
    fun getInternalStoragePath_returns_correct_path() {
        val path = FileCopyService.getInternalStoragePath(context)
        
        assertNotNull("Path should not be null", path)
        assertTrue("Path should contain picocrypt_files", path.contains("picocrypt_files"))
        assertTrue("Path should be absolute", path.startsWith("/"))
    }
    
    @Test
    fun getOutputFilePath_returns_pcv_extension_for_encryption() {
        val inputPath = "/data/test/input_file.txt"
        val outputPath = FileCopyService.getOutputFilePath(context, inputPath, isEncrypt = true)
        
        assertNotNull("Output path should not be null", outputPath)
        assertTrue("Output path should end with .pcv", outputPath.endsWith(".pcv"))
        assertTrue("Output path should contain output_file", outputPath.contains("output_file"))
    }
    
    @Test
    fun getOutputFilePath_returns_no_extension_for_decryption() {
        val inputPath = "/data/test/input_file.pcv"
        val outputPath = FileCopyService.getOutputFilePath(context, inputPath, isEncrypt = false)
        
        assertNotNull("Output path should not be null", outputPath)
        assertFalse("Output path should not end with .pcv", outputPath.endsWith(".pcv"))
        assertTrue("Output path should contain output_file", outputPath.contains("output_file"))
    }
    
    @Test
    fun validateFileExists_returns_false_for_non_existent_file() {
        val result = FileCopyService.validateFileExists("/nonexistent/file.txt")
        
        assertFalse("Should return false for non-existent file", result)
    }
    
    @Test
    fun validateFileExists_returns_true_for_existing_file() = runTest {
        // Create a test file
        val testFile = File(context.filesDir, "picocrypt_files/test_file.txt")
        testFile.parentFile?.mkdirs()
        testFile.writeText("test content")
        
        val result = FileCopyService.validateFileExists(testFile.absolutePath)
        
        assertTrue("Should return true for existing file", result)
        
        // Cleanup
        testFile.delete()
    }
    
    @Test
    fun cleanupAllFiles_removes_all_files_from_internal_storage() = runTest {
        // Create some test files
        val internalDir = File(context.filesDir, "picocrypt_files")
        internalDir.mkdirs()
        val file1 = File(internalDir, "test1.txt")
        val file2 = File(internalDir, "test2.txt")
        file1.writeText("content1")
        file2.writeText("content2")
        
        assertTrue("Files should exist before cleanup", file1.exists())
        assertTrue("Files should exist before cleanup", file2.exists())
        
        val result = FileCopyService.cleanupAllFiles(context)
        
        assertTrue("Cleanup should succeed", result)
        assertFalse("File1 should be deleted", file1.exists())
        assertFalse("File2 should be deleted", file2.exists())
    }

    @Test
    fun cleanupAllFiles_removes_stale_staging_directories_from_internal_storage() = runTest {
        val internalDir = File(context.filesDir, "picocrypt_files")
        val stagedDir = File(internalDir, "staging/MyDocs")
        stagedDir.mkdirs()
        val stagedFile = File(stagedDir, "a.txt").apply { writeText("plaintext") }
        val directFile = File(internalDir, "input_file.txt").apply { writeText("direct") }

        assertTrue("Staged file should exist before cleanup", stagedFile.exists())
        assertTrue("Direct file should exist before cleanup", directFile.exists())

        val result = FileCopyService.cleanupAllFiles(context)

        assertTrue("Startup cleanup should succeed", result)
        assertFalse("Stale staged file should be deleted", stagedFile.exists())
        assertFalse("Stale staging directory should be deleted", stagedDir.exists())
        assertFalse("Direct file should be deleted", directFile.exists())
    }
    
    @Test
    fun cleanupAllFiles_handles_non_existent_directory() = runTest {
        // Ensure directory doesn't exist
        val internalDir = File(context.filesDir, "picocrypt_files")
        if (internalDir.exists()) {
            internalDir.deleteRecursively()
        }
        
        val result = FileCopyService.cleanupAllFiles(context)
        
        // Should return true even if directory doesn't exist
        assertTrue("Cleanup should succeed even if directory doesn't exist", result)
    }
    
    @Test
    fun cleanupOperationFiles_removes_input_and_output_files() = runTest {
        val internalDir = File(context.filesDir, "picocrypt_files")
        internalDir.mkdirs()
        
        val inputFile = File(internalDir, "input_file.txt")
        val outputFile = File(internalDir, "output_file.pcv")
        inputFile.writeText("input content")
        outputFile.writeText("output content")
        
        val result = FileCopyService.cleanupOperationFiles(
            context = context,
            inputFilePath = inputFile.absolutePath,
            outputFilePath = outputFile.absolutePath,
            keyfilePaths = emptyList()
        )
        
        assertTrue("Cleanup should succeed", result)
        assertFalse("Input file should be deleted", inputFile.exists())
        assertFalse("Output file should be deleted", outputFile.exists())
    }
    
    @Test
    fun cleanupOperationFiles_removes_keyfiles() = runTest {
        val internalDir = File(context.filesDir, "picocrypt_files")
        internalDir.mkdirs()
        
        val keyfile1 = File(internalDir, "keyfile_0")
        val keyfile2 = File(internalDir, "keyfile_1")
        keyfile1.writeText("keyfile1")
        keyfile2.writeText("keyfile2")
        
        val result = FileCopyService.cleanupOperationFiles(
            context = context,
            inputFilePath = null,
            outputFilePath = null,
            keyfilePaths = listOf(keyfile1.absolutePath, keyfile2.absolutePath)
        )
        
        assertTrue("Cleanup should succeed", result)
        assertFalse("Keyfile1 should be deleted", keyfile1.exists())
        assertFalse("Keyfile2 should be deleted", keyfile2.exists())
    }
    
    @Test
    fun cleanupOperationFiles_handles_non_existent_files_gracefully() = runTest {
        val result = FileCopyService.cleanupOperationFiles(
            context = context,
            inputFilePath = "/nonexistent/input.txt",
            outputFilePath = "/nonexistent/output.pcv",
            keyfilePaths = listOf("/nonexistent/keyfile.txt")
        )
        
        // Should return true even if files don't exist
        assertTrue("Cleanup should succeed even if files don't exist", result)
    }
    
    @Test
    fun cleanupIncompleteFiles_removes_incomplete_files() = runTest {
        val internalDir = File(context.filesDir, "picocrypt_files")
        internalDir.mkdirs()
        
        val incomplete1 = File(internalDir, "output_file.pcv.incomplete")
        val incomplete2 = File(internalDir, "output_file.incomplete")
        incomplete1.writeText("incomplete1")
        incomplete2.writeText("incomplete2")
        
        val result = FileCopyService.cleanupIncompleteFiles(context)
        
        assertTrue("Cleanup should succeed", result)
        assertFalse("Incomplete file 1 should be deleted", incomplete1.exists())
        assertFalse("Incomplete file 2 should be deleted", incomplete2.exists())
    }
    
    @Test
    fun cleanupKeyfiles_removes_keyfile_files() = runTest {
        val internalDir = File(context.filesDir, "picocrypt_files")
        internalDir.mkdirs()
        
        val keyfile1 = File(internalDir, "keyfile_0")
        val keyfile2 = File(internalDir, "keyfile_1")
        val otherFile = File(internalDir, "other_file.txt")
        keyfile1.writeText("keyfile1")
        keyfile2.writeText("keyfile2")
        otherFile.writeText("other")
        
        val result = FileCopyService.cleanupKeyfiles(context)
        
        assertTrue("Cleanup should succeed", result)
        assertFalse("Keyfile1 should be deleted", keyfile1.exists())
        assertFalse("Keyfile2 should be deleted", keyfile2.exists())
        assertTrue("Other file should remain", otherFile.exists())
    }
    
    @Test
    fun cleanupOperationFilesBeforeStart_removes_output_files() = runTest {
        val internalDir = File(context.filesDir, "picocrypt_files")
        internalDir.mkdirs()
        
        val outputPcv = File(internalDir, "output_file.pcv")
        val outputFile = File(internalDir, "output_file")
        val inputFile = File(internalDir, "input_file.txt")
        outputPcv.writeText("output pcv")
        outputFile.writeText("output")
        inputFile.writeText("input")
        
        val result = FileCopyService.cleanupOperationFilesBeforeStart(context)
        
        assertTrue("Cleanup should succeed", result)
        assertFalse("Output .pcv should be deleted", outputPcv.exists())
        assertFalse("Output file should be deleted", outputFile.exists())
        assertTrue("Input file should remain", inputFile.exists())
    }

    @Test
    fun cleanupOperationFilesBeforeStart_preservesStagingTree() = runTest {
        // Bug 2 regression: staged folder/multi-file inputs live under staging/ and are the
        // very inputs the operation is about to read. Pre-start cleanup must not wipe them
        // (staging hygiene is owned by StagingService.wipeStaging at pick time and
        // clearOperation after the op), or Go would get paths to deleted files.
        val staged = File(context.filesDir, "picocrypt_files/staging/MyDocs")
        staged.mkdirs()
        val a = File(staged, "a.txt").apply { writeText("a") }

        FileCopyService.cleanupOperationFilesBeforeStart(context)

        assertTrue("staged input must survive pre-start cleanup", a.exists())
        // cleanup
        File(context.filesDir, "picocrypt_files/staging").deleteRecursively()
    }

    @Test
    fun deleteFile_removes_existing_file() = runTest {
        val internalDir = File(context.filesDir, "picocrypt_files")
        internalDir.mkdirs()
        
        val testFile = File(internalDir, "test_delete.txt")
        testFile.writeText("content")
        
        assertTrue("File should exist before deletion", testFile.exists())
        
        val result = FileCopyService.deleteFile(context, testFile.absolutePath)
        
        assertTrue("Delete should succeed", result)
        assertFalse("File should be deleted", testFile.exists())
    }
    
    @Test
    fun deleteFile_returns_false_for_non_existent_file() = runTest {
        val result = FileCopyService.deleteFile(context, "/nonexistent/file.txt")
        
        assertFalse("Should return false for non-existent file", result)
    }
}
