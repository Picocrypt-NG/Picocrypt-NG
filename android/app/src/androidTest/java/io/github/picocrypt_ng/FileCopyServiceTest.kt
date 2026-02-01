package io.github.picocrypt_ng

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
    
    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        // Clean up any existing test files
        FileCopyService.cleanupAllFiles(context)
    }
    
    @After
    fun tearDown() {
        // Clean up test files after each test
        FileCopyService.cleanupAllFiles(context)
    }
    
    @Test
    fun `getInternalStoragePath returns correct path`() {
        val path = FileCopyService.getInternalStoragePath(context)
        
        assertNotNull("Path should not be null", path)
        assertTrue("Path should contain picocrypt_files", path.contains("picocrypt_files"))
        assertTrue("Path should be absolute", path.startsWith("/"))
    }
    
    @Test
    fun `getOutputFilePath returns pcv extension for encryption`() {
        val inputPath = "/data/test/input_file.txt"
        val outputPath = FileCopyService.getOutputFilePath(context, inputPath, isEncrypt = true)
        
        assertNotNull("Output path should not be null", outputPath)
        assertTrue("Output path should end with .pcv", outputPath.endsWith(".pcv"))
        assertTrue("Output path should contain output_file", outputPath.contains("output_file"))
    }
    
    @Test
    fun `getOutputFilePath returns no extension for decryption`() {
        val inputPath = "/data/test/input_file.pcv"
        val outputPath = FileCopyService.getOutputFilePath(context, inputPath, isEncrypt = false)
        
        assertNotNull("Output path should not be null", outputPath)
        assertFalse("Output path should not end with .pcv", outputPath.endsWith(".pcv"))
        assertTrue("Output path should contain output_file", outputPath.contains("output_file"))
    }
    
    @Test
    fun `validateFileExists returns false for non-existent file`() {
        val result = FileCopyService.validateFileExists("/nonexistent/file.txt")
        
        assertFalse("Should return false for non-existent file", result)
    }
    
    @Test
    fun `validateFileExists returns true for existing file`() = runTest {
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
    fun `cleanupAllFiles removes all files from internal storage`() = runTest {
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
    fun `cleanupAllFiles handles non-existent directory`() = runTest {
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
    fun `cleanupOperationFiles removes input and output files`() = runTest {
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
    fun `cleanupOperationFiles removes keyfiles`() = runTest {
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
    fun `cleanupOperationFiles handles non-existent files gracefully`() = runTest {
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
    fun `cleanupIncompleteFiles removes incomplete files`() = runTest {
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
    fun `cleanupKeyfiles removes keyfile files`() = runTest {
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
    fun `cleanupOperationFilesBeforeStart removes output files`() = runTest {
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
    fun `deleteFile removes existing file`() = runTest {
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
    fun `deleteFile returns false for non-existent file`() = runTest {
        val result = FileCopyService.deleteFile(context, "/nonexistent/file.txt")
        
        assertFalse("Should return false for non-existent file", result)
    }
}


