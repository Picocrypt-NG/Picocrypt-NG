package io.github.picocrypt_ng.picocrypt_ng

import org.junit.Assert.*
import org.junit.Test
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders

/**
 * Unit tests for FormData class.
 */
class FormDataTest {
    
    @Test
    fun `isEncrypt returns true for non-pcv files`() {
        val formData = TestDataBuilders.createEncryptFormData(selectedFilename = "test.txt")
        assertTrue(formData.isEncrypt)
        assertFalse(formData.isDecrypt)
    }
    
    @Test
    fun `isDecrypt returns true for pcv files`() {
        val formData = TestDataBuilders.createDecryptFormData(selectedFilename = "test.pcv")
        assertTrue(formData.isDecrypt)
        assertFalse(formData.isEncrypt)
    }
    
    @Test
    fun `isEncrypt and isDecrypt return false for empty filename`() {
        val formData = TestDataBuilders.createEncryptFormData(selectedFilename = "")
        assertFalse(formData.isEncrypt)
        assertFalse(formData.isDecrypt)
    }
    
    @Test
    fun `isPasswordsMatch returns true when passwords match`() {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "test123",
            confirmPassword = "test123"
        )
        assertTrue(formData.isPasswordsMatch)
    }
    
    @Test
    fun `isPasswordsMatch returns false when passwords do not match`() {
        val formData = FormData(
            selectedFilename = "test.txt",
            passwordInput = "password1".toCharArray(),
            confirmPasswordInput = "password2".toCharArray(),
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false
        )
        assertFalse(formData.isPasswordsMatch)
    }
    
    @Test
    fun `isPasswordValid returns true for encrypt with matching passwords`() {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "test123",
            confirmPassword = "test123"
        )
        assertTrue(formData.isPasswordValid)
    }
    
    @Test
    fun `isPasswordValid returns false for encrypt with mismatched passwords`() {
        val formData = FormData(
            selectedFilename = "test.txt",
            passwordInput = "password1".toCharArray(),
            confirmPasswordInput = "password2".toCharArray(),
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false
        )
        assertFalse(formData.isPasswordValid)
    }
    
    @Test
    fun `isPasswordValid returns true for decrypt with non-empty password`() {
        val formData = TestDataBuilders.createDecryptFormData(password = "test123")
        assertTrue(formData.isPasswordValid)
    }
    
    @Test
    fun `isPasswordValid returns false for empty password`() {
        val formData = FormData(
            selectedFilename = "test.txt",
            passwordInput = CharArray(0),
            confirmPasswordInput = CharArray(0),
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false
        )
        assertFalse(formData.isPasswordValid)
    }

    @Test
    fun `new v2 keyfile-only encryption is invalid`() {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "",
            confirmPassword = "",
            deniability = false,
            keyfiles = listOf(TestDataBuilders.createKeyfileInfo()),
        )

        assertFalse(formData.isPasswordValid)
        assertFalse(formData.isFormValid)
    }

    @Test
    fun `new v2 password-and-keyfile encryption is invalid`() {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "secret",
            confirmPassword = "secret",
            deniability = false,
            keyfiles = listOf(TestDataBuilders.createKeyfileInfo()),
        )

        assertFalse(formData.isPasswordValid)
        assertFalse(formData.isFormValid)
    }

    @Test
    fun `keyfile-only encryption is invalid with deniability`() {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "",
            confirmPassword = "",
            deniability = true,
            keyfiles = listOf(TestDataBuilders.createKeyfileInfo()),
        )

        assertFalse(formData.isPasswordValid)
        assertFalse(formData.isFormValid)
    }

    @Test
    fun `ordinary keyfile-only decryption remains valid`() {
        val formData = TestDataBuilders.createDecryptFormData(
            password = "",
            keyfiles = listOf(TestDataBuilders.createKeyfileInfo()),
        )

        assertTrue(formData.isPasswordValid)
        assertTrue(formData.isFormValid)
    }

    @Test
    fun `legacy deniable keyfile-only decryption accepts an empty password`() {
        val formData = TestDataBuilders.createDecryptFormData(
            password = "",
            keyfiles = listOf(TestDataBuilders.createKeyfileInfo()),
            decryptionInfo = TestDataBuilders.createDecryptionInfo(
                keyfilesRequired = true,
                deniability = true,
                readable = false,
            ),
        )

        assertTrue(formData.isPasswordValid)
        assertTrue(formData.isFormValid)
    }
    
    @Test
    fun `clearPasswords zeros password arrays`() {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "test123",
            confirmPassword = "test123"
        )
        val passwordCopy = formData.passwordInput.copyOf()
        val confirmCopy = formData.confirmPasswordInput.copyOf()
        
        formData.clearPasswords()
        
        assertTrue(passwordCopy.all { it != '\u0000' })
        assertTrue(formData.passwordInput.all { it == '\u0000' })
        assertTrue(formData.confirmPasswordInput.all { it == '\u0000' })
        assertFalse("an all-NUL password buffer is not a credential", formData.hasPassword)
        assertFalse("clearing the only credential must invalidate the form", formData.isPasswordValid)
    }
    
    @Test
    fun `copyWithClearedPasswords creates copy with empty arrays and clears original`() {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "test123",
            confirmPassword = "test123"
        )
        val originalPassword = formData.passwordInput.copyOf()
        
        val cleared = formData.copyWithClearedPasswords()
        
        assertEquals(0, cleared.passwordInput.size)
        assertEquals(0, cleared.confirmPasswordInput.size)
        assertTrue(formData.passwordInput.all { it == '\u0000' })
        assertTrue(formData.confirmPasswordInput.all { it == '\u0000' })
        // Other fields should be preserved
        assertEquals(formData.selectedFilename, cleared.selectedFilename)
        assertEquals(formData.comments, cleared.comments)
    }
    
    @Test
    fun `areKeyfilesRequiredButMissing returns false when not decrypt`() {
        val formData = TestDataBuilders.createEncryptFormData()
        assertFalse(formData.areKeyfilesRequiredButMissing)
    }
    
    @Test
    fun `areKeyfilesRequiredButMissing returns false when decryptionInfo is null`() {
        val formData = TestDataBuilders.createDecryptFormData(decryptionInfo = null)
        assertFalse(formData.areKeyfilesRequiredButMissing)
    }
    
    @Test
    fun `areKeyfilesRequiredButMissing returns false when keyfiles not required`() {
        val decryptionInfo = TestDataBuilders.createDecryptionInfo(keyfilesRequired = false)
        val formData = TestDataBuilders.createDecryptFormData(
            decryptionInfo = decryptionInfo,
            keyfiles = emptyList()
        )
        assertFalse(formData.areKeyfilesRequiredButMissing)
    }
    
    @Test
    fun `areKeyfilesRequiredButMissing returns true when keyfiles required but missing`() {
        val decryptionInfo = TestDataBuilders.createDecryptionInfo(
            keyfilesRequired = true,
            readable = true
        )
        val formData = TestDataBuilders.createDecryptFormData(
            decryptionInfo = decryptionInfo,
            keyfiles = emptyList()
        )
        assertTrue(formData.areKeyfilesRequiredButMissing)
    }
    
    @Test
    fun `areKeyfilesRequiredButMissing returns false when keyfiles required and provided`() {
        val decryptionInfo = TestDataBuilders.createDecryptionInfo(
            keyfilesRequired = true,
            readable = true
        )
        val keyfiles = listOf(TestDataBuilders.createKeyfileInfo())
        val formData = TestDataBuilders.createDecryptFormData(
            decryptionInfo = decryptionInfo,
            keyfiles = keyfiles
        )
        assertFalse(formData.areKeyfilesRequiredButMissing)
    }
    
    @Test
    fun `areKeyfilesRequiredButMissing returns false when not readable (deniability mode)`() {
        val decryptionInfo = TestDataBuilders.createDecryptionInfo(
            keyfilesRequired = true,
            readable = false // Deniability mode
        )
        val formData = TestDataBuilders.createDecryptFormData(
            decryptionInfo = decryptionInfo,
            keyfiles = emptyList()
        )
        assertFalse(formData.areKeyfilesRequiredButMissing)
    }
    
    @Test
    fun `isFormValid returns true for valid encrypt form`() {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "test123",
            confirmPassword = "test123"
        )
        assertTrue(formData.isFormValid)
    }
    
    @Test
    fun `isFormValid returns false when no file selected`() {
        val formData = TestDataBuilders.createEncryptFormData(selectedFilename = "")
        assertFalse(formData.isFormValid)
    }
    
    @Test
    fun `isFormValid returns false when password invalid`() {
        val formData = FormData(
            selectedFilename = "test.txt",
            passwordInput = CharArray(0),
            confirmPasswordInput = CharArray(0),
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false
        )
        assertFalse(formData.isFormValid)
    }
    
    @Test
    fun `isFormValid returns false when keyfiles required but missing`() {
        val decryptionInfo = TestDataBuilders.createDecryptionInfo(
            keyfilesRequired = true,
            readable = true
        )
        val formData = TestDataBuilders.createDecryptFormData(
            decryptionInfo = decryptionInfo,
            keyfiles = emptyList()
        )
        assertFalse(formData.isFormValid)
    }
    
    @Test
    fun `equals works correctly with CharArray fields`() {
        val formData1 = TestDataBuilders.createEncryptFormData(
            password = "test123",
            confirmPassword = "test123"
        )
        val formData2 = TestDataBuilders.createEncryptFormData(
            password = "test123",
            confirmPassword = "test123"
        )
        val formData3 = TestDataBuilders.createEncryptFormData(
            password = "different",
            confirmPassword = "different"
        )
        
        assertEquals(formData1, formData2)
        assertNotEquals(formData1, formData3)
    }
    
    @Test
    fun `hashCode is consistent with equals`() {
        val formData1 = TestDataBuilders.createEncryptFormData(
            password = "test123",
            confirmPassword = "test123"
        )
        val formData2 = TestDataBuilders.createEncryptFormData(
            password = "test123",
            confirmPassword = "test123"
        )
        val formData3 = TestDataBuilders.createEncryptFormData(
            password = "different",
            confirmPassword = "different"
        )
        
        assertEquals(formData1.hashCode(), formData2.hashCode())
        assertNotEquals(formData1.hashCode(), formData3.hashCode())
    }

    @Test
    fun `isSplitVolumeChunk detects numbered pcv chunks`() {
        // Must mirror Go fileops.IsSplitChunkPath: (?i)\.pcv\.[0-9]+$ on the base name.
        // Desktop split volumes (secret.pcv.0, .1, ...) need recombining; Android can't
        // (single-file picker, no sibling chunks), so they must be detected and rejected.
        val cases = listOf(
            "archive.zip.pcv.0" to true,
            "archive.zip.pcv.12" to true,
            "ARCHIVE.ZIP.PCV.0" to true,   // case-insensitive, like the Go regex
            "secret.pcv.0" to true,
            "backup.pcv.tmp1" to false,    // suffix not all digits
            "notes.pcv.v2" to false,
            "secret.pcv" to false,         // a normal (single) volume
            "photo.jpg" to false,
            "" to false
        )
        for ((name, want) in cases) {
            val formData = TestDataBuilders.createDecryptFormData(selectedFilename = name)
            assertEquals("isSplitVolumeChunk for '$name'", want, formData.isSplitVolumeChunk)
        }
    }

    @Test
    fun `FOLDER selection is encrypt regardless of filename extension`() {
        // A folder/multi-file selection always encrypts (Go zips it). The displayName
        // has no .pcv extension and may have no extension at all, so isEncrypt must key
        // off selectionKind, not the filename. isDecrypt/isSplitVolumeChunk are
        // single-file-only concepts and must be false here.
        val formData = TestDataBuilders.createFolderEncryptFormData(displayName = "MyDocs")
        assertEquals(SelectionKind.FOLDER, formData.selectionKind)
        assertTrue("a folder selection must be an encrypt", formData.isEncrypt)
        assertFalse("a folder selection must never be a decrypt", formData.isDecrypt)
        assertFalse("split-volume detection is single-file-only", formData.isSplitVolumeChunk)
    }

    @Test
    fun `compressed single-file encrypt suggests zip pcv export name`() {
        val formData = TestDataBuilders.createEncryptFormData(
            selectedFilename = "page.html",
            compress = true
        )

        assertEquals("page.html.zip.pcv", formData.suggestedOutputNameFor(OperationType.ENCRYPT))
    }

    @Test
    fun `legacy pcv decrypt keeps filename-derived export name`() {
        val formData = TestDataBuilders.createDecryptFormData(selectedFilename = "page.html.pcv")

        assertEquals("page.html", formData.suggestedOutputNameFor(OperationType.DECRYPT))
    }

    @Test
    fun `zip pcv decrypt keeps zip export suffix without sniffing`() {
        val formData = TestDataBuilders.createDecryptFormData(selectedFilename = "page.html.zip.pcv")

        assertEquals("page.html.zip", formData.suggestedOutputNameFor(OperationType.DECRYPT))
    }

    @Test
    fun `equals and hashCode reflect selection fields`() {
        // The selection model (inputFiles/onlyFolders/onlyFiles/selectionKind/
        // suggestedOutputName) is part of FormData's identity: two forms that differ only
        // in their staged selection must not be considered equal, else a stale folder
        // selection could be mistaken for a new one.
        val a = TestDataBuilders.createFolderEncryptFormData(displayName = "MyDocs")
        val b = TestDataBuilders.createFolderEncryptFormData(displayName = "MyDocs")
        val c = TestDataBuilders.createFolderEncryptFormData(
            displayName = "MyDocs",
            inputFiles = listOf("/stage/MyDocs/only-one.txt")
        )
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, c)
    }

    @Test
    fun `isFormValid is false for a split volume chunk`() {
        // A split chunk must never be a runnable operation: it does not end in .pcv, so
        // isEncrypt is true and it would be double-encrypted. The work button gates on
        // isFormValid, so a chunk must make the form invalid even with a valid password.
        val formData = TestDataBuilders.createDecryptFormData(
            selectedFilename = "secret.pcv.0",
            password = "testpassword"
        )
        assertTrue("precondition: chunk is classified as split", formData.isSplitVolumeChunk)
        assertFalse("a split chunk must invalidate the form", formData.isFormValid)
    }

    @Test
    fun hasSelectedInput_trueForSingleFile() {
        val fd = TestDataBuilders.createEncryptFormData(copiedFilePath = "/data/input_file.txt")
        assertTrue(fd.hasSelectedInput)
    }

    @Test
    fun hasSelectedInput_trueForFolderSelection() {
        val fd = TestDataBuilders.createFolderEncryptFormData()
        assertTrue(fd.hasSelectedInput)
    }

    @Test
    fun hasSelectedInput_falseWhenNothingSelected() {
        val fd = TestDataBuilders.createEncryptFormData(copiedFilePath = "")
        assertFalse(fd.hasSelectedInput)
    }
}
