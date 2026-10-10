package io.github.picocrypt_ng.picocrypt_ng

import android.app.Application
import android.content.Context
import androidx.lifecycle.SavedStateHandle
import io.github.picocrypt_ng.picocrypt_ng.testutils.MainDispatcherRule
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkObject
import io.mockk.unmockkStatic
import io.mockk.verify
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import kotlin.io.path.createTempDirectory
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class AndroidLegacyBoundaryTest {
    @get:Rule val mainDispatcherRule = MainDispatcherRule()

    @Test
    fun legacyReaderPassesNormalUtf8AndHistoricalMalformedReplacementUnchanged() = runTest {
        val root = createTempDirectory("legacy-normal-encoding-").toFile()
        val context = mockk<Context> { every { filesDir } returns root }
        val source = File(root, "picocrypt_files/input_file.pcv").apply {
            parentFile!!.mkdirs(); writeText("legacy ciphertext")
        }
        val cases = listOf(
            charArrayOf('A', '\ud800', 'B') to byteArrayOf(0x41, 0x3f, 0x42),
            charArrayOf('p', '\u00e4', '\u20ac', '\ud83d', '\udd12') to
                byteArrayOf(0x70, 0xc3.toByte(), 0xa4.toByte(), 0xe2.toByte(), 0x82.toByte(), 0xac.toByte(),
                    0xf0.toByte(), 0x9f.toByte(), 0x94.toByte(), 0x92.toByte()),
        )
        mockkObject(GoBridge)
        var encoded = ByteArray(0)
        every { GoBridge.startOperation() } returns Result.success("legacy-normal-encoding")
        every { GoBridge.startDecrypt(any(), any(), any(), any(), any()) } answers {
            encoded = arg<ByteArray>(3).copyOf()
            arg<ByteArray>(3).fill(0)
            Result.success(Unit)
        }
        try {
            for ((password, expected) in cases) {
                val form = TestDataBuilders.createDecryptFormData(copiedFilePath = source.path).copy(passwordInput = password)
                OperationManager.startDecrypt(context, form).getOrThrow()
                assertArrayEquals(expected, encoded)
                OperationManager.clearOperation(shouldCleanupFiles = false)
                form.clearPasswords()
            }
        } finally {
            OperationManager.clearOperation(shouldCleanupFiles = false)
            encoded.fill(0)
            unmockkObject(GoBridge)
            root.deleteRecursively()
        }
    }

    @Test
    fun legacyReaderKeepsHistoricalFloatRoundedPasswordBytesWithoutAnAuthenticationFallback() = runTest {
        val root = createTempDirectory("legacy-encoding-compat-").toFile()
        val context = mockk<Context> { every { filesDir } returns root }
        val source = File(root, "picocrypt_files/input_file.pcv").apply {
            parentFile!!.mkdirs(); writeText("old Android volume")
        }
        val password = CharArray(5_592_407) { '\u0800' }.also { it[it.lastIndex] = '\u0801' }
        val form = TestDataBuilders.createDecryptFormData(copiedFilePath = source.path).copy(passwordInput = password)
        var actualSize = 0
        var actualDigest = ""
        mockkObject(GoBridge)
        every { GoBridge.startOperation() } returns Result.success("legacy-encoding-compat")
        every { GoBridge.startDecrypt(any(), any(), any(), any(), any()) } answers {
            val encoded = arg<ByteArray>(3)
            actualSize = encoded.size
            actualDigest = MessageDigest.getInstance("SHA-256").digest(encoded).joinToString("") { "%02x".format(it) }
            encoded.fill(0)
            Result.success(Unit)
        }
        try {
            OperationManager.startDecrypt(context, form).getOrThrow()
            assertEquals(16_777_218, actualSize)
            assertEquals("6424659e5dd5cd6fb056dfce5bdf549005623761cefe64295c879ac7c586f4ea", actualDigest)
            verify(exactly = 1) { GoBridge.startDecrypt(any(), any(), any(), any(), any()) }
        } finally {
            OperationManager.clearOperation(shouldCleanupFiles = false)
            form.clearPasswords()
            unmockkObject(GoBridge)
            root.deleteRecursively()
        }
    }

    @Test
    fun restoredSelectionRejectsForeignPrivateFilesAndMalformedTypes() {
        val root = createTempDirectory("legacy-restore-").toFile()
        val application = mockk<Application> { every { filesDir } returns root }
        val foreign = File(root, "user-data.pcv").apply { writeText("must survive") }
        try {
            val foreignState = SavedStateHandle(mapOf(
                "selected_filename" to "user-data.pcv",
                "copied_file_path" to foreign.path,
                "comments" to "forged metadata",
            ))
            val restored = MainViewModel(application, foreignState).formState.value
            assertEquals("An app-private pathname is not sufficient input ownership", "", restored.copiedFilePath)
            assertEquals("", restored.selectedFilename)
            assertEquals("", restored.comments)
            assertEquals("must survive", foreign.readText())

            val malformed = MainViewModel(application, SavedStateHandle(mapOf(
                "selected_filename" to 42,
                "copied_file_path" to listOf(foreign.path),
                "comments" to true,
            ))).formState.value
            assertEquals("", malformed.selectedFilename)
            assertEquals("", malformed.copiedFilePath)
            assertEquals("", malformed.comments)
        } finally { root.deleteRecursively() }
    }

    @Test
    fun restoredSelectionAcceptsOnlyExistingRegularOwnedInput() {
        val root = createTempDirectory("legacy-restore-owned-").toFile()
        val application = mockk<Application> { every { filesDir } returns root }
        val source = File(root, "picocrypt_files/input_file.pcv").apply {
            parentFile!!.mkdirs(); writeText("owned encrypted selection")
        }
        fun restore(path: String) = MainViewModel(application, SavedStateHandle(mapOf(
            "selected_filename" to "original.pcv", "copied_file_path" to path, "comments" to "comment",
        ))).formState.value
        try {
            val owned = restore(source.path)
            assertEquals(source.path, owned.copiedFilePath)
            assertEquals("original.pcv", owned.selectedFilename)
            assertEquals("comment", owned.comments)
            assertTrue(owned.passwordInput.isEmpty())

            val foreign = File(root, "foreign.pcv").apply { writeText("foreign") }
            assertTrue(source.delete())
            Files.createSymbolicLink(source.toPath(), foreign.toPath())
            assertEquals("A link in an owned slot must not grant access to its target", "", restore(source.path).copiedFilePath)
            Files.delete(source.toPath())
            assertEquals("A startup-discarded source must not remain selected", "", restore(source.path).copiedFilePath)
        } finally { root.deleteRecursively() }
    }

    @Test
    fun cleanupRefusesForeignPrivatePathsAndLinksButRemovesOwnedFiles() = runTest {
        val root = createTempDirectory("legacy-cleanup-").toFile()
        val context = mockk<Context> { every { filesDir } returns root }
        val foreign = File(root, "private-data").apply { writeText("foreign private bytes") }
        val internal = File(root, "picocrypt_files").apply { mkdirs() }
        val unknown = File(internal, "user-data").apply { writeText("unknown private bytes") }
        val link = File(internal, "input_file.pcv")
        try {
            assertFalse(FileCopyService.cleanupOperationFiles(context, foreign.path, unknown.path, listOf(foreign.path)))
            assertEquals("foreign private bytes", foreign.readText())
            assertEquals("unknown private bytes", unknown.readText())
            Files.createSymbolicLink(link.toPath(), foreign.toPath())
            assertFalse(FileCopyService.cleanupOperationFiles(context, link.path, null, emptyList()))
            assertTrue(Files.isSymbolicLink(link.toPath()))
            assertEquals("foreign private bytes", foreign.readText())
            Files.delete(link.toPath())

            link.writeText("owned ciphertext")
            val output = File(internal, "output_file").apply { writeText("owned plaintext") }
            val key = File(internal, "keyfile_0").apply { writeText("owned key") }
            assertTrue(FileCopyService.cleanupOperationFiles(context, link.path, output.path, listOf(key.path)))
            assertFalse(link.exists())
            assertFalse(output.exists())
            assertFalse(key.exists())
            assertTrue(FileCopyService.cleanupOperationFiles(context, link.path, output.path, listOf(key.path)))
        } finally { root.deleteRecursively() }
    }

    @Test
    fun legacyStartRefusesForeignInputBeforeNativeReservationOrCleanup() = runTest {
        val root = createTempDirectory("legacy-start-boundary-").toFile()
        val context = mockk<Context> { every { filesDir } returns root }
        val foreign = File(root, "user-data.pcv").apply { writeText("private data") }
        val output = File(root, "picocrypt_files/output_file").apply {
            parentFile!!.mkdirs(); writeText("previous output")
        }
        mockkObject(GoBridge)
        every { GoBridge.startOperation() } returns Result.success("must-not-reserve")
        every { GoBridge.startDecrypt(any(), any(), any(), any(), any()) } returns Result.success(Unit)
        try {
            val result = OperationManager.startDecrypt(context,
                TestDataBuilders.createDecryptFormData(copiedFilePath = foreign.path))
            assertTrue("Unowned legacy input must be refused", result.isFailure)
            verify(exactly = 0) { GoBridge.startOperation() }
            assertEquals("previous output", output.readText())
            assertEquals("private data", foreign.readText())
        } finally {
            OperationManager.clearOperation(shouldCleanupFiles = false)
            unmockkObject(GoBridge)
            root.deleteRecursively()
        }
    }

    @Test
    fun forceRetryKeepsTheRequestedCredentialsAfterTheFormIsCleared() = runTest {
        val root = createTempDirectory("legacy-force-credentials-").toFile()
        val context = mockk<Context> { every { filesDir } returns root }
        val input = File(root, "picocrypt_files/input_file.pcv").apply {
            parentFile!!.mkdirs(); writeText("legacy deniable ciphertext")
        }
        val keys = mutableListOf(KeyfileInfo(File(input.parentFile, "keyfile_0").path, "key"))
        File(keys.single().internalPath).writeText("key material")
        val form = TestDataBuilders.createDecryptFormData(copiedFilePath = input.path,
            password = "pässword", keyfiles = keys,
            decryptionInfo = TestDataBuilders.createDecryptionInfo(deniability = true))
        val observedPasswords = mutableListOf<ByteArray>()
        val observedOptions = mutableListOf<DecryptOptions>()
        mockkObject(GoBridge)
        var nextId = 0
        every { GoBridge.startOperation() } answers { Result.success("credential-owner-${nextId++}") }
        every { GoBridge.startDecrypt(any(), any(), any(), any(), any()) } answers {
            observedPasswords.add(arg<ByteArray>(3).copyOf())
            arg<ByteArray>(3).fill(0)
            observedOptions.add(arg(4))
            Result.success(Unit)
        }
        try {
            OperationManager.startDecrypt(context, form).getOrThrow()
            val operation = requireNotNull(OperationManager.currentOperation.value)
            val ownedForm = requireNotNull(operation.formData)
            assertNotSame("Operation credentials must have independent lifetime", form.passwordInput, ownedForm.passwordInput)
            form.clearPasswords()
            keys.clear()
            OperationManager.retryDecryptWithForce(context, operation).getOrThrow()
            assertArrayEquals("pässword".toByteArray(Charsets.UTF_8), observedPasswords.last())
            assertEquals(listOf(File(input.parentFile, "keyfile_0").path), observedOptions.last().keyfiles)
            assertTrue(observedOptions.last().deniability)
            assertTrue(observedOptions.last().forceDecrypt)
            OperationManager.clearOperation(shouldCleanupFiles = false).getOrThrow()
            assertTrue("Dismissal wipes the operation-owned credential", ownedForm.passwordInput.all { it == '\u0000' })
            assertTrue("Retry dismissal preserves the encrypted copy", input.exists())
        } finally {
            OperationManager.clearOperation(shouldCleanupFiles = false)
            observedPasswords.forEach { it.fill(0) }
            unmockkObject(GoBridge)
            root.deleteRecursively()
        }
    }

    @Test
    fun acceptedLegacyStartKeepsCredentialsWhenTheCallerIsCancelled() = runTest {
        val root = createTempDirectory("legacy-cancelled-start-").toFile()
        val context = mockk<Context> { every { filesDir } returns root }
        val input = File(root, "picocrypt_files/input_file.pcv").apply {
            parentFile!!.mkdirs(); writeText("legacy deniable ciphertext")
        }
        val form = TestDataBuilders.createDecryptFormData(copiedFilePath = input.path,
            password = "p\u00e4ssword",
            decryptionInfo = TestDataBuilders.createDecryptionInfo(deniability = true))
            .copy(confirmPasswordInput = "confirmation".toCharArray())
        val observedPasswords = mutableListOf<ByteArray>()
        val observedOptions = mutableListOf<DecryptOptions>()
        lateinit var caller: Job
        mockkObject(GoBridge)
        every { GoBridge.startOperation() } returnsMany listOf(
            Result.success("accepted-before-cancellation"), Result.success("force-after-cancellation"))
        every { GoBridge.startDecrypt(any(), any(), any(), any(), any()) } answers {
            observedPasswords.add(arg<ByteArray>(3).copyOf())
            observedOptions.add(arg(4))
            arg<ByteArray>(3).fill(0)
            if (observedPasswords.size == 1) caller.cancel()
            Result.success(Unit)
        }
        try {
            caller = launch { OperationManager.startDecrypt(context, form).getOrThrow() }
            caller.join()
            assertTrue("The accepted native result must still obey caller cancellation", caller.isCancelled)
            val accepted = requireNotNull(OperationManager.currentOperation.value)
            val owner = requireNotNull(accepted.formData)
            assertEquals("accepted-before-cancellation", accepted.id)
            assertArrayEquals("Accepted credentials must outlive cancelled result delivery",
                "p\u00e4ssword".toCharArray(), owner.passwordInput)
            assertArrayEquals("confirmation".toCharArray(), owner.confirmPasswordInput)
            assertNotSame(form.passwordInput, owner.passwordInput)

            form.clearPasswords()
            OperationManager.retryDecryptWithForce(context, accepted).getOrThrow()
            assertArrayEquals("p\u00e4ssword".toByteArray(Charsets.UTF_8), observedPasswords.last())
            assertTrue(observedOptions.last().forceDecrypt)
            assertTrue(observedOptions.last().deniability)
            OperationManager.clearOperation(shouldCleanupFiles = false).getOrThrow()
            assertTrue("Explicit dismissal wipes the retained password", owner.passwordInput.all { it == '\u0000' })
            assertTrue(owner.confirmPasswordInput.all { it == '\u0000' })
            assertTrue(input.exists())
        } finally {
            OperationManager.clearOperation(shouldCleanupFiles = false)
            form.clearPasswords()
            observedPasswords.forEach { it.fill(0) }
            unmockkObject(GoBridge)
            root.deleteRecursively()
        }
    }

    @Test
    fun rejectedLegacyStartWipesNewOwnerWhenTheCallerIsCancelled() = runTest {
        val root = createTempDirectory("legacy-cancelled-rejection-").toFile()
        val context = mockk<Context> { every { filesDir } returns root }
        val input = File(root, "picocrypt_files/input_file.pcv").apply {
            parentFile!!.mkdirs(); writeText("legacy ciphertext")
        }
        val form = TestDataBuilders.createDecryptFormData(copiedFilePath = input.path, password = "rejected password")
        lateinit var caller: Job
        lateinit var ownedPassword: CharArray
        mockkObject(GoBridge)
        mockkStatic("io.github.picocrypt_ng.picocrypt_ng.SecureBytesKt")
        // Observe the real encoder's mutable input without replacing its implementation.
        every { any<CharArray>().toLegacyUtf8BytesSecure() } answers {
            ownedPassword = firstArg()
            callOriginal()
        }
        every { GoBridge.startOperation() } returns Result.success("rejected-before-cancellation")
        every { GoBridge.startDecrypt(any(), any(), any(), any(), any()) } answers {
            arg<ByteArray>(3).fill(0)
            caller.cancel()
            Result.failure(AppError.ValidationError.InvalidPassword)
        }
        try {
            caller = launch { OperationManager.startDecrypt(context, form) }
            caller.join()
            assertTrue(caller.isCancelled)
            assertNull("A rejected native start cannot retain an operation", OperationManager.currentOperation.value)
            assertNotSame(form.passwordInput, ownedPassword)
            assertTrue("Unaccepted credentials must be wiped despite cancelled result delivery",
                ownedPassword.all { it == '\u0000' })
            assertArrayEquals("rejected password".toCharArray(), form.passwordInput)
            assertTrue(input.exists())
        } finally {
            OperationManager.clearOperation(shouldCleanupFiles = false)
            form.clearPasswords()
            unmockkStatic("io.github.picocrypt_ng.picocrypt_ng.SecureBytesKt")
            unmockkObject(GoBridge)
            root.deleteRecursively()
        }
    }
}
