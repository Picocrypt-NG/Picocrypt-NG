package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.content.res.Resources
import io.mockk.every
import io.mockk.mockk
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class AppErrorTextTest {
    @Test
    fun `localizedMessage prefers resource text over fallback userMessage`() {
        val context = mockk<Context>()
        every { context.getString(R.string.error_auth_failed) } returns "Localized authentication failure"

        val error = AppError.OperationError.PasswordAuth(
            userMessage = "raw Go auth text",
            technicalMessage = "raw Go auth text",
            messageResId = R.string.error_auth_failed,
        )

        assertEquals("Localized authentication failure", error.localizedMessage(context))
    }

    @Test
    fun `localizedMessage uses resource-backed fallback instead of raw exception text`() {
        val context = mockk<Context>()
        every { context.getString(R.string.error_operation_failed) } returns "Localized operation failure"

        val error = AppError.fromException(
            RuntimeException("raw JVM detail /private/path"),
        )

        assertEquals("Localized operation failure", error.localizedMessage(context))
        assertEquals("raw JVM detail /private/path", error.technicalMessage)
        assertFalse(error.userMessage.contains("raw JVM detail /private/path"))
        assertTrue(error.messageArgs.isEmpty())
    }

    @Test
    fun `corrupt header uses dedicated localized display instead of raw Go text`() {
        val context = mockk<Context>()
        every { context.getString(R.string.error_corrupt_header) } returns "Localized corrupt-header failure"

        val error = AppError.fromGoError(
            errorString = "header damaged: volume header is damaged",
            operationType = OperationType.DECRYPT,
            code = "CORRUPT_HEADER",
        )

        assertTrue(error is AppError.OperationError.GenericOperation)
        assertEquals(R.string.error_corrupt_header, error.messageResId)
        assertEquals("Localized corrupt-header failure", error.localizedMessage(context))
        assertEquals("header damaged: volume header is damaged", error.technicalMessage)
        assertFalse(error.userMessage.contains("header damaged"))
    }

    @Test
    fun `localizedMessage formats validation resource arguments`() {
        val context = mockk<Context>()
        every {
            context.getString(R.string.error_split_volume_not_supported, ".pcv")
        } returns "Move the single .pcv file."

        val error = AppError.ValidationError.SplitVolumeNotSupported

        assertEquals(listOf(".pcv"), error.messageArgs)
        assertEquals("Move the single .pcv file.", error.localizedMessage(context))
    }

    @Test
    fun `AUTH_FAILED maps to password auth with localized display resource`() {
        val error = AppError.fromGoError(
            errorString = "raw auth failure",
            operationType = OperationType.DECRYPT,
            code = "AUTH_FAILED",
        )

        assertTrue(error is AppError.OperationError.PasswordAuth)
        assertTrue(error.allowsPasswordRetry())
        assertFalse(error.allowsForceDecrypt())
        assertEquals(R.string.error_auth_failed, error.messageResId)
        assertEquals("raw auth failure", error.technicalMessage)
    }

    @Test
    fun `DATA_CORRUPTED maps to data corruption with localized display resource`() {
        val error = AppError.fromGoError(
            errorString = "raw integrity failure",
            operationType = OperationType.DECRYPT,
            code = "DATA_CORRUPTED",
        )

        assertTrue(error is AppError.OperationError.DataCorruption)
        assertTrue(error.allowsForceDecrypt())
        assertFalse(error.allowsPasswordRetry())
        assertEquals(R.string.error_data_corrupted, error.messageResId)
        assertEquals("raw integrity failure", error.technicalMessage)
    }

    @Test
    fun `failureReasonResId walks typed causes in priority order`() {
        val cases = listOf(
            SecurityException("raw permission detail") to R.string.error_reason_permission_denied,
            RuntimeException("wrapper", FileNotFoundException("raw missing detail")) to
                R.string.error_reason_file_not_found,
            RuntimeException("wrapper", AppError.FileError.InsufficientStorage()) to
                R.string.error_reason_insufficient_storage,
            RuntimeException("wrapper", IOException("raw I/O detail")) to R.string.error_reason_io,
            IllegalArgumentException("raw unknown detail") to R.string.error_reason_unknown,
        )

        cases.forEach { (error, expectedResource) ->
            assertEquals(expectedResource, failureReasonResId(error))
        }
    }

    @Test(timeout = 1_000)
    fun `failureReasonResId terminates on a malformed cyclic cause chain`() {
        val cyclic = object : RuntimeException("raw cyclic detail") {
            override val cause: Throwable
                get() = this
        }

        assertEquals(R.string.error_reason_unknown, failureReasonResId(cyclic))
    }

    @Test
    fun `localizedFailureReason resolves only the localized reason category`() {
        val context = mockk<Context>()
        every {
            context.getString(R.string.error_reason_permission_denied)
        } returns "Localized permission denial"

        val reason = localizedFailureReason(
            context,
            RuntimeException("outer raw detail", SecurityException("inner raw detail")),
        )

        assertEquals("Localized permission denial", reason)
        assertFalse(reason.contains("raw detail"))
    }

    @Test
    fun `EN and RU reason wrappers retain exactly one positional string placeholder`() {
        val wrappers = listOf(
            "error_read_folder_failed",
            "error_copy_files_failed",
            "keyfile_create_failed",
        )

        listOf(
            "src/main/res/values/strings.xml",
            "src/main/res/values-ru/strings.xml",
        ).forEach { catalog ->
            wrappers.forEach { resourceName ->
                assertEquals(
                    "$catalog $resourceName placeholder contract",
                    listOf("%1\$s"),
                    formatSpecifiers(catalog, resourceName),
                )
            }
        }
    }

    @Test
    fun `Resources overloads localize the keyfile wrapper and confine raw detail`() {
        val resources = mockk<Resources>()
        every {
            resources.getString(R.string.error_reason_permission_denied)
        } returns "Localized permission denial"
        every {
            resources.getString(R.string.keyfile_create_failed, "Localized permission denial")
        } returns "Localized keyfile failure: Localized permission denial"

        val raw = "raw keyfile failure /private/path"
        val reason = localizedFailureReason(resources, SecurityException(raw))
        val error = AppError.FileError.SaveFailed(
            userMessage = "Localized fallback without raw detail",
            technicalMessage = raw,
            messageResId = R.string.keyfile_create_failed,
            messageArgs = listOf(reason),
        )
        val display = error.localizedMessage(resources)

        assertEquals("Localized keyfile failure: Localized permission denial", display)
        assertFalse(display.contains(raw))
        assertEquals(raw, error.technicalMessage)
        assertFalse(error.userMessage.contains(raw))
    }

    private fun formatSpecifiers(path: String, resourceName: String): List<String> {
        val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(File(path))
        val strings = document.getElementsByTagName("string")
        val value = (0 until strings.length)
            .map { strings.item(it) as Element }
            .single { it.getAttribute("name") == resourceName }
            .textContent
        return Regex("""%\d+\${'$'}[a-zA-Z]""").findAll(value).map { it.value }.toList()
    }
}
