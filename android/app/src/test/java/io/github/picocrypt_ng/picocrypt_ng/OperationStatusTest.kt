package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.content.res.Resources
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class OperationStatusTest {
    @Test
    fun `every static status code resolves through its matching resource`() {
        val context = mockk<Context>()
        staticStatusResources.forEach { (code, resourceId) ->
            every { context.getString(resourceId) } returns "localized:$code"

            assertEquals(
                OperationDisplayText(status = "localized:$code"),
                renderOperationStatus(
                    context = context,
                    status = OperationStatusData(code),
                    detail = OperationProgressDetail(OperationProgress.NONE),
                    progress = 0f,
                ),
            )
        }
    }

    @Test
    fun `every rate status code formats validated speed and ETA through its resource`() {
        val context = mockk<Context>()
        rateStatusResources.forEach { (code, resourceId) ->
            every { context.getString(resourceId, 12.34, "01:02:03") } returns "localized:$code"

            assertEquals(
                OperationDisplayText(status = "localized:$code"),
                renderOperationStatus(
                    context = context,
                    status = OperationStatusData(code, 12.34, "01:02:03"),
                    detail = OperationProgressDetail(OperationProgress.NONE),
                    progress = 0f,
                ),
            )
            verify(exactly = 1) { context.getString(resourceId, 12.34, "01:02:03") }
        }
    }

    @Test
    fun `percent detail delegates locale aware decimal formatting to Android resources`() {
        val context = mockk<Context>()
        every { context.getString(R.string.status_encrypting_rate, 1.25, "00:00:09") } returns "Шифрование"
        every { context.getString(R.string.progress_percent, 37.5) } returns "37,50 %"

        val result = renderOperationStatus(
            context = context,
            status = OperationStatusData(OperationStatus.ENCRYPTING_RATE, 1.25, "00:00:09"),
            detail = OperationProgressDetail(OperationProgress.PERCENT),
            progress = 0.375f,
        )

        assertEquals(OperationDisplayText("Шифрование", "37,50 %"), result)
        verify(exactly = 1) { context.getString(R.string.progress_percent, 37.5) }
    }

    @Test
    fun `item count detail uses the localized plural selected by total`() {
        val context = mockk<Context>()
        val resources = mockk<Resources>()
        every { context.getString(R.string.status_compressing_files) } returns "Compressing"
        every { context.resources } returns resources
        every {
            resources.getQuantityString(R.plurals.progress_item_count, 10, 3L, 10L)
        } returns "3 of 10 items"

        val result = renderOperationStatus(
            context = context,
            status = OperationStatusData(OperationStatus.COMPRESSING_FILES),
            detail = OperationProgressDetail(OperationProgress.ITEM_COUNT, current = 3, total = 10),
            progress = 0.3f,
        )

        assertEquals(OperationDisplayText("Compressing", "3 of 10 items"), result)
        verify(exactly = 1) {
            resources.getQuantityString(R.plurals.progress_item_count, 10, 3L, 10L)
        }
    }

    @Test
    fun `unknown status degrades to working while unknown detail stays hidden`() {
        val context = mockk<Context>()
        every { context.getString(R.string.fgs_working) } returns "Working safely"

        val result = renderOperationStatus(
            context = context,
            status = OperationStatusData(OperationStatus.UNKNOWN),
            detail = OperationProgressDetail(OperationProgress.UNKNOWN),
            progress = 0.5f,
        )

        assertEquals(OperationDisplayText("Working safely", null), result)
    }

    @Test
    fun `none detail stays hidden`() {
        val context = mockk<Context>()
        every { context.getString(R.string.status_starting) } returns "Starting"

        val result = renderOperationStatus(
            context = context,
            status = OperationStatusData(OperationStatus.STARTING),
            detail = OperationProgressDetail(OperationProgress.NONE),
            progress = 0f,
        )

        assertNull(result.detail)
    }

    @Test
    fun `malformed rate arguments degrade to working instead of interpolation`() {
        val context = mockk<Context>()
        every { context.getString(R.string.fgs_working) } returns "Working safely"
        val malformed = listOf(
            OperationStatusData(OperationStatus.ENCRYPTING_RATE, Double.NaN, "01:02:03"),
            OperationStatusData(OperationStatus.ENCRYPTING_RATE, Double.POSITIVE_INFINITY, "01:02:03"),
            OperationStatusData(OperationStatus.ENCRYPTING_RATE, -0.01, "01:02:03"),
            OperationStatusData(OperationStatus.ENCRYPTING_RATE, 1.0, "1:02:03"),
            OperationStatusData(OperationStatus.ENCRYPTING_RATE, 1.0, "01:60:03"),
            OperationStatusData(OperationStatus.ENCRYPTING_RATE, 1.0, "01:02:60"),
        )

        malformed.forEach { status ->
            assertEquals(
                "Working safely",
                renderOperationStatus(
                    context,
                    status,
                    OperationProgressDetail(OperationProgress.NONE),
                    progress = 0f,
                ).status,
            )
        }
        verify(exactly = 0) {
            context.getString(R.string.status_encrypting_rate, any(), any())
        }
    }

    @Test
    fun `malformed progress arguments stay hidden`() {
        val context = mockk<Context>()
        every { context.getString(R.string.status_starting) } returns "Starting"
        val malformed = listOf(
            OperationProgressDetail(OperationProgress.PERCENT) to Float.NaN,
            OperationProgressDetail(OperationProgress.PERCENT) to -0.01f,
            OperationProgressDetail(OperationProgress.PERCENT) to 1.01f,
            OperationProgressDetail(OperationProgress.ITEM_COUNT, current = -1, total = 10) to 0f,
            OperationProgressDetail(OperationProgress.ITEM_COUNT, current = 11, total = 10) to 0f,
            OperationProgressDetail(OperationProgress.ITEM_COUNT, current = 0, total = 0) to 0f,
            OperationProgressDetail(
                OperationProgress.ITEM_COUNT,
                current = 1,
                total = Int.MAX_VALUE.toLong() + 1,
            ) to 0f,
        )

        malformed.forEach { (detail, progress) ->
            assertNull(
                renderOperationStatus(
                    context,
                    OperationStatusData(OperationStatus.STARTING),
                    detail,
                    progress,
                ).detail,
            )
        }
    }

    @Test
    fun `status resources mirror stable codes and preserve typed rate placeholders`() {
        val base = parseResources("src/main/res/values/strings.xml")
        val russian = parseResources("src/main/res/values-ru/strings.xml")
        val requiredStrings = (staticStatusResources.values + rateStatusResources.values)
            .map(::resourceEntryName)
            .toSet() + "progress_percent"

        requiredStrings.forEach { name ->
            assertTrue("Base resources must contain $name", base.strings.containsKey(name))
            assertTrue("Russian resources must contain $name", russian.strings.containsKey(name))
        }
        rateStatusResources.values.map(::resourceEntryName).forEach { name ->
            listOf(base, russian).forEach { catalog ->
                val text = catalog.strings.getValue(name)
                assertTrue("$name must preserve two-decimal speed", text.contains("%1$.2f"))
                assertTrue("$name must preserve ETA argument", text.contains("%2\$s"))
                assertTrue("$name must preserve the MiB unit", text.contains("MiB"))
            }
        }
        assertEquals("%1$.2f%%", base.strings.getValue("progress_percent"))
        assertEquals("%1$.2f%%", russian.strings.getValue("progress_percent"))
        assertEquals(setOf("one", "other"), base.plurals.getValue("progress_item_count"))
        assertEquals(
            setOf("one", "few", "many", "other"),
            russian.plurals.getValue("progress_item_count"),
        )
    }

    @Test
    fun `both status consumers call the shared renderer without raw notification status`() {
        val service = File(
            "src/main/java/io/github/picocrypt_ng/picocrypt_ng/OperationForegroundService.kt"
        ).readText()
        val progressCard = File(
            "src/main/java/io/github/picocrypt_ng/picocrypt_ng/ui/components/ProgressCard.kt"
        ).readText()

        assertTrue(service.contains("renderOperationStatus("))
        assertTrue(progressCard.contains("renderOperationStatus("))
        assertTrue(
            "Notification content must use the shared renderer output",
            Regex("\\.setContentText\\(displayText\\.status\\)").containsMatchIn(service),
        )
        assertFalse(
            "Notification content must never receive raw status",
            Regex("\\.setContentText\\(status\\)").containsMatchIn(service),
        )
    }

    private fun parseResources(path: String): ResourceCatalog {
        val document = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(File(path))
        val strings = document.getElementsByTagName("string")
        val stringValues = (0 until strings.length)
            .map { strings.item(it) as Element }
            .associate { it.getAttribute("name") to it.textContent }
        val plurals = document.getElementsByTagName("plurals")
        val pluralValues = (0 until plurals.length)
            .map { plurals.item(it) as Element }
            .associate { plural ->
                val items = plural.getElementsByTagName("item")
                plural.getAttribute("name") to (0 until items.length)
                    .map { (items.item(it) as Element).getAttribute("quantity") }
                    .toSet()
            }
        return ResourceCatalog(stringValues, pluralValues)
    }

    private fun resourceEntryName(resourceId: Int): String = resourceNames.getValue(resourceId)

    private data class ResourceCatalog(
        val strings: Map<String, String>,
        val plurals: Map<String, Set<String>>,
    )

    private companion object {
        private val staticStatusResources = linkedMapOf(
            OperationStatus.STARTING to R.string.status_starting,
            OperationStatus.COMPLETED to R.string.status_completed,
            OperationStatus.CANCELLED to R.string.status_cancelled,
            OperationStatus.ERROR to R.string.status_error,
            OperationStatus.COMPRESSING_FILES to R.string.status_compressing_files,
            OperationStatus.GENERATING_VALUES to R.string.status_generating_values,
            OperationStatus.DERIVING_KEY to R.string.status_deriving_key,
            OperationStatus.READING_KEYFILES to R.string.status_reading_keyfiles,
            OperationStatus.CALCULATING_VALUES to R.string.status_calculating_values,
            OperationStatus.WRITING_VALUES to R.string.status_writing_values,
            OperationStatus.SPLITTING to R.string.status_splitting,
            OperationStatus.RECOMBINING_CHUNKS to R.string.status_recombining_chunks,
            OperationStatus.READING_VALUES to R.string.status_reading_values,
            OperationStatus.DUPLICATE_KEYFILES_WARNING to R.string.status_duplicate_keyfiles_warning,
            OperationStatus.VERIFYING_INTEGRITY to R.string.status_verifying_integrity,
            OperationStatus.MAC_VERIFICATION_FAILED_CONTINUING to
                R.string.status_mac_verification_failed_continuing,
            OperationStatus.REPAIRING_VERIFYING to R.string.status_repairing_verifying,
            OperationStatus.INTEGRITY_VERIFIED_DECRYPTING to
                R.string.status_integrity_verified_decrypting,
            OperationStatus.COMPARING_VALUES to R.string.status_comparing_values,
            OperationStatus.UNZIPPING to R.string.status_unzipping,
            OperationStatus.ADDING_PLAUSIBLE_DENIABILITY to
                R.string.status_adding_plausible_deniability,
            OperationStatus.REMOVING_DENIABILITY_PROTECTION to
                R.string.status_removing_deniability_protection,
        )

        private val rateStatusResources = linkedMapOf(
            OperationStatus.COMPRESSING_RATE to R.string.status_compressing_rate,
            OperationStatus.ENCRYPTING_RATE to R.string.status_encrypting_rate,
            OperationStatus.SPLITTING_RATE to R.string.status_splitting_rate,
            OperationStatus.RECOMBINING_RATE to R.string.status_recombining_rate,
            OperationStatus.VERIFYING_RATE to R.string.status_verifying_rate,
            OperationStatus.DECRYPTING_RATE to R.string.status_decrypting_rate,
            OperationStatus.REPAIRING_RATE to R.string.status_repairing_rate,
            OperationStatus.UNPACKING_RATE to R.string.status_unpacking_rate,
            OperationStatus.ADDING_DENIABILITY_RATE to R.string.status_adding_deniability_rate,
            OperationStatus.REMOVING_DENIABILITY_RATE to R.string.status_removing_deniability_rate,
        )

        private val resourceNames = mapOf(
            R.string.status_starting to "status_starting",
            R.string.status_completed to "status_completed",
            R.string.status_cancelled to "status_cancelled",
            R.string.status_error to "status_error",
            R.string.status_compressing_files to "status_compressing_files",
            R.string.status_generating_values to "status_generating_values",
            R.string.status_deriving_key to "status_deriving_key",
            R.string.status_reading_keyfiles to "status_reading_keyfiles",
            R.string.status_calculating_values to "status_calculating_values",
            R.string.status_writing_values to "status_writing_values",
            R.string.status_splitting to "status_splitting",
            R.string.status_recombining_chunks to "status_recombining_chunks",
            R.string.status_reading_values to "status_reading_values",
            R.string.status_duplicate_keyfiles_warning to "status_duplicate_keyfiles_warning",
            R.string.status_verifying_integrity to "status_verifying_integrity",
            R.string.status_mac_verification_failed_continuing to
                "status_mac_verification_failed_continuing",
            R.string.status_repairing_verifying to "status_repairing_verifying",
            R.string.status_integrity_verified_decrypting to
                "status_integrity_verified_decrypting",
            R.string.status_comparing_values to "status_comparing_values",
            R.string.status_unzipping to "status_unzipping",
            R.string.status_adding_plausible_deniability to "status_adding_plausible_deniability",
            R.string.status_removing_deniability_protection to
                "status_removing_deniability_protection",
            R.string.status_compressing_rate to "status_compressing_rate",
            R.string.status_encrypting_rate to "status_encrypting_rate",
            R.string.status_splitting_rate to "status_splitting_rate",
            R.string.status_recombining_rate to "status_recombining_rate",
            R.string.status_verifying_rate to "status_verifying_rate",
            R.string.status_decrypting_rate to "status_decrypting_rate",
            R.string.status_repairing_rate to "status_repairing_rate",
            R.string.status_unpacking_rate to "status_unpacking_rate",
            R.string.status_adding_deniability_rate to "status_adding_deniability_rate",
            R.string.status_removing_deniability_rate to "status_removing_deniability_rate",
        )
    }
}
