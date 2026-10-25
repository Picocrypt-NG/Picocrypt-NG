package io.github.picocrypt_ng.picocrypt_ng

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test

class Pcv3RecoveryTrustTest {
    @Test
    fun `actual mobile recovery evidence selects truthful English and Russian warnings`() {
        listOf("mixed", "final-only", "no-anchor").forEach { name ->
            val stream = javaClass.getResourceAsStream("/pcv3-recovery/$name.json")
            assertNotNull("missing captured real mobile snapshot: $name", stream)
            val captured = JSONObject(requireNotNull(stream).bufferedReader().use { it.readText() })
            val snapshot = projectPcv3Snapshot(readSnapshot(captured))
            val artifact = captured.getJSONObject("artifact")
            assertFalse(snapshot.archivePending)
            assertEquals("published-durable", snapshot.publication.state)
            assertEquals("0", artifact.getString("missing"))
            when (name) {
                "mixed" -> {
                    assertEquals("1", artifact.getString("verified"))
                    assertEquals("1", artifact.getString("unverified"))
                    assertEquals("unverified", artifact.getString("final"))
                }
                "final-only" -> {
                    assertEquals("2", artifact.getString("verified"))
                    assertEquals("0", artifact.getString("unverified"))
                    assertEquals("missing", artifact.getString("final"))
                }
                "no-anchor" -> {
                    assertEquals("0", artifact.getString("verified"))
                    assertEquals("2", artifact.getString("unverified"))
                    assertEquals("unverified", artifact.getString("final"))
                }
            }
            val unverified = name == "no-anchor"
            assertEquals(if (unverified) "force-unverified" else "force-partial", snapshot.semantic.outcome)
            assertEquals(listOf(snapshot.semantic.outcome), snapshot.warnings)
            val display = pcv3ResultDisplay(snapshot)
            val expectedTitle = if (unverified) R.string.pcv3_outcome_force_unverified_title else R.string.pcv3_outcome_force_partial_title
            val expectedBody = if (unverified) R.string.pcv3_outcome_force_unverified_body else R.string.pcv3_outcome_force_partial_body
            assertEquals(expectedTitle, display.outcome.titleResId)
            assertEquals(expectedBody, display.outcome.bodyResId)
            assertEquals(R.string.pcv3_recovery_result_close, display.closeActionResId)
            val resourcePrefix = if (unverified) "pcv3_outcome_force_unverified" else "pcv3_outcome_force_partial"
            for ((locale, title, body) in if (unverified) listOf(
                Triple("values", "Unverified recovery", "Integrity could not be verified. Do not treat this file as trusted."),
                Triple("values-ru", "Непроверенное восстановление", "Целостность не подтверждена. Не считайте файл проверенным."),
            ) else listOf(
                Triple("values", "Partial recovery", "Not a fully verified file. Data may be missing or unverified."),
                Triple("values-ru", "Частичное восстановление", "Файл проверен не полностью. Возможны пропуски и непроверенные данные."),
            )) {
                assertEquals("$name $locale warning", body, resourceText(locale, "${resourcePrefix}_body"))
                assertEquals("$name $locale title", title, resourceText(locale, "${resourcePrefix}_title"))
            }
        }
    }

    private fun readSnapshot(data: JSONObject) = Pcv3SnapshotData(
        statusCode = data.getString("statusCode"), statusArgs = data.strings("statusArgs"),
        outcome = data.getString("outcome"), stage = data.getString("stage"), code = data.getString("code"),
        forceProvenance = data.getString("forceProvenance"), d1BootstrapProvenance = data.getString("d1BootstrapProvenance"),
        detailStage = data.getString("detailStage"), publicationAttempted = data.getBoolean("publicationAttempted"),
        publicationState = data.getString("publicationState"), publicationStage = data.getString("publicationStage"),
        publicationCode = data.getString("publicationCode"), diagnostic = data.getString("diagnostic"),
        completionClass = data.getString("completionClass"), args = data.strings("args"),
        warnings = data.strings("warnings"), archivePending = data.getBoolean("archivePending"),
    )

    private fun JSONObject.strings(key: String): List<String> = getJSONArray(key).let { array ->
        List(array.length()) { array.getString(it) }
    }

    // Read shipped resources, so selecting the right resource ID cannot conceal
    // a false statement about missing ranges or unauthenticated data bytes.
    private fun resourceText(locale: String, name: String): String {
        val document = DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(File("src/main/res/$locale/strings.xml"))
        val strings = document.getElementsByTagName("string")
        return (0 until strings.length).map { strings.item(it) }
            .single { it.attributes.getNamedItem("name").nodeValue == name }.textContent
    }
}
