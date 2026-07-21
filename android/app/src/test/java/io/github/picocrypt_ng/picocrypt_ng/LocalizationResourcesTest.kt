package io.github.picocrypt_ng.picocrypt_ng

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class LocalizationResourcesTest {
    private val stringsFile = File("src/main/res/values/strings.xml")
    private val russianStringsFile = File("src/main/res/values-ru/strings.xml")
    private val document by lazy {
        DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(stringsFile)
    }
    private val russianDocument by lazy {
        DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(russianStringsFile)
    }
    private val catalogs
        get() = listOf("English" to document, "Russian" to russianDocument)

    @Test
    fun `app name stays non translatable`() {
        val appName = stringElement("app_name")

        assertEquals("false", appName.getAttribute("translatable"))
        assertEquals("Picocrypt-NG", appName.textContent)
    }

    @Test
    fun `every plural resource defines an other quantity`() {
        val missingOther = pluralElements()
            .filter { element -> pluralItems(element).none { it.first == "other" } }
            .map { it.getAttribute("name") }

        assertTrue("Plural resources missing quantity=\"other\": $missingOther", missingOther.isEmpty())
    }

    @Test
    fun `catalogs do not use file parenthetical shortcuts`() {
        val offenders = catalogs.flatMap { (catalog, catalogDocument) ->
            textResources(catalogDocument)
                .filter { it.text.contains("file(s)", ignoreCase = true) }
                .map { "$catalog ${it.name}: ${it.text}" }
        }

        assertTrue("Use real plural resources instead of file(s): $offenders", offenders.isEmpty())
    }

    @Test
    fun `formatted strings use positional placeholders`() {
        val offenders = catalogs.flatMap { (catalog, catalogDocument) ->
            textResources(catalogDocument).flatMap { resource ->
                formatSpecifiers.findAll(resource.text)
                    .filter { it.groups[1] == null }
                    .map { "$catalog ${resource.name}: ${resource.text}" }
            }
        }.distinct()

        assertTrue("Formatted resources must use positional placeholders: $offenders", offenders.isEmpty())
    }

    @Test
    fun `typed status and error formats stay exact in both catalogs`() {
        catalogs.forEach { (catalog, catalogDocument) ->
            exactStringFormatContracts.forEach { (name, expected) ->
                assertEquals(
                    "$catalog string $name placeholder contract",
                    expected,
                    formatSpecifiersIn(stringElement(catalogDocument, name).textContent),
                )
            }

            exactPluralFormatContracts.forEach { (name, expected) ->
                pluralItems(pluralElement(catalogDocument, name)).forEach { (quantity, text) ->
                    assertEquals(
                        "$catalog plural $name[$quantity] placeholder contract",
                        expected,
                        formatSpecifiersIn(text),
                    )
                }
            }
        }
    }

    @Test
    fun `russian catalog mirrors the ordered base resource schema`() {
        assertTrue("Missing Russian resources at ${russianStringsFile.path}", russianStringsFile.isFile)

        val baseStringNames = stringElements(document)
            .filterNot { it.getAttribute("translatable") == "false" }
            .map { it.getAttribute("name") }
        val russianStringNames = stringElements(russianDocument)
            .map { it.getAttribute("name") }

        assertEquals(baseStringNames, russianStringNames)
        assertEquals(pluralNames(document), pluralNames(russianDocument))
    }

    @Test
    fun `catalog resource names are unique and visible values are not blank`() {
        catalogs.forEach { (catalog, catalogDocument) ->
            val strings = stringElements(catalogDocument)
            val plurals = pluralElements(catalogDocument)
            val stringNames = strings.map { it.getAttribute("name") }
            val pluralNames = plurals.map { it.getAttribute("name") }
            val duplicateStrings = duplicateValues(stringNames)
            val duplicatePlurals = duplicateValues(pluralNames)
            val crossTypeDuplicates = stringNames.toSet().intersect(pluralNames.toSet())
            val blankStrings = strings
                .filter { it.getAttribute("name").isBlank() || it.textContent.isBlank() }
                .map { it.getAttribute("name") }
            val blankPlurals = plurals
                .filter { it.getAttribute("name").isBlank() || pluralItems(it).isEmpty() }
                .map { it.getAttribute("name") }
            val invalidPluralItems = plurals.flatMap { plural ->
                val name = plural.getAttribute("name")
                val items = pluralItems(plural)
                val duplicateQuantities = duplicateValues(items.map { it.first })
                    .map { "$name[$it] duplicate" }
                val blanks = items
                    .filter { (quantity, text) -> quantity.isBlank() || text.isBlank() }
                    .map { (quantity, _) -> "$name[$quantity] blank" }
                duplicateQuantities + blanks
            }

            assertTrue("$catalog duplicate strings: $duplicateStrings", duplicateStrings.isEmpty())
            assertTrue("$catalog duplicate plurals: $duplicatePlurals", duplicatePlurals.isEmpty())
            assertTrue(
                "$catalog names shared by string and plural resources: $crossTypeDuplicates",
                crossTypeDuplicates.isEmpty(),
            )
            assertTrue("$catalog blank string resources: $blankStrings", blankStrings.isEmpty())
            assertTrue("$catalog blank plural resources: $blankPlurals", blankPlurals.isEmpty())
            assertTrue(
                "$catalog blank or duplicate plural items: $invalidPluralItems",
                invalidPluralItems.isEmpty(),
            )
        }
    }

    @Test
    fun `renderer and localized error boundary resources exist in both catalogs`() {
        catalogs.forEach { (catalog, catalogDocument) ->
            val stringNames = stringElements(catalogDocument)
                .map { it.getAttribute("name") }
                .toSet()
            val missingStrings = requiredRendererStrings
                .plus(requiredErrorBoundaryStrings)
                .filterNot(stringNames::contains)
            val pluralNames = pluralNames(catalogDocument).toSet()
            val missingPlurals = requiredRendererPlurals.filterNot(pluralNames::contains)

            assertTrue("$catalog missing required strings: $missingStrings", missingStrings.isEmpty())
            assertTrue("$catalog missing required plurals: $missingPlurals", missingPlurals.isEmpty())
        }
    }

    @Test
    fun `russian plurals use Russian quantity categories`() {
        pluralNames(document).forEach { name ->
            val quantities = pluralItems(pluralElement(russianDocument, name))
                .map { it.first }

            assertEquals(
                "Russian plural $name should define one, few, many, and other",
                listOf("one", "few", "many", "other"),
                quantities,
            )
        }
    }

    @Test
    fun `every translated string and plural preserves the exact placeholder multiset`() {
        val baseStrings = stringElements(document)
            .filterNot { it.getAttribute("translatable") == "false" }
            .associate { it.getAttribute("name") to formatSpecifiersIn(it.textContent) }
        val stringMismatches = stringElements(russianDocument)
            .filter { russian -> formatSpecifiersIn(russian.textContent) != baseStrings[russian.getAttribute("name")] }
            .map { russian ->
                val name = russian.getAttribute("name")
                "$name: ${formatSpecifiersIn(russian.textContent)} != ${baseStrings[name]}"
            }

        val basePluralOther = pluralElements(document)
            .associate { plural ->
                val name = plural.getAttribute("name")
                val other = pluralItems(plural).first { it.first == "other" }.second
                name to formatSpecifiersIn(other)
            }
        val pluralMismatches = pluralElements(russianDocument).flatMap { plural ->
            val name = plural.getAttribute("name")
            val expected = basePluralOther[name]
            pluralItems(plural)
                .filter { (_, text) -> formatSpecifiersIn(text) != expected }
                .map { (quantity, text) -> "$name[$quantity]: ${formatSpecifiersIn(text)} != $expected" }
        }

        val basePluralMismatches = pluralElements(document).flatMap { plural ->
            val name = plural.getAttribute("name")
            val expected = basePluralOther.getValue(name)
            pluralItems(plural)
                .filter { (_, text) -> formatSpecifiersIn(text) != expected }
                .map { (quantity, text) ->
                    "base $name[$quantity]: ${formatSpecifiersIn(text)} != $expected"
                }
        }
        val placeholderMismatches = stringMismatches + basePluralMismatches + pluralMismatches

        assertTrue(
            "Translated resources must preserve positional format placeholders: $placeholderMismatches",
            placeholderMismatches.isEmpty(),
        )
    }

    @Test
    fun `russian high risk wording keeps security meaning`() {
        assertRussianContains("force_decrypt_warning", "непровер", "повреж")
        assertRussianContains("error_data_corrupted", "не провер", "повреж")
        assertRussianContains("error_corrupt_header", "заголов", "повреж")
        assertRussianContains("error_decrypt_retry_only", "только", "расшифр", "принуд")
        assertRussianContains("comments_plaintext_warning", "открыт", "метадан")
        assertRussianContains("error_auth_failed", "аутентиф", "парол", "ключев")
        assertRussianContains("prevent_screenshots_description", "сним", "запис", "недавн")
        assertRussianContains("deniability_note", "правдоподоб", "отриц", "метадан", "нельзя")

        val deniabilityCopy = textResources(russianDocument)
            .filter { it.name.contains("deniability") }
            .joinToString(separator = "\n") { it.text.lowercase() }
        assertFalse("Russian deniability copy must not promise anonymity", deniabilityCopy.contains("аноним"))
        assertFalse("Russian deniability copy must not promise invisibility", deniabilityCopy.contains("невидим"))
        assertFalse("Russian deniability copy must not call deniability a hidden mode", deniabilityCopy.contains("скрытый режим"))

        val authenticationCopy = textResources(russianDocument)
            .joinToString(separator = "\n") { it.text.lowercase() }
        assertFalse(
            "Russian authentication copy must not imply accounts, logins, or authorization",
            disallowedRussianAuthenticationWords.containsMatchIn(authenticationCopy),
        )
    }

    @Test
    fun `technical filename extensions stay format arguments`() {
        assertContainsWords("error_split_volume_not_supported", "not supported", "recombine")
        assertRussianContains("error_split_volume_not_supported", "не поддерж", "объедин")

        val rawExtensionMentions = catalogs.flatMap { (catalog, catalogDocument) ->
            textResources(catalogDocument)
                .filter { it.name != "app_name" }
                .filter { resource -> rawFilenameExtension.containsMatchIn(resource.text) }
                .map { "$catalog ${it.name}: ${it.text}" }
        }

        assertTrue(
            "Translator-facing strings must pass technical filename extensions as arguments: $rawExtensionMentions",
            rawExtensionMentions.isEmpty(),
        )
    }

    @Test
    fun `counted keyfile and selected file labels are plural resources`() {
        assertPlural("keyfiles_count")
        assertPlural("keyfiles_required_count")
        assertPlural("selected_files_count")
    }

    @Test
    fun `high risk wording keeps security meaning`() {
        assertContainsWords("force_decrypt_warning", "unverified", "corrupted")
        assertContainsWords("error_data_corrupted", "unverified", "corrupted")
        assertContainsWords("error_corrupt_header", "header", "damaged")
        assertContainsWords("error_decrypt_retry_only", "only", "decryption", "force decrypt")
        assertContainsWords("comments_plaintext_warning", "plaintext metadata")
        assertContainsWords("error_auth_failed", "authentication", "password", "keyfile")
        assertContainsWords("deniability_note", "deniability mode", "metadata", "cannot be previewed")
        assertContainsWords(
            "prevent_screenshots_description",
            "screenshots",
            "screen recording",
            "recent apps",
        )

        val deniabilityCopy = textResources()
            .filter { it.name.contains("deniability") }
            .joinToString(separator = "\n") { it.text.lowercase() }
        assertFalse("Deniability copy must not promise anonymity", deniabilityCopy.contains("anonymous"))
        assertFalse("Deniability copy must not call deniability a hidden mode", deniabilityCopy.contains("hidden mode"))

        val authenticationCopy = textResources()
            .joinToString(separator = "\n") { it.text.lowercase() }
        assertFalse(
            "Authentication copy must not imply Picocrypt-NG has accounts, logins, or authorization",
            disallowedAuthenticationWords.containsMatchIn(authenticationCopy),
        )
    }

    @Test
    fun `status resources keep invariant units and phase digits in both catalogs`() {
        catalogs.forEach { (catalog, catalogDocument) ->
            rateStatusResourceNames.forEach { name ->
                val text = stringElement(catalogDocument, name).textContent
                assertTrue("$catalog $name must preserve MiB: $text", text.contains("MiB"))
                assertTrue("$catalog $name must preserve ETA: $text", text.contains("ETA"))
            }

            val verificationDigits = Regex("""\d+""")
                .findAll(stringElement(catalogDocument, "status_verifying_integrity").textContent)
                .map { it.value }
                .toList()
            assertEquals(
                "$catalog verify-first status must preserve phase digits",
                listOf("1", "2"),
                verificationDigits,
            )
        }
    }

    @Test
    fun `authentication wording guard rejects account login and authorization terms`() {
        val blockedTerms = listOf(
            "account",
            "login",
            "log in",
            "sign in",
            "signin",
            "authorization",
            "authorize",
            "authorized",
        )

        val missedTerms = blockedTerms.filterNot { term ->
            disallowedAuthenticationWords.containsMatchIn("Volume $term failed")
        }

        assertTrue("Authentication wording guard missed: $missedTerms", missedTerms.isEmpty())
    }

    private fun stringElement(name: String): Element {
        return stringElement(document, name)
    }

    private fun stringElement(document: org.w3c.dom.Document, name: String): Element {
        val nodes = document.getElementsByTagName("string")
        for (index in 0 until nodes.length) {
            val element = nodes.item(index) as Element
            if (element.getAttribute("name") == name) return element
        }
        throw AssertionError("Missing string resource: $name")
    }

    private fun pluralElement(name: String): Element {
        return pluralElement(document, name)
    }

    private fun pluralElement(document: org.w3c.dom.Document, name: String): Element {
        return pluralElements(document).firstOrNull { it.getAttribute("name") == name }
            ?: throw AssertionError("Missing plurals resource: $name")
    }

    private fun pluralElements(document: org.w3c.dom.Document = this.document): List<Element> {
        val nodes = document.getElementsByTagName("plurals")
        return List(nodes.length) { index -> nodes.item(index) as Element }
    }

    private fun pluralNames(document: org.w3c.dom.Document): List<String> {
        return pluralElements(document).map { it.getAttribute("name") }
    }

    private fun pluralItems(element: Element): List<Pair<String, String>> {
        val items = element.getElementsByTagName("item")
        return List(items.length) { index ->
            val item = items.item(index) as Element
            item.getAttribute("quantity") to item.textContent
        }
    }

    private fun textResources(): List<TextResource> {
        return textResources(document)
    }

    private fun textResources(document: org.w3c.dom.Document): List<TextResource> {
        val strings = document.getElementsByTagName("string")
        val stringResources = List(strings.length) { index ->
            val element = strings.item(index) as Element
            TextResource(element.getAttribute("name"), element.textContent)
        }
        val pluralResources = pluralElements(document).flatMap { plural ->
            val pluralName = plural.getAttribute("name")
            pluralItems(plural).map { (quantity, value) ->
                TextResource("$pluralName[$quantity]", value)
            }
        }
        return stringResources + pluralResources
    }

    private fun assertPlural(name: String) {
        val items = pluralItems(pluralElement(name))

        assertEquals(
            "Plural $name should define one and other exactly once",
            listOf("one", "other"),
            items.map { it.first }.sorted(),
        )
        items.forEach { (quantity, text) ->
            assertEquals(
                "Plural $name[$quantity] should format its count exactly once",
                listOf("%1\$d"),
                formatSpecifiersIn(text),
            )
        }
    }

    private fun assertContainsWords(name: String, vararg words: String) {
        val text = stringElement(name).textContent.lowercase()
        words.forEach { word ->
            assertTrue("$name must contain \"$word\": $text", text.contains(word))
        }
    }

    private fun assertRussianContains(name: String, vararg fragments: String) {
        val text = stringElement(russianDocument, name).textContent.lowercase()
        fragments.forEach { fragment ->
            assertTrue("$name must contain Russian fragment \"$fragment\": $text", text.contains(fragment))
        }
    }

    private fun stringElements(document: org.w3c.dom.Document): List<Element> {
        val nodes = document.getElementsByTagName("string")
        return List(nodes.length) { index -> nodes.item(index) as Element }
    }

    private fun formatSpecifiersIn(text: String): List<String> {
        return formatSpecifiers.findAll(text).map { match -> match.value }.toList().sorted()
    }

    private fun duplicateValues(values: List<String>): List<String> {
        return values.groupingBy { it }.eachCount()
            .filterValues { it > 1 }
            .keys
            .toList()
    }

    private data class TextResource(val name: String, val text: String)

    private companion object {
        private val rateStatusResourceNames = listOf(
            "status_compressing_rate",
            "status_encrypting_rate",
            "status_splitting_rate",
            "status_recombining_rate",
            "status_verifying_rate",
            "status_decrypting_rate",
            "status_repairing_rate",
            "status_unpacking_rate",
            "status_adding_deniability_rate",
            "status_removing_deniability_rate",
        )
        private val requiredRendererStrings = listOf(
            "fgs_working",
            "status_starting",
            "status_completed",
            "status_cancelled",
            "status_error",
            "status_compressing_files",
            "status_generating_values",
            "status_deriving_key",
            "status_reading_keyfiles",
            "status_calculating_values",
            "status_writing_values",
            "status_splitting",
            "status_recombining_chunks",
            "status_reading_values",
            "status_duplicate_keyfiles_warning",
            "status_verifying_integrity",
            "status_mac_verification_failed_continuing",
            "status_repairing_verifying",
            "status_integrity_verified_decrypting",
            "status_comparing_values",
            "status_unzipping",
            "status_adding_plausible_deniability",
            "status_removing_deniability_protection",
            "progress_percent",
        ) + rateStatusResourceNames
        private val requiredRendererPlurals = listOf("progress_item_count")
        private val requiredErrorBoundaryStrings = listOf(
            "error_auth_failed",
            "error_data_corrupted",
            "error_corrupt_header",
            "error_file_not_found",
            "error_operation_failed",
            "error_reason_permission_denied",
            "error_reason_file_not_found",
            "error_reason_insufficient_storage",
            "error_reason_io",
            "error_reason_unknown",
            "operation_cancelled",
            "error_read_folder_failed",
            "error_copy_files_failed",
            "keyfile_create_failed",
        )
        private val exactStringFormatContracts =
            rateStatusResourceNames.associateWith { listOf("%1\$.2f", "%2\$s") } + mapOf(
                "progress_percent" to listOf("%1\$.2f"),
                "error_read_folder_failed" to listOf("%1\$s"),
                "error_copy_files_failed" to listOf("%1\$s"),
                "keyfile_create_failed" to listOf("%1\$s"),
                "error_split_volume_not_supported" to listOf("%1\$s"),
                "error_insufficient_storage" to listOf("%1\$d", "%2\$d"),
            )
        private val exactPluralFormatContracts = mapOf(
            "progress_item_count" to listOf("%1\$d", "%2\$d"),
        )
        private val formatSpecifiers =
            Regex("""%(?!%)(?!n)(\d+\$)?[-#+ 0,(<]*\d*(?:\.\d+)?[a-zA-Z]""")
        private val disallowedAuthenticationWords =
            Regex("""\b(account|login|log in|sign in|signin|authorization|authorize|authorized)\b""")
        private val disallowedRussianAuthenticationWords =
            Regex("""\b(аккаунт|уч[её]тн\w*|логин|вход|авторизац\w*)\b""")
        private val rawFilenameExtension =
            Regex("""\.(pcv|zip|bin|incomplete)\b""", RegexOption.IGNORE_CASE)
    }
}
