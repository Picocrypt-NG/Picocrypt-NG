package io.github.picocrypt_ng.picocrypt_ng

import java.io.File
import java.util.Locale
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Document
import org.w3c.dom.Element

class LocalizationResourcesTest {
    private val stringsFile = File("src/main/res/values/strings.xml")
    private val document by lazy {
        DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(stringsFile)
    }
    private val translatedCatalogs by lazy {
        localeSpecs
            .filter { it.file.isFile }
            .map { spec -> Catalog(spec, parseDocument(spec.file)) }
    }
    private val catalogs by lazy {
        listOf(Catalog(baseLocaleSpec, document)) + translatedCatalogs
    }

    @Test
    fun `release locale filters catalogs and semantic checks stay in lockstep`() {
        val configuredLocales = System.getProperty(releaseLocaleFiltersProperty)
            ?.split(",")
            ?.filter(String::isNotBlank)
            .orEmpty()
        check(configuredLocales.isNotEmpty()) {
            "Missing $releaseLocaleFiltersProperty; run this test through Gradle"
        }
        val configuredCatalogDirectories = configuredLocales
            .map { locale ->
                if (locale == baseLocaleSpec.tag) {
                    baseLocaleSpec.resourceDirectory
                } else {
                    "values-$locale"
                }
            }
            .toSortedSet()
        val repositoryCatalogDirectories = stringsFile.parentFile
            ?.parentFile
            ?.listFiles()
            .orEmpty()
            .filter { directory ->
                directory.isDirectory &&
                    (directory.name == "values" || directory.name.startsWith("values-")) &&
                    File(directory, "strings.xml").isFile
            }
            .map(File::getName)
            .toSortedSet()
        val semanticallyCheckedDirectories = (listOf(baseLocaleSpec) + localeSpecs)
            .map(LocaleSpec::resourceDirectory)
            .toSortedSet()

        assertEquals(
            "Repo-owned strings.xml catalogs must exactly match androidResources.localeFilters",
            configuredCatalogDirectories,
            repositoryCatalogDirectories,
        )
        assertEquals(
            "Every release catalog must participate in localization semantic checks",
            configuredCatalogDirectories,
            semanticallyCheckedDirectories,
        )
    }

    @Test
    fun `app name stays non translatable`() {
        val appName = stringElement("app_name")

        assertEquals("false", appName.getAttribute("translatable"))
        assertEquals("Picocrypt-NG", appName.textContent)
    }

    @Test
    fun `every plural resource defines an other quantity`() {
        val missingOther = catalogs.flatMap { catalog ->
            pluralElements(catalog.document)
                .filter { element -> pluralItems(element).none { it.first == "other" } }
                .map { "${catalog.spec.tag}:${it.getAttribute("name")}" }
        }

        assertTrue("Plural resources missing quantity=\"other\": $missingOther", missingOther.isEmpty())
    }

    @Test
    fun `catalogs do not use file parenthetical shortcuts`() {
        val offenders = catalogs.flatMap { catalog ->
            textResources(catalog.document)
                .filter { it.text.contains("file(s)", ignoreCase = true) }
                .map { "${catalog.spec.displayName} ${it.name}: ${it.text}" }
        }

        assertTrue("Use real plural resources instead of file(s): $offenders", offenders.isEmpty())
    }

    @Test
    fun `formatted strings use positional placeholders`() {
        val offenders = catalogs.flatMap { catalog ->
            textResources(catalog.document).flatMap { resource ->
                formatSpecifiers.findAll(resource.text)
                    .filter { it.groups[1] == null }
                    .map { "${catalog.spec.displayName} ${resource.name}: ${resource.text}" }
            }
        }.distinct()

        assertTrue("Formatted resources must use positional placeholders: $offenders", offenders.isEmpty())
    }

    @Test
    fun `typed status and error formats stay exact in every catalog`() {
        catalogs.forEach { catalog ->
            exactStringFormatContracts.forEach { (name, expected) ->
                assertEquals(
                    "${catalog.spec.displayName} string $name placeholder contract",
                    expected,
                    formatSpecifiersIn(stringElement(catalog.document, name).textContent),
                )
            }

            exactPluralFormatContracts.forEach { (name, expected) ->
                pluralItems(pluralElement(catalog.document, name)).forEach { (quantity, text) ->
                    assertEquals(
                        "${catalog.spec.displayName} plural $name[$quantity] placeholder contract",
                        expected,
                        formatSpecifiersIn(text),
                    )
                }
            }
        }
    }

    @Test
    fun `translated catalogs mirror the exact ordered base resource schema`() {
        val expectedSchema = resourceSchema(document, excludeNonTranslatable = true)

        translatedCatalogs.forEach { catalog ->
            assertEquals(
                "${catalog.spec.displayName} ordered resource schema",
                expectedSchema,
                resourceSchema(catalog.document, excludeNonTranslatable = false),
            )
        }
    }

    @Test
    fun `catalog resource names are unique and visible values are not blank`() {
        catalogs.forEach { catalog ->
            val strings = stringElements(catalog.document)
            val plurals = pluralElements(catalog.document)
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

            assertTrue("${catalog.spec.displayName} duplicate strings: $duplicateStrings", duplicateStrings.isEmpty())
            assertTrue("${catalog.spec.displayName} duplicate plurals: $duplicatePlurals", duplicatePlurals.isEmpty())
            assertTrue(
                "${catalog.spec.displayName} names shared by string and plural resources: $crossTypeDuplicates",
                crossTypeDuplicates.isEmpty(),
            )
            assertTrue("${catalog.spec.displayName} blank string resources: $blankStrings", blankStrings.isEmpty())
            assertTrue("${catalog.spec.displayName} blank plural resources: $blankPlurals", blankPlurals.isEmpty())
            assertTrue(
                "${catalog.spec.displayName} blank or duplicate plural items: $invalidPluralItems",
                invalidPluralItems.isEmpty(),
            )
        }
    }

    @Test
    fun `renderer and localized error boundary resources exist in every catalog`() {
        catalogs.forEach { catalog ->
            val stringNames = stringElements(catalog.document)
                .map { it.getAttribute("name") }
                .toSet()
            val missingStrings = requiredRendererStrings
                .plus(requiredErrorBoundaryStrings)
                .filterNot(stringNames::contains)
            val pluralNames = pluralNames(catalog.document).toSet()
            val missingPlurals = requiredRendererPlurals.filterNot(pluralNames::contains)

            assertTrue("${catalog.spec.displayName} missing required strings: $missingStrings", missingStrings.isEmpty())
            assertTrue("${catalog.spec.displayName} missing required plurals: $missingPlurals", missingPlurals.isEmpty())
        }
    }

    @Test
    fun `catalog plurals use locale specific quantity categories`() {
        catalogs.forEach { catalog ->
            pluralNames(catalog.document).forEach { name ->
                val quantities = pluralItems(pluralElement(catalog.document, name)).map { it.first }

                assertEquals(
                    "${catalog.spec.displayName} plural $name quantities",
                    catalog.spec.quantities,
                    quantities,
                )
            }
        }
    }

    @Test
    fun `French progress item count agrees with the total quantity`() {
        val french = translatedCatalogs.single { it.spec.tag == "fr" }
        val forms = pluralItems(pluralElement(french.document, "progress_item_count")).toMap()
        val cases = listOf(
            Triple("other", 10L, "1 sur 10 éléments"),
            Triple("one", 1L, "1 sur 1 élément"),
        )

        cases.forEach { (quantity, total, expected) ->
            assertEquals(
                "French progress count for 1/$total",
                expected,
                String.format(Locale.FRENCH, forms.getValue(quantity), 1L, total),
            )
        }
    }

    @Test
    fun `every translated string and plural preserves its exact technical contract`() {
        val baseStrings = stringElements(document)
            .filterNot { it.getAttribute("translatable") == "false" }
            .associate { it.getAttribute("name") to resourceContract(it.textContent) }
        val stringMismatches = translatedCatalogs.flatMap { catalog ->
            stringElements(catalog.document)
                .filter { translated ->
                    resourceContract(translated.textContent) != baseStrings[translated.getAttribute("name")]
                }
                .map { translated ->
                    val name = translated.getAttribute("name")
                    "${catalog.spec.tag}:$name ${resourceContract(translated.textContent)} != ${baseStrings[name]}"
                }
            }

        val basePluralOther = pluralElements(document)
            .associate { plural ->
                val name = plural.getAttribute("name")
                val other = pluralItems(plural).first { it.first == "other" }.second
                name to resourceContract(other)
            }
        val pluralMismatches = translatedCatalogs.flatMap { catalog ->
            pluralElements(catalog.document).flatMap { plural ->
                val name = plural.getAttribute("name")
                val expected = basePluralOther[name]
                pluralItems(plural)
                    .filter { (_, text) -> resourceContract(text) != expected }
                    .map { (quantity, text) ->
                        "${catalog.spec.tag}:$name[$quantity] ${resourceContract(text)} != $expected"
                    }
            }
        }

        val basePluralMismatches = pluralElements(document).flatMap { plural ->
            val name = plural.getAttribute("name")
            val expected = basePluralOther.getValue(name)
            pluralItems(plural)
                .filter { (_, text) -> resourceContract(text) != expected }
                .map { (quantity, text) ->
                    "base:$name[$quantity] ${resourceContract(text)} != $expected"
                }
        }
        val contractMismatches = stringMismatches + basePluralMismatches + pluralMismatches

        assertTrue(
            "Resources must preserve placeholders, literal percent signs and digits, extensions, " +
                "and invariant technical tokens: $contractMismatches",
            contractMismatches.isEmpty(),
        )
    }

    @Test
    fun `translated high risk wording keeps security meaning`() {
        translatedCatalogs.forEach { catalog ->
            securityRequiredTerms.getValue(catalog.spec.tag).forEach { (name, terms) ->
                assertCatalogContains(catalog, name, *terms.toTypedArray())
            }

            val deniabilityCopy = deniabilityResourceNames
                .joinToString(separator = "\n") { name ->
                    stringElement(catalog.document, name).textContent.lowercase()
                }
            securityForbiddenDeniabilityTerms.getValue(catalog.spec.tag).forEach { term ->
                assertFalse(
                    "${catalog.spec.displayName} deniability copy must not contain forbidden claim '$term'",
                    deniabilityCopy.contains(term.lowercase()),
                )
            }

            val forceDecryptCopy = stringElement(catalog.document, "force_decrypt_warning")
                .textContent
                .lowercase()
            securityForbiddenForceTerms.getValue(catalog.spec.tag).forEach { term ->
                assertFalse(
                    "${catalog.spec.displayName} force-decrypt copy must not contain forbidden claim '$term'",
                    forceDecryptCopy.contains(term.lowercase()),
                )
            }

            val allCopy = textResources(catalog.document).joinToString(separator = "\n") { it.text }
            catalogForbiddenTerms[catalog.spec.tag].orEmpty().forEach { term ->
                assertFalse(
                    "${catalog.spec.displayName} catalog must not mix terminology '$term'",
                    allCopy.contains(term),
                )
            }
        }

        val russian = translatedCatalogs.firstOrNull { it.spec.tag == "ru" } ?: return
        val authenticationCopy = textResources(russian.document)
            .joinToString(separator = "\n") { it.text.lowercase() }
        assertFalse(
            "Russian authentication copy must not imply accounts, logins, or authorization",
            disallowedRussianAuthenticationWords.containsMatchIn(authenticationCopy),
        )
    }

    @Test
    fun `technical filename extensions stay format arguments`() {
        assertContainsWords("error_split_volume_not_supported", "not supported", "recombine")
        translatedCatalogs.forEach { catalog ->
            assertCatalogContains(
                catalog,
                "error_split_volume_not_supported",
                *splitVolumeRequiredTerms.getValue(catalog.spec.tag).toTypedArray(),
            )
        }

        val rawExtensionMentions = catalogs.flatMap { catalog ->
            textResources(catalog.document)
                .filter { it.name != "app_name" }
                .filter { resource -> rawFilenameExtension.containsMatchIn(resource.text) }
                .map { "${catalog.spec.displayName} ${it.name}: ${it.text}" }
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
        assertContainsWords("deniability_password_required", "deniability", "non-empty password")
        assertContainsWords(
            "error_keyfile_writes_disabled",
            "new v2 volumes",
            "keyfiles",
            "disabled",
            "reviewed v3 format",
            "existing",
            "decrypted",
        )
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
    fun `status resources keep invariant units and phase digits in every catalog`() {
        catalogs.forEach { catalog ->
            rateStatusResourceNames.forEach { name ->
                val text = stringElement(catalog.document, name).textContent
                assertTrue("${catalog.spec.displayName} $name must preserve MiB: $text", text.contains("MiB"))
                assertTrue("${catalog.spec.displayName} $name must preserve ETA: $text", text.contains("ETA"))
            }

            val verificationDigits = Regex("""\d+""")
                .findAll(stringElement(catalog.document, "status_verifying_integrity").textContent)
                .map { it.value }
                .toList()
                .sorted()
            assertEquals(
                "${catalog.spec.displayName} verify-first status must preserve both phase digits",
                listOf("1", "2"),
                verificationDigits,
            )
        }
    }

    @Test
    fun `high risk translations are not untranslated English`() {
        val baseHighRiskValues = highRiskResourceNames.associateWith { name ->
            normalizedValue(stringElement(name).textContent)
        }
        val untranslated = translatedCatalogs.flatMap { catalog ->
            highRiskResourceNames
                .filterNot(intentionallyInvariantHighRiskResources::contains)
                .filter { name ->
                    normalizedValue(stringElement(catalog.document, name).textContent) ==
                        baseHighRiskValues.getValue(name)
                }
                .map { name -> "${catalog.spec.tag}:$name" }
        }

        assertTrue(
            "P0/P1 resources must not silently fall back to English: $untranslated",
            untranslated.isEmpty(),
        )
    }

    @Test
    fun `independent model review corrections preserve their semantic reasons`() {
        translatedCatalogs.forEach { catalog ->
            modelReviewCorrectionGuards[catalog.spec.tag].orEmpty().forEach { (name, guard) ->
                val text = stringElement(catalog.document, name).textContent
                guard.requiredFragments.forEach { fragment ->
                    assertTrue(
                        "${catalog.spec.displayName} $name must retain reviewed meaning '$fragment': $text",
                        text.contains(fragment, ignoreCase = true),
                    )
                }
                guard.forbiddenFragments.forEach { fragment ->
                    assertFalse(
                        "${catalog.spec.displayName} $name must reject reviewed defect '$fragment': $text",
                        text.contains(fragment, ignoreCase = true),
                    )
                }
            }
        }
    }

    @Test
    fun `authentication wording guards reject account login and authorization terms`() {
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
        val blockedRussianTerms = listOf(
            "аккаунт",
            "учётная запись",
            "логин",
            "вход",
            "авторизация",
        )
        val missedRussianTerms = blockedRussianTerms.filterNot { term ->
            disallowedRussianAuthenticationWords.containsMatchIn("Ошибка $term тома")
        }

        assertTrue("Authentication wording guard missed: $missedTerms", missedTerms.isEmpty())
        assertTrue(
            "Russian authentication wording guard missed: $missedRussianTerms",
            missedRussianTerms.isEmpty(),
        )
    }

    private fun stringElement(name: String): Element {
        return stringElement(document, name)
    }

    private fun parseDocument(file: File): Document {
        return DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(file)
    }

    private fun stringElement(document: Document, name: String): Element {
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

    private fun pluralElement(document: Document, name: String): Element {
        return pluralElements(document).firstOrNull { it.getAttribute("name") == name }
            ?: throw AssertionError("Missing plurals resource: $name")
    }

    private fun pluralElements(document: Document = this.document): List<Element> {
        val nodes = document.getElementsByTagName("plurals")
        return List(nodes.length) { index -> nodes.item(index) as Element }
    }

    private fun pluralNames(document: Document): List<String> {
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

    private fun textResources(document: Document): List<TextResource> {
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

    private fun assertCatalogContains(catalog: Catalog, name: String, vararg fragments: String) {
        val text = stringElement(catalog.document, name).textContent.lowercase()
        fragments.forEach { fragment ->
            assertTrue(
                "${catalog.spec.displayName} $name must contain \"$fragment\": $text",
                text.contains(fragment.lowercase()),
            )
        }
    }

    private fun stringElements(document: Document): List<Element> {
        val nodes = document.getElementsByTagName("string")
        return List(nodes.length) { index -> nodes.item(index) as Element }
    }

    private fun resourceSchema(
        document: Document,
        excludeNonTranslatable: Boolean,
    ): List<ResourceName> {
        val schema = mutableListOf<ResourceName>()
        val children = document.documentElement.childNodes
        for (index in 0 until children.length) {
            val element = children.item(index) as? Element ?: continue
            if (element.tagName != "string" && element.tagName != "plurals") continue
            if (excludeNonTranslatable && element.getAttribute("translatable") == "false") continue
            schema += ResourceName(element.tagName, element.getAttribute("name"))
        }
        return schema
    }

    private fun formatSpecifiersIn(text: String): List<String> {
        return formatSpecifiers.findAll(text).map { match -> match.value }.toList().sorted()
    }

    private fun normalizedValue(text: String): String {
        return text.trim().lowercase().replace(Regex("""\s+"""), " ")
    }

    private fun resourceContract(text: String): ResourceContract {
        val withoutPlaceholders = formatSpecifiers.replace(text, "").replace("%%", "")
        return ResourceContract(
            placeholders = formatSpecifiersIn(text),
            literalPercentCount = literalPercent.findAll(text).count(),
            literalDigits = literalDigits.findAll(withoutPlaceholders).map { it.value }.toList().sorted(),
            extensions = technicalExtension.findAll(withoutPlaceholders).map { it.value }.toList().sorted(),
            invariantCounts = invariantTechnicalTokens.associateWith { token -> text.windowed(token.length).count { it == token } },
        )
    }

    private fun duplicateValues(values: List<String>): List<String> {
        return values.groupingBy { it }.eachCount()
            .filterValues { it > 1 }
            .keys
            .toList()
    }

    private data class Catalog(val spec: LocaleSpec, val document: Document)

    private data class LocaleSpec(
        val tag: String,
        val displayName: String,
        val resourceDirectory: String,
        val quantities: List<String>,
    ) {
        val file = File("src/main/res/$resourceDirectory/strings.xml")
    }

    private data class ResourceName(val type: String, val name: String)

    private data class ResourceContract(
        val placeholders: List<String>,
        val literalPercentCount: Int,
        val literalDigits: List<String>,
        val extensions: List<String>,
        val invariantCounts: Map<String, Int>,
    )

    private data class ReviewCorrectionGuard(
        val requiredFragments: List<String>,
        val forbiddenFragments: List<String>,
    )

    private data class TextResource(val name: String, val text: String)

    private companion object {
        private const val releaseLocaleFiltersProperty = "picocrypt.releaseLocaleFilters"
        private val baseLocaleSpec = LocaleSpec(
            tag = "en",
            displayName = "English",
            resourceDirectory = "values",
            quantities = listOf("one", "other"),
        )
        private val localeSpecs = listOf(
            LocaleSpec("ru", "Russian", "values-ru", listOf("one", "few", "many", "other")),
            LocaleSpec("de", "German", "values-de", listOf("one", "other")),
            LocaleSpec("fr", "French", "values-fr", listOf("one", "many", "other")),
            LocaleSpec("es", "Spanish", "values-es", listOf("one", "many", "other")),
            LocaleSpec("zh-Hans", "Simplified Chinese", "values-b+zh+Hans", listOf("other")),
            LocaleSpec("hi", "Hindi", "values-hi", listOf("one", "other")),
            LocaleSpec("ko", "Korean", "values-ko", listOf("other")),
        )
        private val securityRequiredTerms = mapOf(
            "ru" to mapOf(
                "comments_plaintext_warning" to listOf("открыт", "метадан", "секрет"),
                "force_decrypt_warning" to listOf("целостност", "принуд", "непровер", "повреж"),
                "error_auth_failed" to listOf("аутентиф", "парол", "ключев", "поряд"),
                "error_data_corrupted" to listOf("целостност", "не провер", "повреж"),
                "error_corrupt_header" to listOf("заголов", "повреж"),
                "error_decrypt_retry_only" to listOf("только", "расшифр", "принуд"),
                "deniability_note" to listOf("правдоподоб", "метадан", "до расшифров", "неизвест"),
                "deniability_password_required" to listOf("правдоподоб", "непуст", "парол"),
                "error_keyfile_writes_disabled" to listOf("нов", "v2", "ключев", "отключ", "v3", "существ", "расшифр"),
                "prevent_screenshots_description" to listOf("сним", "запис", "недавн"),
            ),
            "de" to mapOf(
                "comments_plaintext_warning" to listOf("Klartext-Metadaten", "Geheimnisse"),
                "force_decrypt_warning" to listOf("Integritätsprüfung", "erzwungener Entschlüsselung", "nicht verifizierte Ausgabe", "beschädigt"),
                "error_auth_failed" to listOf("Authentifizierung", "Passwort", "Schlüsseldateien", "Reihenfolge"),
                "error_data_corrupted" to listOf("Integritätsprüfung", "nicht verifiziert", "beschädigt"),
                "error_corrupt_header" to listOf("Header", "beschädigt"),
                "error_decrypt_retry_only" to listOf("Nur", "Entschlüsselung", "erzwungener"),
                "deniability_note" to listOf("Abstreitbarkeitsmodus", "Header-Metadaten", "vor der Entschlüsselung", "unbekannt"),
                "deniability_password_required" to listOf("Abstreitbarkeit", "nicht leeres Passwort"),
                "error_keyfile_writes_disabled" to listOf("Neue", "v2", "Schlüsseldateien", "deaktiviert", "v3", "Vorhandene", "entschlüsselt"),
                "prevent_screenshots_description" to listOf("Screenshots", "Bildschirmaufnahmen", "zuletzt verwendeten Apps"),
            ),
            "fr" to mapOf(
                "comments_plaintext_warning" to listOf("métadonnées en clair", "secret"),
                "force_decrypt_warning" to listOf("contrôle d’intégrité", "déchiffrement forcé", "sortie non vérifiée", "corrompue"),
                "error_auth_failed" to listOf("authentification", "mot de passe", "fichiers-clés", "ordre"),
                "error_data_corrupted" to listOf("contrôle d’intégrité", "pas vérifiée", "corrompue"),
                "error_corrupt_header" to listOf("en-tête", "endommagé"),
                "error_decrypt_retry_only" to listOf("Seules", "déchiffrement", "forcé"),
                "deniability_note" to listOf("déni plausible", "métadonnées de l’en-tête", "avant le déchiffrement", "inconnus"),
                "deniability_password_required" to listOf("déni plausible", "mot de passe non vide"),
                "error_keyfile_writes_disabled" to listOf("nouveaux volumes v2", "fichiers-clés", "désactivée", "format v3", "existants", "déchiffrables"),
                "prevent_screenshots_description" to listOf("captures", "enregistrements", "applications récentes"),
            ),
            "es" to mapOf(
                "comments_plaintext_warning" to listOf("metadatos en texto claro", "secretos"),
                "force_decrypt_warning" to listOf("verificación de integridad", "descifrado forzado", "salida no verificada", "dañada"),
                "error_auth_failed" to listOf("autenticación", "contraseña", "archivos de clave", "orden"),
                "error_data_corrupted" to listOf("verificación de integridad", "no está verificada", "dañada"),
                "error_corrupt_header" to listOf("encabezado", "dañado"),
                "error_decrypt_retry_only" to listOf("Solo", "descifrado", "forzado"),
                "deniability_note" to listOf("negación plausible", "metadatos del encabezado", "antes del descifrado", "desconocen"),
                "deniability_password_required" to listOf("negación plausible", "contraseña no vacía"),
                "error_keyfile_writes_disabled" to listOf("nuevos volúmenes v2", "archivos de clave", "deshabilitada", "formato v3", "existentes", "descifrar"),
                "prevent_screenshots_description" to listOf("capturas", "grabación", "aplicaciones recientes"),
            ),
            "zh-Hans" to mapOf(
                "comments_plaintext_warning" to listOf("明文元数据", "秘密"),
                "force_decrypt_warning" to listOf("完整性检查", "强制解密", "未经验证", "损坏"),
                "error_auth_failed" to listOf("身份验证", "密码", "密钥文件", "顺序"),
                "error_data_corrupted" to listOf("完整性检查", "未经验证", "损坏"),
                "error_corrupt_header" to listOf("标头", "损坏"),
                "error_decrypt_retry_only" to listOf("只有", "解密", "强制"),
                "deniability_note" to listOf("可否认性", "标头元数据", "解密前", "未知"),
                "deniability_password_required" to listOf("可否认性", "非空密码"),
                "error_keyfile_writes_disabled" to listOf("新", "v2", "密钥文件", "禁用", "v3", "现有", "解密"),
                "prevent_screenshots_description" to listOf("截屏", "屏幕录制", "最近使用的应用"),
            ),
            "hi" to mapOf(
                "comments_plaintext_warning" to listOf("सादा-पाठ मेटाडेटा", "गुप्त"),
                "force_decrypt_warning" to listOf("अखंडता जाँच", "बलपूर्वक डिक्रिप्ट", "असत्यापित आउटपुट", "क्षतिग्रस्त"),
                "error_auth_failed" to listOf("प्रमाणीकरण", "पासवर्ड", "कुंजी फ़ाइलें", "क्रम"),
                "error_data_corrupted" to listOf("अखंडता जाँच", "असत्यापित", "क्षतिग्रस्त"),
                "error_corrupt_header" to listOf("हेडर", "क्षतिग्रस्त"),
                "error_decrypt_retry_only" to listOf("केवल", "डिक्रिप्शन", "बलपूर्वक"),
                "deniability_note" to listOf("विश्वसनीय इनकार", "हेडर मेटाडेटा", "डिक्रिप्ट करने से पहले", "अज्ञात"),
                "deniability_password_required" to listOf("विश्वसनीय इनकार", "खाली न होने वाला पासवर्ड"),
                "error_keyfile_writes_disabled" to listOf("नए", "v2", "कुंजी फ़ाइल", "बंद", "v3", "मौजूदा", "डिक्रिप्ट"),
                "prevent_screenshots_description" to listOf("स्क्रीनशॉट", "स्क्रीन रिकॉर्डिंग", "हाल के ऐप्स"),
            ),
            "ko" to mapOf(
                "comments_plaintext_warning" to listOf("평문 메타데이터", "비밀"),
                "force_decrypt_warning" to listOf("무결성 검사", "강제 복호화", "검증되지 않은 출력", "손상"),
                "error_auth_failed" to listOf("인증", "비밀번호", "키 파일", "순서"),
                "error_data_corrupted" to listOf("무결성 검사", "검증되지", "손상"),
                "error_corrupt_header" to listOf("헤더", "손상"),
                "error_decrypt_retry_only" to listOf("복호화", "강제 복호화"),
                "deniability_note" to listOf("부인 가능", "헤더 메타데이터", "복호화 전", "알 수"),
                "deniability_password_required" to listOf("부인 가능", "빈 비밀번호", "사용할 수 없습니다"),
                "error_keyfile_writes_disabled" to listOf("새", "v2", "키 파일", "만들 수 없습니다", "v3", "기존", "복호화"),
                "prevent_screenshots_description" to listOf("스크린샷", "화면 녹화", "최근 앱"),
            ),
        )
        private val deniabilityResourceNames = listOf(
            "comments_not_readable",
            "comments_disabled_deniability",
            "deniability",
            "deniability_status",
            "deniability_note",
            "deniability_password_required",
            "status_adding_plausible_deniability",
            "status_removing_deniability_protection",
            "status_adding_deniability_rate",
            "status_removing_deniability_rate",
        )
        private val securityForbiddenDeniabilityTerms = mapOf(
            "ru" to listOf("аноним", "невидим", "скрытый режим"),
            "de" to listOf("anonym", "unsichtbar", "unentdeck", "versteckt", "verborgen"),
            "fr" to listOf("anonym", "invisible", "indétect", "caché"),
            "es" to listOf("anón", "invisible", "indetect", "ocult"),
            "zh-Hans" to listOf("匿名", "隐身", "不可检测", "隐藏模式"),
            "hi" to listOf("गुमनाम", "अदृश्य"),
            "ko" to listOf("익명", "보이지 않", "탐지할 수 없", "숨김 모드", "부인 방지"),
        )
        private val securityForbiddenForceTerms = mapOf(
            "ru" to listOf("безопас", "исправлен", "восстановлен"),
            "de" to listOf("sicher", "repariert", "wiederhergestellt"),
            "fr" to listOf("sûre", "réparée", "récupérée"),
            "es" to listOf("segura", "reparada", "recuperada"),
            "zh-Hans" to listOf("安全", "修复", "恢复"),
            "hi" to listOf("सुरक्षित", "मरम्मत", "रिकवर"),
            "ko" to listOf("안전", "수리", "복구"),
        )
        private val catalogForbiddenTerms = mapOf(
            "zh-Hans" to listOf("密碼", "金鑰", "資料夾", "標頭", "覆蓋", "輸出", "檔案", "設定", "錯誤", "驗證"),
            "hi" to listOf("फाइल", "फोल्डर", "कूटबद्ध", "विकूट", "कूटलेखन"),
        )
        private val splitVolumeRequiredTerms = mapOf(
            "ru" to listOf("Android", "не поддерж", "объедин"),
            "de" to listOf("Android", "nicht unterstützt", "zusammen"),
            "fr" to listOf("Android", "pas pris en charge", "recombin"),
            "es" to listOf("Android", "no se admiten", "Recombine", "equipo"),
            "zh-Hans" to listOf("Android", "不支持", "合并"),
            "hi" to listOf("Android", "समर्थित नहीं", "फिर से जोड़ें"),
            "ko" to listOf("Android", "지원하지", "다시 결합"),
        )
        private val modelReviewCorrectionGuards = mapOf(
            "de" to mapOf(
                "status_starting" to ReviewCorrectionGuard(
                    requiredFragments = listOf("gestartet"),
                    forbiddenFragments = listOf("Start…"),
                ),
            ),
            "es" to mapOf(
                "comments_plaintext_warning" to ReviewCorrectionGuard(
                    requiredFragments = listOf("texto claro"),
                    forbiddenFragments = listOf("texto plano"),
                ),
                "error_split_volume_not_supported" to ReviewCorrectionGuard(
                    requiredFragments = listOf("no se admiten", "equipo"),
                    forbiddenFragments = listOf("no son compatibles", "ordenador"),
                ),
            ),
            "zh-Hans" to mapOf(
                "require_this_order" to ReviewCorrectionGuard(
                    requiredFragments = listOf("顺序", "使用"),
                    forbiddenFragments = emptyList(),
                ),
            ),
            "hi" to mapOf(
                "status_verifying_integrity" to ReviewCorrectionGuard(
                    requiredFragments = listOf("2 में से", "चरण 1"),
                    forbiddenFragments = listOf("चरण 1 में से 2"),
                ),
                "status_removing_deniability_protection" to ReviewCorrectionGuard(
                    requiredFragments = listOf("इनकार की सुरक्षा"),
                    forbiddenFragments = listOf("इनकार सुरक्षा"),
                ),
            ),
            "ko" to mapOf(
                "status_adding_plausible_deniability" to ReviewCorrectionGuard(
                    requiredFragments = listOf("그럴듯한 부인 가능성"),
                    forbiddenFragments = listOf("합리적 부인 가능성"),
                ),
                "privacy_security" to ReviewCorrectionGuard(
                    requiredFragments = listOf("개인정보 보호 및 보안"),
                    forbiddenFragments = listOf("&"),
                ),
            ),
        )
        private val highRiskResourceNames = setOf(
            "authentication_error",
            "error_auth_failed",
            "data_corruption_detected",
            "error_data_corrupted",
            "error_corrupt_header",
            "force_decrypt",
            "force_decrypt_warning",
            "verify_first",
            "status_verifying_integrity",
            "status_mac_verification_failed_continuing",
            "status_integrity_verified_decrypting",
            "comments_plaintext_warning",
            "deniability_note",
            "discard_output",
            "error_delete_failed",
            "error_insufficient_storage",
            "error_reason_insufficient_storage",
            "cancel",
            "operation_cancelled",
            "operation_cancelled_message",
            "status_cancelled",
            "retry",
            "error_decrypt_retry_only",
            "error_operation_data_unavailable",
            "keyfiles_required_warning",
            "keyfile_order_matters",
            "require_this_order",
            "deniability_password_required",
            "error_keyfile_writes_disabled",
        )
        private val intentionallyInvariantHighRiskResources = emptySet<String>()
        private val invariantTechnicalTokens = listOf("MiB", "ETA", "MAC", "Android", "Reed-Solomon", "ZIP")
        private val literalPercent = Regex("""%%""")
        private val literalDigits = Regex("""\d+""")
        private val technicalExtension = Regex("""(?<![\w.])\.[A-Za-z0-9][A-Za-z0-9_-]*""")
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
        )
        private val exactStringFormatContracts =
            rateStatusResourceNames.associateWith { listOf("%1\$.2f", "%2\$s") } + mapOf(
                "progress_percent" to listOf("%1\$.2f"),
                "error_read_folder_failed" to listOf("%1\$s"),
                "error_copy_files_failed" to listOf("%1\$s"),
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
            Regex("""(?iuU)\b(аккаунт|уч[её]тн\p{L}*|логин|вход|авторизац\p{L}*)\b""")
        private val rawFilenameExtension =
            Regex("""\.(pcv|zip|bin|incomplete)\b""", RegexOption.IGNORE_CASE)
    }
}
