package io.github.picocrypt_ng.picocrypt_ng

import java.io.File
import java.util.Properties
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class LocaleConfigurationPolicyTest {
    private val buildFile = File("build.gradle.kts")
    private val resourcesProperties = File("src/main/res/resources.properties")
    private val sourceManifest = File("src/main/AndroidManifest.xml")
    private val buildRoot = File("build")

    @Test
    fun `source declares generated and filtered locale policy`() {
        val buildText = buildFile.readText()
        val androidBlock = blockNamed(buildText, "android")
        val androidResourcesBlock = androidBlock?.let { blockNamed(it, "androidResources") }
        val buildTypesBlock = androidBlock?.let { blockNamed(it, "buildTypes") }
        val debugBlock = buildTypesBlock?.let { blockNamed(it, "debug") }
        val debugUnitTestBlock = blockAfter(
            buildText,
            Regex(
                """tasks\.matching\s*\{\s*it\.name\s*==\s*"testDebugUnitTest"\s*}""" +
                    """\.configureEach\s*\{""",
            ),
        )
        val issues = mutableListOf<String>()

        if (androidResourcesBlock?.contains(Regex("""\bgenerateLocaleConfig\s*=\s*true\b""")) != true) {
            issues += "androidResources.generateLocaleConfig must be true"
        }

        if (!resourcesProperties.isFile) {
            issues += "missing " + resourcesProperties.path
        } else {
            val properties = Properties().apply {
                resourcesProperties.inputStream().use(::load)
            }
            if (properties.size != 1 || properties.getProperty("unqualifiedResLocale") != "en") {
                issues += "resources.properties must contain only unqualifiedResLocale=en"
            }
        }

        val configurationMatches = androidResourcesBlock
            ?.let { localeFilters.findAll(it).toList() }
            .orEmpty()
        val configuredLocales = configurationMatches.singleOrNull()
            ?.groupValues
            ?.get(1)
            ?.let { body -> quotedValue.findAll(body).map { it.groupValues[1] }.toList() }
        if (configuredLocales != expectedResourceConfigurations) {
            issues += "androidResources.localeFilters=" + configuredLocales +
                "; want " + expectedResourceConfigurations
        }
        val legacyFilters = androidBlock
            ?.let { legacyResourceConfigurations.findAll(it).map { match -> match.value }.toList() }
            .orEmpty()
        if (legacyFilters.isNotEmpty()) {
            issues += "legacy locale filters are forbidden: " + legacyFilters
        }
        if (debugBlock?.contains(Regex("""\bisPseudoLocalesEnabled\s*=\s*true\b""")) != true) {
            issues += "debug pseudolocales must remain enabled"
        }
        if (debugUnitTestBlock?.contains(Regex("""dependsOn\("processReleaseResources"\)""")) != true) {
            issues += "testDebugUnitTest must depend on processReleaseResources"
        }

        assertTrue("Locale configuration policy violations: " + issues, issues.isEmpty())
    }

    @Test
    fun `source contains no manual locale configuration`() {
        val sourceResourceXml = File("src")
            .walkTopDown()
            .filter(File::isFile)
            .filter { it.extension == "xml" && it.invariantSeparatorsPath.contains("/res/xml") }
            .toList()
        val namedManualConfigs = sourceResourceXml.filter { it.name == "locale_config.xml" }
        val rootedManualConfigs = sourceResourceXml.filter { file ->
            runCatching {
                DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
                    .documentElement
                    .tagName == "locale-config"
            }.getOrDefault(false)
        }
        val sourceManifestHasReference = sourceManifest.readText().contains("android:localeConfig")

        assertTrue(
            "Manual locale configuration files are forbidden: " +
                (namedManualConfigs + rootedManualConfigs).distinct().map(File::getPath),
            namedManualConfigs.isEmpty() && rootedManualConfigs.isEmpty(),
        )
        assertFalse(
            "The source manifest must let AGP inject android:localeConfig",
            sourceManifestHasReference,
        )
    }

    @Test
    fun `processed release has one generated locale configuration and manifest reference`() {
        val generatedConfigs = generatedReleaseLocaleConfigs()
        val logicalNames = generatedConfigs.map { it.nameWithoutExtension }.distinct()
        val unqualifiedConfigs = generatedConfigs.filter { it.parentFile?.name == "xml" }
        val issues = mutableListOf<String>()

        if (generatedConfigs.isEmpty()) {
            issues += "missing generated release LocaleConfig below " + buildRoot.path
        }
        if (logicalNames.size != 1) {
            issues += "generated LocaleConfig logical resource names=" + logicalNames
        }
        if (unqualifiedConfigs.size != 1) {
            issues += "unqualified generated LocaleConfig files=" + unqualifiedConfigs.map(File::getPath)
        }
        if (unqualifiedConfigs.size == 1) {
            val defaultLocale = defaultLocaleIn(unqualifiedConfigs.single())
            if (defaultLocale != "en") {
                issues += unqualifiedConfigs.single().path +
                    " android:defaultLocale=" + defaultLocale + "; want en"
            }
        }
        val unexpectedQualifiers = generatedConfigs
            .map { it.parentFile?.name.orEmpty() }
            .filterNot { it == "xml" || versionedXmlDirectory.matches(it) }
        if (unexpectedQualifiers.isNotEmpty()) {
            issues += "unexpected generated LocaleConfig qualifiers=" + unexpectedQualifiers
        }

        generatedConfigs.forEach { config ->
            val locales = localesIn(config)
            if (locales.size != expectedGeneratedLocales.size || locales.toSet() != expectedGeneratedLocales) {
                issues += config.path + " locales=" + locales + "; want " + expectedGeneratedLocales
            }
            if (locales.size != locales.distinct().size) {
                issues += config.path + " contains duplicate locales"
            }
            if (locales.contains("en-XA") || locales.contains("ar-XB")) {
                issues += config.path + " contains debug-only pseudolocales"
            }
        }

        val releaseManifests = finalMergedReleaseManifests()
        if (releaseManifests.isEmpty()) {
            issues += "no final merged release manifests found below " + buildRoot.path
        }
        val expectedReference = logicalNames.singleOrNull()?.let { "@xml/" + it }
        releaseManifests.forEach { manifest ->
            val references = localeConfigReference
                .findAll(manifest.readText())
                .map { it.groupValues[1] }
                .toList()
            if (references.size != 1) {
                issues += manifest.path + " localeConfig references=" + references +
                    "; want exactly one"
            } else if (expectedReference != null && references.single() != expectedReference) {
                issues += manifest.path + " localeConfig=" + references.single() +
                    "; want " + expectedReference
            }
        }

        assertTrue("Generated release LocaleConfig policy violations: " + issues, issues.isEmpty())
    }

    private fun blockNamed(source: String, name: String): String? {
        return blockAfter(source, Regex("""\b""" + Regex.escape(name) + """\s*\{"""))
    }

    private fun blockAfter(source: String, prefix: Regex): String? {
        val match = prefix.find(source) ?: return null
        val openBrace = source.lastIndexOf('{', match.range.last)
        var depth = 0
        for (index in openBrace until source.length) {
            when (source[index]) {
                '{' -> depth += 1
                '}' -> {
                    depth -= 1
                    if (depth == 0) return source.substring(openBrace + 1, index)
                }
            }
        }
        return null
    }

    private fun generatedReleaseLocaleConfigs(): List<File> {
        if (!buildRoot.isDirectory) return emptyList()
        return buildRoot
            .walkTopDown()
            .filter(File::isFile)
            .filter { it.extension == "xml" }
            .filter { file -> file.invariantSeparatorsPath.split("/").contains("release") }
            .filter { file ->
                file.invariantSeparatorsPath
                    .split("/")
                    .dropLast(1)
                    .any { directory ->
                        directory.lowercase().replace("_", "").replace("-", "")
                            .contains("localeconfig")
                    }
            }
            .filter { file ->
                runCatching { file.readText().contains("<locale-config") }.getOrDefault(false)
            }
            .toList()
    }

    private fun finalMergedReleaseManifests(): List<File> {
        val finalManifestRoot = File(
            buildRoot,
            "intermediates/merged_manifests/release/processReleaseManifest",
        )
        if (!finalManifestRoot.isDirectory) return emptyList()
        return finalManifestRoot
            .walkTopDown()
            .filter(File::isFile)
            .filter { it.name == "AndroidManifest.xml" }
            .toList()
    }

    private fun defaultLocaleIn(config: File): String {
        val document = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
            .newDocumentBuilder()
            .parse(config)
        if (document.documentElement.tagName != "locale-config") return ""
        return document.documentElement.getAttributeNS(androidNamespace, "defaultLocale")
    }

    private fun localesIn(config: File): List<String> {
        val document = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
            .newDocumentBuilder()
            .parse(config)
        if (document.documentElement.tagName != "locale-config") return emptyList()
        val localeNodes = document.getElementsByTagName("locale")
        return List(localeNodes.length) { index ->
            val locale = localeNodes.item(index) as Element
            locale.getAttributeNS(androidNamespace, "name").ifBlank {
                locale.getAttribute("android:name")
            }
        }
    }

    private companion object {
        private const val androidNamespace = "http://schemas.android.com/apk/res/android"
        private val expectedResourceConfigurations = listOf(
            "en",
            "ru",
            "de",
            "fr",
            "es",
            "b+zh+Hans",
            "hi",
            "ko",
        )
        private val expectedGeneratedLocales = setOf("en", "ru", "de", "fr", "es", "zh-Hans", "hi", "ko")
        private val localeFilters = Regex(
            """\blocaleFilters\s*\+=\s*listOf\((.*?)\)""",
            RegexOption.DOT_MATCHES_ALL,
        )
        private val legacyResourceConfigurations = Regex(
            """\b(?:resourceConfigurations|resConfigs?)\b""",
        )
        private val quotedValue = Regex(""""([^"]+)"""")
        private val versionedXmlDirectory = Regex("""xml-v\d+""")
        private val localeConfigReference = Regex("""android:localeConfig\s*=\s*"([^"]+)"""")
    }
}
