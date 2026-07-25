import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import com.android.build.api.variant.FilterConfiguration.FilterType.ABI

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.parcelize)
}

val releaseSigningRequested = gradle.startParameter.taskNames.any { task ->
    val lower = task.lowercase()
    lower.contains("assemblerelease") ||
        lower.contains("bundlerelease") ||
        lower.contains("packagerelease")
}

// ABI splits only for release builds: keeps debug a single app-debug.apk (fast iteration
// and the PR test build), while release ships per-ABI APKs for F-Droid/IzzyOnDroid.
val abiSplitsEnabled = releaseSigningRequested

val releaseSigningProps = mapOf(
    "PICOCRYPT_KEYSTORE_PATH" to providers.gradleProperty("PICOCRYPT_KEYSTORE_PATH").orNull,
    "PICOCRYPT_KEYSTORE_PASSWORD" to providers.gradleProperty("PICOCRYPT_KEYSTORE_PASSWORD").orNull,
    "PICOCRYPT_KEY_ALIAS" to providers.gradleProperty("PICOCRYPT_KEY_ALIAS").orNull,
    "PICOCRYPT_KEY_PASSWORD" to providers.gradleProperty("PICOCRYPT_KEY_PASSWORD").orNull,
)

val releaseSigningConfigured = releaseSigningProps.values.none { it.isNullOrBlank() }
val releaseSigningRequired = providers
    .gradleProperty("PICOCRYPT_REQUIRE_RELEASE_SIGNING")
    .map(String::toBoolean)
    .orElse(false)
    .get()

android {
    namespace = "io.github.picocrypt_ng.picocrypt_ng"
    compileSdk = 37

    androidResources {
        generateLocaleConfig = true
        localeFilters += listOf(
            "en", "ru", "de", "fr", "es", "b+zh+Hans", "hi", "ko",
        )
    }

    defaultConfig {
        applicationId = "io.github.picocrypt_ng.picocrypt_ng"
        minSdk = 24
        targetSdk = 36
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        versionCode = providers
            .gradleProperty("PICOCRYPT_VERSION_CODE")
            .map(String::toInt)
            .orElse(1)
            .get()
        versionName = providers
            .gradleProperty("PICOCRYPT_VERSION_NAME")
            .orElse("dev")
            .get()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (releaseSigningConfigured) {
            create("release") {
                storeFile = file(releaseSigningProps.getValue("PICOCRYPT_KEYSTORE_PATH")!!)
                storePassword = releaseSigningProps.getValue("PICOCRYPT_KEYSTORE_PASSWORD")
                keyAlias = releaseSigningProps.getValue("PICOCRYPT_KEY_ALIAS")
                keyPassword = releaseSigningProps.getValue("PICOCRYPT_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        debug {
            isPseudoLocalesEnabled = true
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            if (releaseSigningConfigured) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    dependenciesInfo {
        // F-Droid/IzzyOnDroid: strip Google's signed, third-party-unverifiable dependency
        // metadata blob from release artifacts so the build stays fully transparent.
        includeInApk = false
        includeInBundle = false
    }
    splits {
        abi {
            // Per-ABI APKs for F-Droid/IzzyOnDroid (~15 MB smaller each), plus a universal
            // APK as a fallback. The native .so libs come from the gomobile AAR; AGP
            // partitions them at packaging time.
            isEnable = abiSplitsEnabled
            reset()
            include("arm64-v8a", "x86_64")
            isUniversalApk = true
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
    packaging {
        resources {
            excludes += setOf(
                "META-INF/LICENSE.md",
                "META-INF/LICENSE-notice.md",
            )
        }
    }
}

tasks.matching { it.name == "testDebugUnitTest" }.configureEach {
    dependsOn("processReleaseResources")
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

// Give each supported per-ABI APK a stable unique versionCode so it can coexist with
// the universal APK. Preserve the established offsets for upgrade compatibility;
// the universal APK keeps the base code as the fallback.
// Mirror this in the next fdroiddata release as [10 * %c + 2, 10 * %c + 4].
val abiVersionCodeOffsets = mapOf(
    "arm64-v8a" to 2,
    "x86_64" to 4,
)

androidComponents {
    onVariants { variant ->
        variant.outputs.forEach { output ->
            val abi = output.filters.find { it.filterType == ABI }?.identifier ?: return@forEach
            val offset = abiVersionCodeOffsets[abi] ?: return@forEach
            val base = output.versionCode.get() ?: 0
            output.versionCode.set(base * 10 + offset)
        }
    }
}

if (releaseSigningRequested && releaseSigningRequired && !releaseSigningConfigured) {
    throw GradleException(
        "Missing Android release signing properties. Expected PICOCRYPT_KEYSTORE_PATH, " +
            "PICOCRYPT_KEYSTORE_PASSWORD, PICOCRYPT_KEY_ALIAS, and PICOCRYPT_KEY_PASSWORD."
    )
}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.documentfile)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.animation.lint)
    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.androidx.arch.core.testing)
    // JSONObject for unit tests (Android's org.json is not available in unit tests)
    testImplementation(libs.org.json)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    androidTestImplementation(libs.mockk)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)

    implementation(libs.androidx.material.icons.extended)
    implementation(libs.kotlinx.coroutines.android)
    
    // Go Mobile bindings (built separately with build-gomobile.sh)
    implementation(files("libs/picocrypt-mobile.aar"))
}
