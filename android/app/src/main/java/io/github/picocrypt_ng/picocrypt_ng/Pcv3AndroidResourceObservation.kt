package io.github.picocrypt_ng.picocrypt_ng

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.Process
import java.util.Locale

/** Raw, non-secret Android observations. Go remains the only policy and admission owner. */
data class Pcv3AndroidResourceObservation(
    val manufacturer: String,
    val model: String,
    val abi: String,
    val osArch: String,
    val totalRamBytes: Long,
    val effectiveAvailableBytes: Long,
    val processIs64Bit: Boolean,
    val emulatorTraitsClear: Boolean,
    val lowMemory: Boolean,
)

internal fun interface Pcv3ResourceObservationReader {
    fun read(): Pcv3AndroidResourceObservation?
}

internal data class Pcv3AndroidMemoryObservation(
    val totalRamBytes: Long,
    val availableBytes: Long,
    val lowMemory: Boolean,
)

internal data class Pcv3AndroidBuildObservation(
    val brand: String,
    val device: String,
    val fingerprint: String,
    val hardware: String,
    val manufacturer: String,
    val model: String,
    val product: String,
)

/** Platform seam keeps JVM tests off Android stubs while production reads every field fresh. */
internal interface Pcv3AndroidResourcePlatform {
    fun readMemory(): Pcv3AndroidMemoryObservation?
    fun readBuild(): Pcv3AndroidBuildObservation
    fun firstSupportedAbi(): String
    fun osArch(): String
    fun processIs64Bit(): Boolean
}

private class AndroidPcv3ResourcePlatform(context: Context) : Pcv3AndroidResourcePlatform {
    private val applicationContext = context.applicationContext

    override fun readMemory(): Pcv3AndroidMemoryObservation? {
        val manager = applicationContext.getSystemService(ActivityManager::class.java) ?: return null
        val memory = ActivityManager.MemoryInfo()
        manager.getMemoryInfo(memory)
        return Pcv3AndroidMemoryObservation(memory.totalMem, memory.availMem, memory.lowMemory)
    }

    override fun readBuild() = Pcv3AndroidBuildObservation(
        brand = Build.BRAND,
        device = Build.DEVICE,
        fingerprint = Build.FINGERPRINT,
        hardware = Build.HARDWARE,
        manufacturer = Build.MANUFACTURER,
        model = Build.MODEL,
        product = Build.PRODUCT,
    )

    override fun firstSupportedAbi(): String = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
    override fun osArch(): String = System.getProperty("os.arch").orEmpty()
    override fun processIs64Bit(): Boolean = Process.is64Bit()
}

internal class Pcv3AndroidResourceObservationReader internal constructor(
    private val platform: Pcv3AndroidResourcePlatform,
) : Pcv3ResourceObservationReader {
    constructor(context: Context) : this(AndroidPcv3ResourcePlatform(context.applicationContext))

    override fun read(): Pcv3AndroidResourceObservation? {
        val memory = platform.readMemory() ?: return null
        val build = platform.readBuild()
        return Pcv3AndroidResourceObservation(
            manufacturer = build.manufacturer,
            model = build.model,
            abi = platform.firstSupportedAbi(),
            osArch = platform.osArch(),
            totalRamBytes = memory.totalRamBytes,
            effectiveAvailableBytes = memory.availableBytes,
            processIs64Bit = platform.processIs64Bit(),
            emulatorTraitsClear = pcv3EmulatorTraitsClear(build),
            lowMemory = memory.lowMemory,
        )
    }
}

internal fun pcv3EmulatorTraitsClear(): Boolean = pcv3EmulatorTraitsClear(
    Pcv3AndroidBuildObservation(
        brand = Build.BRAND,
        device = Build.DEVICE,
        fingerprint = Build.FINGERPRINT,
        hardware = Build.HARDWARE,
        manufacturer = Build.MANUFACTURER,
        model = Build.MODEL,
        product = Build.PRODUCT,
    ),
)

internal fun pcv3EmulatorTraitsClear(build: Pcv3AndroidBuildObservation): Boolean {
    val values = listOf(
        build.brand,
        build.device,
        build.fingerprint,
        build.hardware,
        build.manufacturer,
        build.model,
        build.product,
    ).map { it.lowercase(Locale.ROOT) }
    return PCV3_EMULATOR_MARKERS.none { marker -> values.any { marker in it } } &&
        build.manufacturer.lowercase(Locale.ROOT) != "unknown"
}

private val PCV3_EMULATOR_MARKERS = listOf(
    "android sdk built for",
    "emulator",
    "generic",
    "genymotion",
    "goldfish",
    "google_sdk",
    "ranchu",
    "sdk_gphone",
    "vbox",
)
