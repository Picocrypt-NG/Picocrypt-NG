package io.github.picocrypt_ng.picocrypt_ng

import android.app.ActivityManager
import android.content.Context
import android.os.Debug
import android.os.Process

/** Fresh, non-secret facts for one Go-owned PCV3 resource decision. */
data class Pcv3AndroidResourceObservation(
    val totalRamBytes: Long,
    val effectiveAvailableBytes: Long,
    val platformThresholdBytes: Long,
    val processFootprintBytes: Long,
    val processIs64Bit: Boolean,
    val lowMemory: Boolean,
)

internal fun interface Pcv3ResourceObservationReader {
    fun read(): Pcv3AndroidResourceObservation?
}

internal data class Pcv3AndroidMemoryObservation(
    val totalRamBytes: Long,
    val availableBytes: Long,
    val thresholdBytes: Long,
    val processPssBytes: Long,
    val lowMemory: Boolean,
)

internal interface Pcv3AndroidResourcePlatform {
    fun readMemory(): Pcv3AndroidMemoryObservation?
    fun processIs64Bit(): Boolean
}

private class AndroidPcv3ResourcePlatform(context: Context) : Pcv3AndroidResourcePlatform {
    private val applicationContext = context.applicationContext

    override fun readMemory(): Pcv3AndroidMemoryObservation? {
        val manager = applicationContext.getSystemService(ActivityManager::class.java) ?: return null
        val system = ActivityManager.MemoryInfo()
        manager.getMemoryInfo(system)

        val process = Debug.MemoryInfo()
        Debug.getMemoryInfo(process)
        val processPssKiB = process.totalPss
        if (processPssKiB <= 0) return null

        return Pcv3AndroidMemoryObservation(
            totalRamBytes = system.totalMem,
            availableBytes = system.availMem,
            thresholdBytes = system.threshold,
            processPssBytes = processPssKiB.toLong() * 1024,
            lowMemory = system.lowMemory,
        )
    }

    override fun processIs64Bit(): Boolean = Process.is64Bit()
}

internal class Pcv3AndroidResourceObservationReader internal constructor(
    private val platform: Pcv3AndroidResourcePlatform,
) : Pcv3ResourceObservationReader {
    constructor(context: Context) : this(AndroidPcv3ResourcePlatform(context.applicationContext))

    override fun read(): Pcv3AndroidResourceObservation? {
        val memory = platform.readMemory() ?: return null
        if (
            memory.totalRamBytes <= 0 ||
            memory.availableBytes <= 0 || memory.availableBytes > memory.totalRamBytes ||
            memory.thresholdBytes <= 0 || memory.thresholdBytes > memory.totalRamBytes ||
            memory.processPssBytes <= 0 || memory.processPssBytes > memory.totalRamBytes
        ) {
            return null
        }
        return Pcv3AndroidResourceObservation(
            totalRamBytes = memory.totalRamBytes,
            effectiveAvailableBytes = memory.availableBytes,
            platformThresholdBytes = memory.thresholdBytes,
            processFootprintBytes = memory.processPssBytes,
            processIs64Bit = platform.processIs64Bit(),
            lowMemory = memory.lowMemory,
        )
    }
}
