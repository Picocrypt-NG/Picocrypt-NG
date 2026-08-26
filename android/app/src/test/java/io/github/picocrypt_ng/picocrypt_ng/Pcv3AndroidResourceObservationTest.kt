package io.github.picocrypt_ng.picocrypt_ng

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Pcv3AndroidResourceObservationTest {
    @Test
    fun `each PCV3 resource read forwards one fresh raw Android observation without local arithmetic`() {
        val platform = SequencedResourcePlatform(
            memories = ArrayDeque(
                listOf(
                    Pcv3AndroidMemoryObservation(8_000L, 3_000L, lowMemory = false),
                    Pcv3AndroidMemoryObservation(8_000L, 2_500L, lowMemory = true),
                ),
            ),
        )
        val reader = Pcv3AndroidResourceObservationReader(platform)

        val first = reader.read()
        val second = reader.read()

        assertEquals(
            Pcv3AndroidResourceObservation(
                "Acme", "Secure Phone", "arm64-v8a", "aarch64",
                8_000L, 3_000L, true, true, false,
            ),
            first,
        )
        assertEquals(
            Pcv3AndroidResourceObservation(
                "Acme", "Secure Phone", "arm64-v8a", "aarch64",
                8_000L, 2_500L, true, true, true,
            ),
            second,
        )
        assertEquals("a resource challenge requires a fresh MemoryInfo read", 2, platform.memoryReads)
    }

    @Test
    fun `shared emulator evidence helper rejects every conservative marker and unknown manufacturer`() {
        val clean = Pcv3AndroidBuildObservation(
            brand = "Acme",
            device = "secure_phone",
            fingerprint = "acme/secure/phone:16/release-keys",
            hardware = "acme-soc",
            manufacturer = "Acme",
            model = "Secure Phone",
            product = "secure_phone",
        )
        assertTrue(pcv3EmulatorTraitsClear(clean))
        assertFalse(pcv3EmulatorTraitsClear(clean.copy(model = "Android SDK built for x86_64")))
        assertFalse(pcv3EmulatorTraitsClear(clean.copy(hardware = "RaNcHu")))
        assertFalse(pcv3EmulatorTraitsClear(clean.copy(manufacturer = "unknown")))
    }

    private class SequencedResourcePlatform(
        private val memories: ArrayDeque<Pcv3AndroidMemoryObservation>,
    ) : Pcv3AndroidResourcePlatform {
        var memoryReads = 0
            private set

        override fun readMemory(): Pcv3AndroidMemoryObservation? {
            memoryReads += 1
            return if (memories.isEmpty()) null else memories.removeFirst()
        }

        override fun readBuild() = Pcv3AndroidBuildObservation(
            brand = "Acme",
            device = "secure_phone",
            fingerprint = "acme/secure/phone:16/release-keys",
            hardware = "acme-soc",
            manufacturer = "Acme",
            model = "Secure Phone",
            product = "secure_phone",
        )

        override fun firstSupportedAbi() = "arm64-v8a"
        override fun osArch() = "aarch64"
        override fun processIs64Bit() = true
    }
}
