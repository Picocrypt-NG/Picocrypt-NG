package io.github.picocrypt_ng.picocrypt_ng

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class Pcv3AndroidResourceObservationTest {
    @Test
    fun `each challenge gets one fresh memory and process observation`() {
        val platform = SequencedResourcePlatform(
            ArrayDeque(
                listOf(
                    Pcv3AndroidMemoryObservation(8_000L, 3_000L, 500L, 200L, false),
                    Pcv3AndroidMemoryObservation(8_000L, 2_500L, 500L, 220L, true),
                ),
            ),
        )
        val reader = Pcv3AndroidResourceObservationReader(platform)

        assertEquals(
            Pcv3AndroidResourceObservation(8_000L, 3_000L, 500L, 200L, true, false),
            reader.read(),
        )
        assertEquals(
            Pcv3AndroidResourceObservation(8_000L, 2_500L, 500L, 220L, true, true),
            reader.read(),
        )
        assertEquals(2, platform.reads)
    }

    @Test
    fun `incomplete or contradictory memory facts produce no observation`() {
        val invalid = listOf(
            Pcv3AndroidMemoryObservation(0L, 3_000L, 500L, 200L, false),
            Pcv3AndroidMemoryObservation(8_000L, 0L, 500L, 200L, false),
            Pcv3AndroidMemoryObservation(8_000L, 8_001L, 500L, 200L, false),
            Pcv3AndroidMemoryObservation(8_000L, 3_000L, 0L, 200L, false),
            Pcv3AndroidMemoryObservation(8_000L, 3_000L, 500L, 0L, false),
        )

        for (memory in invalid) {
            assertNull(
                Pcv3AndroidResourceObservationReader(
                    SequencedResourcePlatform(ArrayDeque(listOf(memory))),
                ).read(),
            )
        }
    }

    private class SequencedResourcePlatform(
        private val memories: ArrayDeque<Pcv3AndroidMemoryObservation>,
    ) : Pcv3AndroidResourcePlatform {
        var reads = 0
            private set

        override fun readMemory(): Pcv3AndroidMemoryObservation? {
            reads += 1
            return if (memories.isEmpty()) null else memories.removeFirst()
        }

        override fun processIs64Bit() = true
    }
}
