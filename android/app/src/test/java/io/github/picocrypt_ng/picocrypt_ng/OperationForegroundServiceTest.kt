package io.github.picocrypt_ng.picocrypt_ng

import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class OperationForegroundServiceTest {
    @Test
    fun `timeout stops host before blocked SAF settles while cleanup retains ownership`() = runTest {
        val settled = CompletableDeferred<Unit>()
        var stopped = false
        var cleanupStarted = false
        var cleanupFinished = false
        stopTimedOutOperationForegroundHost(
            cleanupScope = backgroundScope,
            operation = null,
            pcv3Busy = true,
            stopHost = { stopped = true },
            cancelLegacy = { error("no legacy owner") },
            cancelPcv3 = {
                cleanupStarted = true
                settled.await()
                cleanupFinished = true
            },
        )
        try {
            assertTrue("Android grace period cannot depend on provider settlement", stopped)
            runCurrent()
            assertTrue(cleanupStarted)
            assertFalse(cleanupFinished)
        } finally {
            settled.complete(Unit)
            runCurrent()
        }
        assertTrue("stopping the host must not abandon cleanup custody", cleanupFinished)
    }

    @Test
    fun `foreground host stops only after both legacy and PCV3 ownership are inactive`() {
        val active = TestDataBuilders.createOperationState(done = false)
        val done = TestDataBuilders.createOperationState(done = true)

        assertFalse(shouldStopOperationForegroundHost(active, pcv3Busy = false))
        assertFalse(shouldStopOperationForegroundHost(null, pcv3Busy = true))
        assertFalse(shouldStopOperationForegroundHost(done, pcv3Busy = true))
        assertTrue(shouldStopOperationForegroundHost(null, pcv3Busy = false))
        assertTrue(shouldStopOperationForegroundHost(done, pcv3Busy = false))
    }

    @Test
    fun `foreground host step immediately refreshes every active owner and propagates cancellation`() = runTest {
        val active = TestDataBuilders.createOperationState(done = false)
        val events = mutableListOf<String>()

        pollOperationForegroundOwners(
            operation = active,
            pcv3Busy = true,
            pollLegacy = { events += "legacy" },
            refreshPcv3 = { events += "pcv3" },
        )
        assertEquals("the time-bounded PCV3 challenge is serviced first", listOf("pcv3", "legacy"), events)

        val cancellation = CancellationException("service stopped")
        val thrown = runCatching {
            pollOperationForegroundOwners(
                operation = null,
                pcv3Busy = true,
                pollLegacy = { error("inactive legacy owner must not poll") },
                refreshPcv3 = { throw cancellation },
            )
        }.exceptionOrNull()
        assertSame(cancellation, thrown)
    }

    @Test
    fun `foreground timeout cancels only the owners that can still be active`() = runTest {
        val events = mutableListOf<String>()
        cancelOperationForegroundOwners(
            operation = TestDataBuilders.createOperationState(done = false),
            pcv3Busy = true,
            cancelLegacy = { events += "legacy-cancel" },
            cancelPcv3 = { events += "pcv3-cancel" },
        )
        assertEquals(listOf("legacy-cancel", "pcv3-cancel"), events)

        events.clear()
        cancelOperationForegroundOwners(
            operation = TestDataBuilders.createOperationState(done = true),
            pcv3Busy = false,
            cancelLegacy = { events += "unexpected-legacy" },
            cancelPcv3 = { events += "unexpected-pcv3" },
        )
        assertTrue(events.isEmpty())
    }

    @Test
    fun `foreground timeout attempts PCV3 after every legacy failure and propagates the required cause`() = runTest {
        val failures = listOf<Throwable>(
            CancellationException("legacy cancellation"),
            IllegalStateException("legacy cancellation failed"),
            NoSuchMethodError("stale legacy cancellation boundary"),
        )
        failures.forEach { failure ->
            val events = mutableListOf<String>()
            val thrown = runCatching {
                cancelOperationForegroundOwners(
                    operation = TestDataBuilders.createOperationState(done = false),
                    pcv3Busy = true,
                    cancelLegacy = {
                        events += "legacy-cancel"
                        throw failure
                    },
                    cancelPcv3 = { events += "pcv3-cancel" },
                )
            }.exceptionOrNull()

            assertEquals(listOf("legacy-cancel", "pcv3-cancel"), events)
            assertSame("the first exact timeout failure is preserved", failure, thrown)
        }
    }
}
