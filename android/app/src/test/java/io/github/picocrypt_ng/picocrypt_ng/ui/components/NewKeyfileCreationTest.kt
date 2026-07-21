package io.github.picocrypt_ng.picocrypt_ng.ui.components

import java.io.IOException
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class NewKeyfileCreationTest {
    @Test
    fun `keyfile bytes are zeroed when creation is cancelled`() = runTest {
        val bytes = ByteArray(32) { 0x5A.toByte() }
        val cancellation = CancellationException("cancel after generation")

        try {
            withZeroedKeyfileBuffer(bytes) {
                throw cancellation
            }
            fail("CancellationException must be rethrown")
        } catch (actual: CancellationException) {
            assertSame(cancellation, actual)
        }

        assertTrue("Every generated keyfile byte must be zeroed", bytes.all { it == 0.toByte() })
    }

    @Test
    fun `configuration cancellation never reaches the error owner`() = runTest {
        val thrownCancellation = CancellationException("thrown cancellation")
        val returnedCancellation = CancellationException("returned cancellation")
        val cancellations = listOf(
            thrownCancellation to suspend {
                throw thrownCancellation
            },
            returnedCancellation to suspend {
                Result.failure<String>(returnedCancellation)
            },
        )

        cancellations.forEach { (expected, operation) ->
            val errors = mutableListOf<Throwable>()

            try {
                runNewKeyfileCreation(
                    operation = operation,
                    onSuccess = { fail("Cancelled keyfile creation must not succeed") },
                    onFailure = { errors += it },
                )
                fail("CancellationException must be rethrown")
            } catch (actual: CancellationException) {
                assertSame(expected, actual)
            }

            assertEquals("Cancellation must not become a user-visible error", emptyList<Throwable>(), errors)
        }
    }

    @Test
    fun `copy and create failures each reach one error owner exactly once`() = runTest {
        val copyFailure = IOException("copy failed")
        val createFailure = SecurityException("create failed")
        val failures = listOf(
            copyFailure to suspend { Result.failure<String>(copyFailure) },
            createFailure to suspend { throw createFailure },
        )

        failures.forEach { (expected, operation) ->
            val errors = mutableListOf<Throwable>()

            runNewKeyfileCreation(
                operation = operation,
                onSuccess = { fail("Failed keyfile creation must not succeed") },
                onFailure = { errors += it },
            )

            assertEquals("A failure must have one dialog state owner", 1, errors.size)
            assertSame(expected, errors.single())
        }
    }

    @Test
    fun `successful creation bypasses the error owner`() = runTest {
        val errors = mutableListOf<Throwable>()
        var createdPath: String? = null

        runNewKeyfileCreation(
            operation = { Result.success("/internal/keyfile_0") },
            onSuccess = { createdPath = it },
            onFailure = { errors += it },
        )

        assertEquals("/internal/keyfile_0", createdPath)
        assertEquals(emptyList<Throwable>(), errors)
    }
}
