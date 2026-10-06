package io.github.picocrypt_ng.picocrypt_ng

import android.net.Uri
import io.mockk.every
import io.mockk.mockk
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlin.coroutines.cancellation.CancellationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class Pcv3SafLifecycleTest {

    @Test
    fun `native resource refusal settles directly with its typed no-output snapshot`() = runTest {
        assertNativePreparationTerminalSettles(resourcePreparationTerminal())
    }

    @Test
    fun `native preparation cancellation settles directly with its typed refused snapshot`() = runTest {
        assertNativePreparationTerminalSettles(cancelledPreparationTerminal())
    }

    @Test
    fun `mixed preparation terminal tuples cannot settle custody or release`() = runTest {
        val resource = resourcePreparationTerminal()
        val cancellation = cancelledPreparationTerminal()
        val malformed = listOf(
            resource.copy(diagnostic = "none"),
            resource.copy(stage = "output-publication"),
            resource.copy(completionClass = "refused"),
            resource.copy(publicationAttempted = true),
            resource.copy(publicationState = "not-published"),
            resource.copy(publicationStage = "resource-budget"),
            resource.copy(warnings = listOf("cleanup-incomplete")),
            resource.copy(restoredReceipt = "forged"),
            resource.copy(args = listOf("1")),
            cancellation.copy(diagnostic = "none"),
            cancellation.copy(stage = "output-publication"),
            cancellation.copy(completionClass = "no-output"),
            cancellation.copy(publicationAttempted = false),
            cancellation.copy(publicationState = "none"),
            cancellation.copy(publicationStage = "output-publication"),
            cancellation.copy(publicationCode = "PCV3_PUBLICATION_NOT_PUBLISHED"),
            cancellation.copy(warnings = listOf("cleanup-incomplete")),
            cancellation.copy(restoredReceipt = "forged"),
            cancellation.copy(forceProvenance = "verified"),
        )
        malformed.forEachIndexed { index, terminal ->
            val events = mutableListOf<String>()
            val operation = SafOperation("op-mixed-$index", archivePendingSnapshot(), events)
            val session = SafSession(operation, "unused", terminal, events)
            operation.archive = SafArchive(operation, session, terminal, events,
                beginKind = "terminal", beginSession = null)
            val lifecycle = lifecycle(operation, RecordingCustodian(events))
            val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()
            val publisher = RecordingPublisher(events)
            val result = lifecycle.exportPcv3Archive(live.operationId, live.generation, opaqueUri(), publisher)
            assertTrue("malformed terminal $index must fail closed", result.isFailure)
            assertFalse(events.any { it.startsWith("receipt:") })
            assertEquals(0, operation.releaseCalls)
            assertEquals(0, publisher.publishCalls)
            assertFalse(lifecycle.presentation.value is Pcv3Presentation.Final)
        }
    }

    private suspend fun assertNativePreparationTerminalSettles(terminal: Pcv3SnapshotData) {
        val events = mutableListOf<String>()
        val operation = SafOperation("op-native-terminal", archivePendingSnapshot(), events)
        val session = SafSession(operation, "unused", terminal, events)
        operation.archive = SafArchive(operation, session, terminal, events,
            beginKind = "terminal", beginSession = null)
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()
        val publisher = RecordingPublisher(events)
        val result = lifecycle.exportPcv3Archive(live.operationId, live.generation, opaqueUri(), publisher)
        assertTrue("a canonical native terminal must settle: ${result.exceptionOrNull()?.message}", result.isSuccess)
        assertEquals(0, publisher.publishCalls)
        assertEquals(0, session.confirmCalls)
        assertEquals(0, session.cancelCalls)
        assertEquals(0, session.abortCalls)
        assertEquals(0, session.finishCalls)
        assertEquals(1, operation.releaseCalls)
        assertEquals(listOf("begin", "receipt:none", "release"), events)
        val final = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals("operation-failed", final.snapshot.semantic.outcome)
        assertEquals(terminal.stage, final.snapshot.semantic.stage)
        assertEquals(terminal.diagnostic, final.snapshot.diagnostic)
        assertEquals(terminal.completionClass, final.snapshot.completionClass)
        assertEquals(terminal.publicationState, final.snapshot.publication.state)
    }

    private fun resourcePreparationTerminal() = safNoOutputSnapshot(false, false).copy(
        stage = "resource-budget", diagnostic = "resource-limit",
    )

    private fun cancelledPreparationTerminal() = safNoOutputSnapshot(true, false).copy(
        stage = "cancellation", diagnostic = "cancellation",
        publicationStage = "cancellation", publicationCode = "PCV3_PUBLICATION_CANCELLED",
        completionClass = "refused",
    )

    @Test
    fun `blocked Begin receives fresh resource observations while the archive action is claimed`() = runTest {
        val events = java.util.Collections.synchronizedList(mutableListOf<String>())
        val operation = SafOperation("op-preparation-resources", archivePendingSnapshot(), events)
        val session = SafSession(operation, "active-receipt", terminalSnapshot("terminal-receipt"), events)
        val archive = SafArchive(operation, session, activeSnapshot("active-receipt"), events)
        operation.archive = archive
        val observed = java.util.concurrent.CountDownLatch(1)
        val entered = java.util.concurrent.CountDownLatch(1)
        val observations = java.util.concurrent.CopyOnWriteArrayList<Pcv3AndroidResourceObservation>()
        val fresh = Pcv3AndroidResourceObservation(4L shl 30, 3L shl 30, 64L shl 20, 96L shl 20, true, false)
        archive.afterBeginPrepared = {
            operation.challenge = object : Pcv3ResourceChallengeCapability {
                override fun submit(observation: Pcv3AndroidResourceObservation): Boolean {
                    observations += observation
                    operation.challenge = null
                    observed.countDown()
                    return true
                }
            }
            entered.countDown()
            observed.await(3, java.util.concurrent.TimeUnit.SECONDS)
        }
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()
        assertTrue(lifecycle.installResourceObservationReader(Pcv3ResourceObservationReader { fresh }))
        val export = async(Dispatchers.Default) { lifecycle.exportPcv3Archive(live.operationId, live.generation, opaqueUri(), RecordingPublisher(events)) }
        assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
        export.await().getOrThrow()
        assertEquals("the claimed action must service its own fresh challenge", listOf(fresh), observations)
        assertEquals(1, session.finishCalls)
    }

    @Test
    fun `native budget exhaustion refuses before active receipt and provider effects`() = runTest {
        val events = mutableListOf<String>()
        val operation = SafOperation("op-budget", archivePendingSnapshot(), events)
        val session = SafSession(operation, "active-receipt", terminalSnapshot("terminal-receipt"), events, hostAllowance = 1024)
        operation.archive = SafArchive(operation, session, activeSnapshot("active-receipt"), events)
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()
        val publisher = RecordingPublisher(events)
        val result = lifecycle.exportPcv3Archive(live.operationId, live.generation, opaqueUri(), publisher)
        assertEquals("PCV3_RESOURCE_LIMIT", result.exceptionOrNull()?.message)
        assertEquals(0, publisher.publishCalls)
        assertEquals(0, session.confirmCalls)
        assertFalse(events.contains("receipt:active-receipt"))
        assertEquals(1, session.abortCalls)
    }

    @Test
    fun `receipt confirmation precedes provider and successful Finish precedes terminal settlement and Release`() = runTest {
        val events = mutableListOf<String>()
        val activeReceipt = "active-receipt"
        val terminalReceipt = "terminal-receipt"
        val operation = SafOperation(
            id = "op-saf-success",
            initial = archivePendingSnapshot(),
            events = events,
        )
        val session = SafSession(
            operation = operation,
            activeReceipt = activeReceipt,
            terminal = terminalSnapshot(terminalReceipt),
            events = events,
        )
        operation.archive = SafArchive(operation, session, activeSnapshot(activeReceipt), events)
        val custodian = RecordingCustodian(events)
        val lifecycle = lifecycle(operation, custodian)
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()

        val result = lifecycle.exportPcv3Archive(
            live.operationId,
            live.generation,
            opaqueUri(),
            RecordingPublisher(events),
        )

        assertTrue(result.isSuccess)
        assertEquals(
            listOf(
                "begin",
                "entry-count",
                "entry:0",
                "receipt:$activeReceipt",
                "confirm:$activeReceipt",
                "provider",
                "provider-return",
                "finish",
                "receipt:$terminalReceipt",
                "release",
            ),
            events,
        )
        assertEquals(1, session.finishCalls)
        assertEquals(0, session.abortCalls)
        assertEquals(0, session.cancelCalls)
        assertEquals(1, operation.releaseCalls)
        val final = lifecycle.presentation.value as Pcv3Presentation.Final
        assertEquals("published-durability-uncertain", final.snapshot.publication.state)
    }

    @Test
    fun `unknown active receipt custody aborts with zero confirmation provider and Release`() = runTest {
        val events = mutableListOf<String>()
        val activeReceipt = "active-receipt"
        val operation = SafOperation("op-saf-receipt", archivePendingSnapshot(), events)
        val session = SafSession(
            operation,
            activeReceipt,
            terminalSnapshot("terminal-receipt"),
            events,
        )
        operation.archive = SafArchive(operation, session, activeSnapshot(activeReceipt), events)
        val custodian = RecordingCustodian(events, failOn = activeReceipt)
        val publisher = RecordingPublisher(events)
        val lifecycle = lifecycle(operation, custodian)
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()

        val result = lifecycle.exportPcv3Archive(
            live.operationId,
            live.generation,
            opaqueUri(),
            publisher,
        )

        assertTrue(result.isFailure)
        assertEquals(0, session.confirmCalls)
        assertEquals(0, publisher.publishCalls)
        assertEquals(1, session.cancelCalls)
        assertEquals(1, session.abortCalls)
        assertTrue(events.contains("receipt:terminal-receipt"))
        assertEquals(0, operation.releaseCalls)
        assertSame(ReceiptCustody.Unknown, custodian.custody)
        assertTrue(lifecycle.busy.value)
    }

    @Test
    fun `noncanonical active snapshot aborts before receipt confirmation and provider effects`() = runTest {
        val events = mutableListOf<String>()
        val activeReceipt = "active-malformed"
        val operation = SafOperation("op-saf-malformed-active", archivePendingSnapshot(), events)
        val session = SafSession(
            operation,
            activeReceipt,
            terminalSnapshot("terminal-receipt"),
            events,
        )
        operation.archive = SafArchive(
            operation,
            session,
            activeSnapshot(activeReceipt).copy(forceProvenance = "verified"),
            events,
        )
        val publisher = RecordingPublisher(events)
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()

        val result = lifecycle.exportPcv3Archive(
            live.operationId,
            live.generation,
            opaqueUri(),
            publisher,
        )

        assertTrue(result.isFailure)
        assertFalse(events.contains("receipt:$activeReceipt"))
        assertEquals(0, session.confirmCalls)
        assertEquals(0, publisher.publishCalls)
        assertEquals(1, session.cancelCalls)
        assertEquals(1, session.abortCalls)
        assertTrue(events.contains("receipt:terminal-receipt"))
        assertEquals(1, operation.releaseCalls)
    }

    @Test
    fun `stale archive ticket has zero Begin and provider effects`() = runTest {
        val events = mutableListOf<String>()
        val operation = SafOperation("op-saf-stale", archivePendingSnapshot(), events)
        val session = SafSession(
            operation,
            "active-receipt",
            terminalSnapshot("terminal-receipt"),
            events,
        )
        val archive = SafArchive(operation, session, activeSnapshot("active-receipt"), events)
        operation.archive = archive
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()
        val publisher = RecordingPublisher(events)

        assertTrue(
            lifecycle.exportPcv3Archive(
                "stale",
                live.generation,
                opaqueUri(),
                publisher,
            ).isFailure,
        )
        assertEquals(0, archive.beginCalls)
        assertEquals(0, publisher.publishCalls)
    }

    @Test
    fun `terminal Begin carrying a session cancels and aborts the untransferred session`() = runTest {
        val events = mutableListOf<String>()
        val terminal = terminalSnapshot("terminal-receipt")
        val operation = SafOperation("op-saf-malformed-terminal", archivePendingSnapshot(), events)
        val session = SafSession(operation, "active-receipt", terminal, events)
        operation.archive = SafArchive(
            operation = operation,
            session = session,
            active = terminal,
            events = events,
            beginKind = "terminal",
        )
        val publisher = RecordingPublisher(events)
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()

        val result = lifecycle.exportPcv3Archive(
            live.operationId,
            live.generation,
            opaqueUri(),
            publisher,
        )

        assertTrue(result.isFailure)
        assertEquals(1, session.cancelCalls)
        assertEquals(1, session.abortCalls)
        assertEquals(0, session.confirmCalls)
        assertEquals(0, publisher.publishCalls)
        assertTrue(events.indexOf("session-cancel") < events.indexOf("abort"))
    }

    @Test
    fun `expired or unknown Begin carrying a session cancels and aborts without provider effects`() = runTest {
        for (kind in listOf("expired", "unknown")) {
            val events = mutableListOf<String>()
            val terminal = terminalSnapshot("terminal-$kind")
            val operation = SafOperation("op-saf-malformed-$kind", archivePendingSnapshot(), events)
            val session = SafSession(operation, "active-$kind", terminal, events)
            operation.archive = SafArchive(
                operation = operation,
                session = session,
                active = terminal,
                events = events,
                beginKind = kind,
            )
            val publisher = RecordingPublisher(events)
            val lifecycle = lifecycle(operation, RecordingCustodian(events))
            val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()

            val result = lifecycle.exportPcv3Archive(
                live.operationId,
                live.generation,
                opaqueUri(),
                publisher,
            )

            assertTrue("$kind must fail closed", result.isFailure)
            assertEquals("$kind must cancel exactly once", 1, session.cancelCalls)
            assertEquals("$kind must abort exactly once", 1, session.abortCalls)
            assertEquals("$kind must not confirm", 0, session.confirmCalls)
            assertEquals("$kind must not reach the provider", 0, publisher.publishCalls)
            assertTrue(events.indexOf("session-cancel") < events.indexOf("abort"))
        }
    }

    @Test
    fun `noncanonical terminal Begin without a session has zero receipt and Release effects`() = runTest {
        val events = mutableListOf<String>()
        val malformed = terminalSnapshot("terminal-receipt").copy(
            publicationCode = "PCV3_SUCCESS",
        )
        val operation = SafOperation("op-saf-malformed-snapshot", archivePendingSnapshot(), events)
        val session = SafSession(operation, "active-receipt", malformed, events)
        operation.archive = SafArchive(
            operation = operation,
            session = session,
            active = malformed,
            events = events,
            beginKind = "terminal",
            beginSession = null,
        )
        val publisher = RecordingPublisher(events)
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()

        val result = lifecycle.exportPcv3Archive(
            live.operationId,
            live.generation,
            opaqueUri(),
            publisher,
        )

        assertTrue(result.isFailure)
        assertFalse(events.any { it.startsWith("receipt:") })
        assertEquals(0, operation.releaseCalls)
        assertEquals(0, publisher.publishCalls)
    }

    @Test
    fun `each canonical closed SAF terminal family settles exact custody before Release`() = runTest {
        val terminals = listOf(
            safNoOutputSnapshot(publicationAttempted = false, cleanupIncomplete = true),
            safNoOutputSnapshot(publicationAttempted = true, cleanupIncomplete = false),
            terminalSnapshot("terminal-durability"),
            safPublicationIndeterminateSnapshot("terminal-indeterminate"),
        )

        terminals.forEachIndexed { index, terminal ->
            val events = mutableListOf<String>()
            val operation = SafOperation("op-saf-terminal-$index", archivePendingSnapshot(), events)
            val session = SafSession(operation, "active-$index", terminal, events)
            operation.archive = SafArchive(
                operation = operation,
                session = session,
                active = terminal,
                events = events,
                beginKind = "terminal",
                beginSession = null,
            )
            val publisher = RecordingPublisher(events)
            val lifecycle = lifecycle(operation, RecordingCustodian(events))
            val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()

            val result = lifecycle.exportPcv3Archive(
                live.operationId,
                live.generation,
                opaqueUri(),
                publisher,
            )

            assertTrue(
                "canonical terminal $index failed with ${result.exceptionOrNull()?.message}; events=$events",
                result.isSuccess,
            )
            assertEquals(1, operation.releaseCalls)
            assertEquals(0, publisher.publishCalls)
            assertTrue(events.indexOf("receipt:${terminal.restoredReceipt.ifEmpty { "none" }}") < events.indexOf("release"))
        }
    }

    @Test
    fun `claimed Finish never falls through to Abort when terminalization fails`() = runTest {
        data class Case(
            val name: String,
            val terminal: Pcv3SnapshotData,
            val finishFailure: Throwable? = null,
        )
        val cases = listOf(
            Case(
                "invalid return",
                terminalSnapshot("terminal-invalid").copy(completionClass = "unknown"),
            ),
            Case(
                "throw",
                terminalSnapshot("terminal-throw"),
                IllegalStateException("finish failed after ownership was consumed"),
            ),
        )

        cases.forEach { case ->
            val events = mutableListOf<String>()
            val operation = SafOperation("op-saf-finish-${case.name}", archivePendingSnapshot(), events)
            val session = SafSession(
                operation = operation,
                activeReceipt = "active-${case.name}",
                terminal = case.terminal,
                events = events,
                finishFailure = case.finishFailure,
            )
            operation.archive = SafArchive(
                operation,
                session,
                activeSnapshot("active-${case.name}"),
                events,
            )
            val publisher = RecordingPublisher(events)
            val lifecycle = lifecycle(operation, RecordingCustodian(events))
            val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()

            val result = lifecycle.exportPcv3Archive(
                live.operationId,
                live.generation,
                opaqueUri(),
                publisher,
            )

            assertTrue("${case.name} must fail closed", result.isFailure)
            assertEquals("${case.name}: Finish is one shot", 1, session.finishCalls)
            assertEquals("${case.name}: Abort is mutually exclusive with claimed Finish", 0, session.abortCalls)
            assertEquals("${case.name}: no Release", 0, operation.releaseCalls)
            assertFalse("${case.name}: no terminal receipt effect", events.any { it.startsWith("receipt:terminal") })
        }
    }

    @Test
    fun `cancellation interrupts the exact provider action waits for settlement then Aborts once`() = runTest {
        val events = mutableListOf<String>()
        val operation = SafOperation("op-saf-cancel", archivePendingSnapshot(), events)
        val session = SafSession(
            operation,
            "active-receipt",
            terminalSnapshot("terminal-receipt"),
            events,
        )
        operation.archive = SafArchive(operation, session, activeSnapshot("active-receipt"), events)
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()
        val providerEntered = CompletableDeferred<Unit>()
        val providerRelease = CompletableDeferred<Unit>()
        val publisher = RecordingPublisher(
            events = events,
            entered = providerEntered,
            release = providerRelease,
            result = Pcv3SafPublicationResult.NEEDS_ABORT,
        )
        val export = async(Dispatchers.Default) {
            lifecycle.exportPcv3Archive(
                live.operationId,
                live.generation,
                opaqueUri(),
                publisher,
            )
        }
        providerEntered.await()

        val cancel = async(Dispatchers.Default) { lifecycle.cancelPcv3() }
        while (session.cancelCalls == 0) kotlinx.coroutines.yield()
        assertFalse("Cancel cannot finish before the provider call settles", cancel.isCompleted)
        providerRelease.complete(Unit)

        assertTrue(cancel.await().isSuccess)
        assertTrue(export.await().isFailure)
        assertEquals(1, publisher.cancellation.cancelCalls)
        assertEquals(1, session.cancelCalls)
        assertEquals(1, session.abortCalls)
        assertEquals(0, session.finishCalls)
        assertTrue(events.indexOf("session-cancel") < events.indexOf("provider-return"))
        assertTrue(events.indexOf("provider-return") < events.indexOf("abort"))
    }

    @Test
    fun `caller cancellation interrupts a blocked provider then waits and Aborts with the exact cause`() = runTest {
        val events = mutableListOf<String>()
        val operation = SafOperation("op-saf-caller-cancel", archivePendingSnapshot(), events)
        val session = SafSession(
            operation,
            "active-receipt",
            terminalSnapshot("terminal-receipt"),
            events,
        )
        operation.archive = SafArchive(operation, session, activeSnapshot("active-receipt"), events)
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()
        val providerEntered = CompletableDeferred<Unit>()
        val providerRelease = CompletableDeferred<Unit>()
        val publisher = RecordingPublisher(
            events = events,
            entered = providerEntered,
            release = providerRelease,
        )
        // Anonymous subtype prevents coroutine stack-trace recovery from cloning
        // the exception and obscuring the lifecycle's identity guarantee.
        val cancellation = object : CancellationException("caller export cancelled") {}
        val export = async(Dispatchers.Default) {
            lifecycle.exportPcv3Archive(
                live.operationId,
                live.generation,
                opaqueUri(),
                publisher,
            )
        }
        providerEntered.await()

        try {
            export.cancel(cancellation)
            assertTrue(
                "caller cancellation must reach the lifecycle while the provider is still blocked",
                publisher.cancellation.awaitCancellation(),
            )
            assertFalse("the test has not released the blocked provider", providerRelease.isCompleted)
            assertEquals(1, publisher.cancellation.cancelCalls)
            assertEquals(1, session.cancelCalls)
            assertFalse("provider must still be in flight after both cancellation calls", events.contains("provider-return"))
        } finally {
            providerRelease.complete(Unit)
        }

        val actual = try {
            export.await()
            throw AssertionError("caller cancellation must propagate")
        } catch (error: CancellationException) {
            error
        }
        assertSame("the caller-owned cancellation identity must be preserved", cancellation, actual)
        assertEquals(1, session.abortCalls)
        assertEquals(0, session.finishCalls)
        assertEquals(0, operation.releaseCalls)
        assertTrue(events.indexOf("provider-return") < events.indexOf("abort"))
    }

    @Test
    fun `cancellation reaches blocked Begin before a session returns`() = runTest {
        val events = java.util.Collections.synchronizedList(mutableListOf<String>())
        val operation = SafOperation("op-preparation", archivePendingSnapshot(), events)
        val session = SafSession(operation, "active-receipt", terminalSnapshot("terminal-receipt"), events)
        val archive = SafArchive(operation, session, activeSnapshot("active-receipt"), events)
        operation.archive = archive
        val entered = java.util.concurrent.CountDownLatch(1)
        val cancelled = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        archive.afterBeginPrepared = { entered.countDown(); release.await(5, java.util.concurrent.TimeUnit.SECONDS) }
        archive.preparationCancelled = { cancelled.countDown() }
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()
        val publisher = RecordingPublisher(events)
        val export = async(Dispatchers.Default) { lifecycle.exportPcv3Archive(live.operationId, live.generation, opaqueUri(), publisher) }
        assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS))
        val cancel = async(Dispatchers.Default) { lifecycle.cancelPcv3() }
        try {
            assertTrue("Begin cancellation must reach the archive owner without an exposed session", cancelled.await(3, java.util.concurrent.TimeUnit.SECONDS))
            assertFalse(cancel.isCompleted)
            assertEquals(0, operation.releaseCalls)
        } finally { release.countDown() }
        export.await()
        cancel.await()
        assertEquals(1, session.abortCalls)
        assertEquals(0, session.finishCalls)
        assertFalse(events.any { it.startsWith("publish") || it.startsWith("confirm:") })
    }

    @Test
    fun `cancellation after Begin prepares a session still Cancels and Aborts it once`() = runTest {
        val events = mutableListOf<String>()
        val operation = SafOperation("op-saf-cancel-after-begin", archivePendingSnapshot(), events)
        val session = SafSession(
            operation,
            "active-receipt",
            terminalSnapshot("terminal-receipt"),
            events,
        )
        val archive = SafArchive(operation, session, activeSnapshot("active-receipt"), events)
        operation.archive = archive
        val publisher = RecordingPublisher(events)
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()

        lateinit var export: kotlinx.coroutines.Deferred<Result<Unit>>
        archive.afterBeginPrepared = { export.cancel() }
        export = async(Dispatchers.Default, start = CoroutineStart.LAZY) {
            lifecycle.exportPcv3Archive(
                live.operationId,
                live.generation,
                opaqueUri(),
                publisher,
            )
        }
        export.start()

        var cancelled = false
        try {
            export.await()
        } catch (_: CancellationException) {
            cancelled = true
        }

        assertTrue("the caller cancellation must propagate", cancelled)
        assertEquals(1, session.cancelCalls)
        assertEquals(1, session.abortCalls)
        assertEquals(0, session.finishCalls)
        assertEquals(0, session.confirmCalls)
        assertEquals(0, publisher.publishCalls)
        assertEquals(0, operation.releaseCalls)
        assertTrue(events.indexOf("begin-prepared") < events.indexOf("session-cancel"))
        assertTrue(events.indexOf("session-cancel") < events.indexOf("abort"))
    }

    @Test
    fun `cancellation after Finish claim never invokes session Cancel or Abort`() = runTest {
        val events = mutableListOf<String>()
        val finishEntered = CompletableDeferred<Unit>()
        val finishRelease = CompletableDeferred<Unit>()
        val operation = SafOperation("op-saf-cancel-during-finish", archivePendingSnapshot(), events)
        val session = SafSession(
            operation = operation,
            activeReceipt = "active-receipt",
            terminal = terminalSnapshot("terminal-receipt"),
            events = events,
            finishEntered = finishEntered,
            finishRelease = finishRelease,
        )
        operation.archive = SafArchive(operation, session, activeSnapshot("active-receipt"), events)
        val publisher = RecordingPublisher(events)
        val lifecycle = lifecycle(operation, RecordingCustodian(events))
        val live = lifecycle.start(request(), "password".toCharArray(), File("receipt")).getOrThrow()

        val export = async(Dispatchers.Default) {
            lifecycle.exportPcv3Archive(
                live.operationId,
                live.generation,
                opaqueUri(),
                publisher,
            )
        }
        finishEntered.await()
        val cancel = async(Dispatchers.Default) { lifecycle.cancelPcv3() }
        while (publisher.cancellation.cancelCalls == 0) kotlinx.coroutines.yield()
        assertFalse("Cancel waits for the claimed Finish to settle", cancel.isCompleted)
        finishRelease.complete(Unit)

        assertTrue(cancel.await().isSuccess)
        export.await()
        assertEquals(1, session.finishCalls)
        assertEquals("Finish ownership excludes session Cancel", 0, session.cancelCalls)
        assertEquals("Finish ownership excludes Abort", 0, session.abortCalls)
    }

    private fun lifecycle(
        operation: SafOperation,
        custodian: RecordingCustodian,
    ) = Pcv3Lifecycle(
        bridge = Pcv3Bridge(SafTransport(operation)),
        receiptCustodyFactory = Pcv3ReceiptCustodyFactory { _, initial ->
            assertSame(ReceiptCustody.None, initial)
            custodian
        },
    )

    private fun request() = Pcv3Request(
        mode = "read-normal",
        factorPolicy = "password",
        keyfileOrder = "none",
        source = "input",
        target = "output",
        keyfiles = emptyList(),
    )

    private fun opaqueUri(): Uri = mockk<Uri>().also { uri ->
        every { uri.authority } returns "provider"
        every { uri.toString() } throws AssertionError("URI string conversion")
        every { uri.path } throws AssertionError("URI path conversion")
    }

    private class SafTransport(
        private val operation: Pcv3OperationCapability,
    ) : Pcv3Transport {
        override fun start(requestJson: String, password: ByteArray) = Pcv3StartData("", operation)
        override fun restoreReceipt(receipt: String) =
            Pcv3RestoredReceiptData("PCV3_RECEIPT_INVALID", "", "", null)
    }

    private class SafOperation(
        override val id: String,
        initial: Pcv3SnapshotData,
        private val events: MutableList<String>,
    ) : Pcv3OperationCapability {
        @Volatile
        var snapshotData = initial
        @Volatile
        var challenge: Pcv3ResourceChallengeCapability? = null
        override fun resourceChallenge(): Pcv3ResourceChallengeCapability? = challenge
        @Volatile
        var archive: SafArchive? = null
        @Volatile
        var output: Pcv3OutputCapability? = null
        var releaseCalls = 0
            private set

        override fun snapshot(): Pcv3SnapshotData = snapshotData
        override fun consent(): Pcv3ConsentCapability? = null
        override fun archive(): Pcv3ArchiveCapability? = archive?.takeIf { !it.consumed }
        override fun output(): Pcv3OutputCapability? = output
        override fun cancel(): Pcv3SnapshotData = snapshotData

        override fun release(): String {
            releaseCalls += 1
            events += "release"
            return if (snapshotData.archivePending || archive?.consumed == false || output != null) {
                "PCV3_OPERATION_RELEASE_DENIED"
            } else {
                ""
            }
        }
    }

    private class SafArchive(
        private val operation: SafOperation,
        private val session: SafSession,
        private val active: Pcv3SnapshotData,
        private val events: MutableList<String>,
        private val beginKind: String = "session",
        private val beginSession: Pcv3ArchiveSessionCapability? = session,
    ) : Pcv3ArchiveCapability {
        @Volatile
        var consumed = false
            private set
        var beginCalls = 0
            private set
        var afterBeginPrepared: (() -> Unit)? = null
        var preparationCancelled: (() -> Unit)? = null
        override fun cancelPreparation() { preparationCancelled?.invoke() }

        override fun close(): Pcv3SnapshotData {
            consumed = true
            return session.abort()
        }

        override fun beginSaf(): Pcv3ArchiveBeginData {
            beginCalls += 1
            events += "begin"
            consumed = true
            operation.snapshotData = active
            val result = Pcv3ArchiveBeginData(beginKind, "", beginSession, active)
            afterBeginPrepared?.let { callback ->
                events += "begin-prepared"
                callback()
            }
            return result
        }
    }

    private class SafSession(
        private val operation: SafOperation,
        private val activeReceipt: String,
        private val terminal: Pcv3SnapshotData,
        private val events: MutableList<String>,
        private val finishFailure: Throwable? = null,
        private val finishEntered: CompletableDeferred<Unit>? = null,
        private val finishRelease: CompletableDeferred<Unit>? = null,
        private val hostAllowance: Long = PCV3_SAF_MAX_WORKING_BYTES,
    ) : Pcv3ArchiveSessionCapability {
        var confirmCalls = 0
            private set
        var cancelCalls = 0
            private set
        var finishCalls = 0
            private set
        var abortCalls = 0
            private set

        override fun hostMemoryBudgetBytes(): Long = hostAllowance

        override fun entryCount(): Long {
            events += "entry-count"
            return 1
        }

        override fun entry(index: Long): Pcv3ArchiveEntryData? {
            events += "entry:$index"
            return Pcv3ArchiveEntryData("file", -1, isDirectory = false, size = 1)
        }

        override fun confirmCrashReceiptPersisted(receipt: String): Pcv3ArchiveStepData {
            confirmCalls += 1
            events += "confirm:$receipt"
            return if (receipt == activeReceipt) {
                Pcv3ArchiveStepData("ready", 0)
            } else {
                Pcv3ArchiveStepData("rejected", -1)
            }
        }

        override fun attempt(index: Long) = Pcv3ArchiveStepData("attempted", index)
        override fun ackDirectory(index: Long) = Pcv3ArchiveStepData("ready", index + 1)
        override fun writeFd(index: Long, descriptor: Long) = Pcv3ArchiveStepData("ready", index + 1)

        override fun cancel(): Pcv3ArchiveStepData {
            cancelCalls += 1
            events += "session-cancel"
            return Pcv3ArchiveStepData("poisoned", -1)
        }

        override fun finish(): Pcv3SnapshotData {
            finishCalls += 1
            events += "finish"
            finishEntered?.complete(Unit)
            finishRelease?.let { runBlocking { it.await() } }
            finishFailure?.let { throw it }
            operation.snapshotData = terminal
            return terminal
        }

        override fun abort(): Pcv3SnapshotData {
            abortCalls += 1
            events += "abort"
            operation.snapshotData = terminal
            return terminal
        }
    }

    private class RecordingPublisher(
        private val events: MutableList<String>,
        private val entered: CompletableDeferred<Unit>? = null,
        private val release: CompletableDeferred<Unit>? = null,
        private val result: Pcv3SafPublicationResult = Pcv3SafPublicationResult.READY_TO_FINISH,
    ) : Pcv3SafPublisher {
        val cancellation = RecordingCancellation(events)
        var publishCalls = 0
            private set

        override fun newCancellation(): Pcv3SafCancellation = cancellation

        override fun publish(
            root: Uri,
            manifest: Pcv3SafManifest,
            session: Pcv3SafEntrySession,
            cancellation: Pcv3SafCancellation,
        ): Pcv3SafPublicationResult {
            publishCalls += 1
            events += "provider"
            entered?.complete(Unit)
            release?.let { runBlocking { it.await() } }
            events += "provider-return"
            return result
        }
    }

    private class RecordingCancellation(
        private val events: MutableList<String>,
    ) : Pcv3SafCancellation {
        private val cancellationObserved = CountDownLatch(1)
        @Volatile
        private var cancelled = false
        var cancelCalls = 0
            private set

        override fun isCancelled(): Boolean = cancelled

        override fun cancel() {
            if (!cancelled) {
                cancelled = true
                cancelCalls += 1
                events += "provider-cancel"
                cancellationObserved.countDown()
            }
        }

        fun awaitCancellation(): Boolean = cancellationObserved.await(2, TimeUnit.SECONDS)
    }

    private class RecordingCustodian(
        private val events: MutableList<String>,
        private val failOn: String? = null,
    ) : Pcv3ReceiptCustodyCapability {
        override var custody: ReceiptCustody = ReceiptCustody.None
            private set

        override fun transition(desiredReceipt: String?): ReceiptCustody {
            events += "receipt:${desiredReceipt ?: "none"}"
            custody = if ((failOn != null && desiredReceipt == failOn) || custody === ReceiptCustody.Unknown) {
                ReceiptCustody.Unknown
            } else if (desiredReceipt == null) {
                ReceiptCustody.None
            } else {
                ReceiptCustody.Exact(desiredReceipt)
            }
            return custody
        }
    }

    private fun archivePendingSnapshot() = Pcv3SnapshotData(
        statusCode = "none", statusArgs = emptyList(), outcome = "success", stage = "none", code = "PCV3_SUCCESS",
        forceProvenance = "none", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = false, publicationState = "none", publicationStage = "none", publicationCode = "none",
        diagnostic = "none", completionClass = "archive-pending", args = emptyList(), warnings = emptyList(),
        archivePending = true,
    )

    private fun activeSnapshot(receipt: String) = Pcv3SnapshotData(
        statusCode = "publishing", statusArgs = emptyList(), outcome = "success", stage = "none", code = "PCV3_SUCCESS",
        forceProvenance = "none", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = true, publicationState = "publication-indeterminate",
        publicationStage = "output-publication", publicationCode = "PCV3_PUBLICATION_INDETERMINATE",
        diagnostic = "none", completionClass = "publication-indeterminate", args = emptyList(),
        warnings = listOf("publication-indeterminate"),
        archivePending = false, restoredReceipt = receipt,
    )

    private fun terminalSnapshot(receipt: String) = Pcv3SnapshotData(
        statusCode = "none", statusArgs = emptyList(), outcome = "success", stage = "none", code = "PCV3_SUCCESS",
        forceProvenance = "none", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = true, publicationState = "published-durability-uncertain",
        publicationStage = "directory-sync", publicationCode = "PCV3_PUBLICATION_DURABILITY_UNCERTAIN",
        diagnostic = "none", completionClass = "durability-uncertain", args = emptyList(),
        warnings = listOf("durability-uncertain"), archivePending = false, restoredReceipt = receipt,
    )

    private fun safNoOutputSnapshot(
        publicationAttempted: Boolean,
        cleanupIncomplete: Boolean,
    ) = Pcv3SnapshotData(
        statusCode = "none", statusArgs = emptyList(), outcome = "operation-failed",
        stage = "output-publication", code = "PCV3_OPERATION_FAILED",
        forceProvenance = "none", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = publicationAttempted,
        publicationState = if (publicationAttempted) "not-published" else "none",
        publicationStage = if (publicationAttempted) "output-publication" else "none",
        publicationCode = if (publicationAttempted) "PCV3_PUBLICATION_NOT_PUBLISHED" else "none",
        diagnostic = if (publicationAttempted) "none" else "core-failure",
        completionClass = "no-output", args = emptyList(),
        warnings = if (cleanupIncomplete) listOf("cleanup-incomplete") else emptyList(),
        archivePending = false,
    )

    private fun safPublicationIndeterminateSnapshot(receipt: String) = Pcv3SnapshotData(
        statusCode = "none", statusArgs = emptyList(), outcome = "success", stage = "none", code = "PCV3_SUCCESS",
        forceProvenance = "none", d1BootstrapProvenance = "none", detailStage = "none",
        publicationAttempted = true, publicationState = "publication-indeterminate",
        publicationStage = "output-publication", publicationCode = "PCV3_PUBLICATION_INDETERMINATE",
        diagnostic = "core-failure", completionClass = "publication-indeterminate",
        args = emptyList(), warnings = listOf("publication-indeterminate", "cleanup-incomplete"),
        archivePending = false, restoredReceipt = receipt,
    )
}
