package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import io.mockk.mockk
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class StartupCleanupTest {
    private lateinit var context: Context
    private val parent = File("/data/user/0/app/files/picocrypt_files")

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        StartupCleanup.resetForTests()
    }

    @After
    fun tearDown() {
        StartupCleanup.resetForTests()
    }

    @Test
    fun `none receipt runs journal before exact retained and unrelated transient cleanup`() = runTest {
        val events = mutableListOf<String>()

        val first = StartupCleanup.runBeforeUi(
            context = context,
            restoreReceipt = {
                events += "receipt"
                Pcv3ReceiptRestore.None
            },
            ensurePrivateParent = {
                events += "parent"
                parent
            },
            cleanupJournal = { path ->
                assertEquals(parent.absolutePath, path)
                events += "journal"
                Pcv3JournalCleanupState.ABSENT
            },
            cleanupRetainedOutput = {
                events += "retained"
                true
            },
            cleanupTransient = {
                events += "transient"
                true
            },
        )
        val second = StartupCleanup.runBeforeUi(
            context = context,
            restoreReceipt = { error("completed startup must not restore twice") },
            ensurePrivateParent = { error("completed startup must not reopen the parent") },
            cleanupJournal = { error("completed startup must not repeat journal cleanup") },
            cleanupRetainedOutput = { error("completed startup must not repeat retained cleanup") },
            cleanupTransient = { error("completed startup must not repeat transient cleanup") },
        )

        assertTrue(first)
        assertTrue(second)
        assertEquals(listOf("receipt", "parent", "journal", "retained", "transient"), events)
        assertTrue("Only fully clean None custody may dispatch PCV3", StartupCleanup.allowsPcv3Dispatch())
    }

    @Test
    fun `exact restored receipt starts deny-only UI but preserves every private file`() = runTest {
        val retainedRuns = AtomicInteger(0)
        val transientRuns = AtomicInteger(0)
        val receipt = validReceipt()
        val restored = restoredPresentation(receipt)

        val result = StartupCleanup.runBeforeUi(
            context = context,
            restoreReceipt = {
                Pcv3ReceiptRestore.Exact(ReceiptCustody.Exact(receipt), restored)
            },
            ensurePrivateParent = { parent },
            cleanupJournal = { Pcv3JournalCleanupState.CLEANED },
            cleanupRetainedOutput = {
                retainedRuns.incrementAndGet()
                true
            },
            cleanupTransient = {
                transientRuns.incrementAndGet()
                true
            },
        )

        assertTrue("The already-installed Restored presentation may initialize deny-only UI", result)
        assertEquals(0, retainedRuns.get())
        assertEquals(0, transientRuns.get())
        assertFalse("A restored receipt must block new operations until explicit dismissal", StartupCleanup.allowsPcv3Dispatch())
    }

    @Test
    fun `mismatched restored presentation cannot authorize startup`() = runTest {
        var cleanupRuns = 0

        val result = StartupCleanup.runBeforeUi(
            context = context,
            restoreReceipt = {
                Pcv3ReceiptRestore.Exact(
                    ReceiptCustody.Exact(validReceipt()),
                    restoredPresentation(validReceipt() + "-different"),
                )
            },
            ensurePrivateParent = { parent },
            cleanupJournal = { Pcv3JournalCleanupState.ABSENT },
            cleanupRetainedOutput = { cleanupRuns++; true },
            cleanupTransient = { cleanupRuns++; true },
        )

        assertFalse(result)
        assertEquals(0, cleanupRuns)
        assertFalse(StartupCleanup.allowsPcv3Dispatch())
    }

    @Test
    fun `unknown receipt remains sticky and blocks retained and transient cleanup`() = runTest {
        val events = mutableListOf<String>()
        var laterRestoreCalls = 0

        val first = StartupCleanup.runBeforeUi(
            context = context,
            restoreReceipt = {
                events += "receipt unknown"
                Pcv3ReceiptRestore.Unknown
            },
            ensurePrivateParent = {
                events += "parent"
                parent
            },
            cleanupJournal = {
                events += "journal"
                Pcv3JournalCleanupState.ABSENT
            },
            cleanupRetainedOutput = {
                events += "retained"
                true
            },
            cleanupTransient = {
                events += "transient"
                true
            },
        )
        val second = StartupCleanup.runBeforeUi(
            context = context,
            restoreReceipt = {
                laterRestoreCalls++
                Pcv3ReceiptRestore.None
            },
            ensurePrivateParent = { error("sticky block must not be reopened") },
            cleanupJournal = { error("sticky block must not rerun Go cleanup") },
            cleanupRetainedOutput = { error("sticky block must not delete retained data") },
            cleanupTransient = { error("sticky block must not delete transient data") },
        )

        assertFalse(first)
        assertFalse(second)
        assertEquals(listOf("receipt unknown", "parent", "journal"), events)
        assertEquals(0, laterRestoreCalls)
        assertFalse(StartupCleanup.allowsPcv3Dispatch())
    }

    @Test
    fun `incomplete journal is called once and hard-blocks every Kotlin cleanup`() = runTest {
        val journalRuns = AtomicInteger(0)
        val retainedRuns = AtomicInteger(0)
        val transientRuns = AtomicInteger(0)

        repeat(2) {
            assertFalse(
                StartupCleanup.runBeforeUi(
                    context = context,
                    restoreReceipt = { Pcv3ReceiptRestore.None },
                    ensurePrivateParent = { parent },
                    cleanupJournal = {
                        journalRuns.incrementAndGet()
                        Pcv3JournalCleanupState.INCOMPLETE
                    },
                    cleanupRetainedOutput = {
                        retainedRuns.incrementAndGet()
                        true
                    },
                    cleanupTransient = {
                        transientRuns.incrementAndGet()
                        true
                    },
                ),
            )
        }

        assertEquals("A closed incomplete result is sticky in this process", 1, journalRuns.get())
        assertEquals(0, retainedRuns.get())
        assertEquals(0, transientRuns.get())
    }

    @Test
    fun `fixed parent failure stops before Go and every deletion boundary`() = runTest {
        val journalRuns = AtomicInteger(0)
        val cleanupRuns = AtomicInteger(0)

        val result = StartupCleanup.runBeforeUi(
            context = context,
            restoreReceipt = { Pcv3ReceiptRestore.None },
            ensurePrivateParent = { null },
            cleanupJournal = {
                journalRuns.incrementAndGet()
                Pcv3JournalCleanupState.ABSENT
            },
            cleanupRetainedOutput = {
                cleanupRuns.incrementAndGet()
                true
            },
            cleanupTransient = {
                cleanupRuns.incrementAndGet()
                true
            },
        )

        assertFalse(result)
        assertEquals(0, journalRuns.get())
        assertEquals(0, cleanupRuns.get())
    }

    @Test
    fun `failed exact retained deletion retries without repeating receipt or journal authority`() = runTest {
        val restoreRuns = AtomicInteger(0)
        val journalRuns = AtomicInteger(0)
        val retainedRuns = AtomicInteger(0)
        val transientRuns = AtomicInteger(0)

        val first = StartupCleanup.runBeforeUi(
            context = context,
            restoreReceipt = {
                restoreRuns.incrementAndGet()
                Pcv3ReceiptRestore.None
            },
            ensurePrivateParent = { parent },
            cleanupJournal = {
                journalRuns.incrementAndGet()
                Pcv3JournalCleanupState.CLEANED
            },
            cleanupRetainedOutput = { retainedRuns.incrementAndGet() > 1 },
            cleanupTransient = { transientRuns.incrementAndGet(); true },
        )
        val second = StartupCleanup.runBeforeUi(
            context = context,
            restoreReceipt = { restoreRuns.incrementAndGet(); Pcv3ReceiptRestore.Unknown },
            ensurePrivateParent = { error("validated parent should stay frozen") },
            cleanupJournal = { journalRuns.incrementAndGet(); Pcv3JournalCleanupState.INCOMPLETE },
            cleanupRetainedOutput = { retainedRuns.incrementAndGet() > 1 },
            cleanupTransient = { transientRuns.incrementAndGet(); true },
        )

        assertFalse(first)
        assertTrue(second)
        assertEquals(1, restoreRuns.get())
        assertEquals(1, journalRuns.get())
        assertEquals(2, retainedRuns.get())
        assertEquals(1, transientRuns.get())
        assertTrue(StartupCleanup.allowsPcv3Dispatch())
    }

    @Test
    fun `receipt cancellation reaches the lifecycle owner before filesystem effects`() = runTest {
        val cancellation = CancellationException("startup receipt restore cancelled")
        val filesystemRuns = AtomicInteger(0)

        try {
            StartupCleanup.runBeforeUi(
                context = context,
                restoreReceipt = { throw cancellation },
                ensurePrivateParent = {
                    filesystemRuns.incrementAndGet()
                    parent
                },
                cleanupJournal = {
                    filesystemRuns.incrementAndGet()
                    Pcv3JournalCleanupState.ABSENT
                },
                cleanupRetainedOutput = { filesystemRuns.incrementAndGet(); true },
                cleanupTransient = { filesystemRuns.incrementAndGet(); true },
            )
            fail("Startup owner must observe cancellation")
        } catch (actual: CancellationException) {
            assertSame(cancellation, actual)
        }

        assertEquals(0, filesystemRuns.get())
        assertFalse(StartupCleanup.allowsPcv3Dispatch())

        val retryRuns = AtomicInteger(0)
        assertFalse(
            StartupCleanup.runBeforeUi(
                context = context,
                restoreReceipt = {
                    retryRuns.incrementAndGet()
                    Pcv3ReceiptRestore.None
                },
                ensurePrivateParent = { retryRuns.incrementAndGet(); parent },
                cleanupJournal = {
                    retryRuns.incrementAndGet()
                    Pcv3JournalCleanupState.ABSENT
                },
                cleanupRetainedOutput = { retryRuns.incrementAndGet(); true },
                cleanupTransient = { retryRuns.incrementAndGet(); true },
            ),
        )
        assertEquals(0, retryRuns.get())
    }

    @Test
    fun `concurrent callers cannot return before the one startup cleanup finishes`() = runTest {
        val cleanupStarted = CompletableDeferred<Unit>()
        val allowCleanupToFinish = CompletableDeferred<Unit>()
        val cleanupRuns = AtomicInteger(0)
        val first = async {
            StartupCleanup.runBeforeUi(
                context = context,
                restoreReceipt = { Pcv3ReceiptRestore.None },
                ensurePrivateParent = { parent },
                cleanupJournal = { Pcv3JournalCleanupState.ABSENT },
                cleanupRetainedOutput = { true },
                cleanupTransient = {
                    cleanupRuns.incrementAndGet()
                    cleanupStarted.complete(Unit)
                    allowCleanupToFinish.await()
                    true
                },
            )
        }
        cleanupStarted.await()
        val second = async {
            StartupCleanup.runBeforeUi(
                context = context,
                restoreReceipt = { error("must share the first result") },
                ensurePrivateParent = { error("must share the first result") },
                cleanupJournal = { error("must share the first result") },
                cleanupRetainedOutput = { error("must share the first result") },
                cleanupTransient = { error("must share the first result") },
            )
        }

        assertFalse(second.isCompleted)
        allowCleanupToFinish.complete(Unit)
        assertTrue(first.await())
        assertTrue(second.await())
        assertEquals(1, cleanupRuns.get())
    }

    private fun validReceipt(): String =
        """{"version":1,"receiptID":"r_restored","operationID":"op_restored"}"""

    private fun restoredPresentation(receipt: String) = Pcv3Presentation.Restored(
        snapshot = Pcv3SnapshotView(
            statusCode = "none",
            statusArgs = emptyList(),
            semantic = Pcv3Semantic("success", "none", "PCV3_SUCCESS"),
            publication = Pcv3Publication(
                attempted = true,
                state = "published-durability-uncertain",
                stage = "directory-sync",
                code = "PCV3_PUBLICATION_DURABILITY_UNCERTAIN",
            ),
            forceProvenance = "verified",
            d1BootstrapProvenance = "matching",
            detailStage = "metadata",
            diagnostic = "none",
            completionClass = "durability-uncertain",
            resultArgs = emptyList(),
            warnings = listOf("durability-uncertain"),
            archivePending = false,
            restoredReceipt = receipt,
        ),
        operationId = "op_restored",
        generation = 1,
        receiptId = "r_restored",
    )
}
