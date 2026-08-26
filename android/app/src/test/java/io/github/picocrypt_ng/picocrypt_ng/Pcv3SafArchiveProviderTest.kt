package io.github.picocrypt_ng.picocrypt_ng

import android.content.ContentResolver
import android.database.Cursor
import android.net.Uri
import android.os.CancellationSignal
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.Runs
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class Pcv3SafArchiveProviderTest {
    @Test
    fun `manifest capture reads each bounded immutable entry once`() {
        val events = mutableListOf<String>()
        val session = RecordingArchiveSession(
            entries = listOf(
                Pcv3ArchiveEntryData("folder", -1, isDirectory = true, size = 0),
                Pcv3ArchiveEntryData("empty", 0, isDirectory = false, size = 0),
            ),
            events = events,
        )

        val manifest = capturePcv3SafManifest(session)

        assertNotNull(manifest)
        assertEquals(
            listOf("entry-count", "entry:0", "entry:1"),
            events,
        )
        assertEquals(
            listOf(
                Pcv3ArchiveEntryData("folder", -1, isDirectory = true, size = 0),
                Pcv3ArchiveEntryData("empty", 0, isDirectory = false, size = 0),
            ),
            manifest?.entries,
        )
    }

    @Test
    fun `manifest capture rejects traversal topology and contradictory directory sizes`() {
        val invalid = listOf(
            listOf(Pcv3ArchiveEntryData("..", -1, isDirectory = false, size = 1)),
            listOf(Pcv3ArchiveEntryData("a/b", -1, isDirectory = false, size = 1)),
            listOf(Pcv3ArchiveEntryData("directory", -1, isDirectory = true, size = 1)),
            listOf(Pcv3ArchiveEntryData("negative", -1, isDirectory = false, size = -1)),
            listOf(Pcv3ArchiveEntryData("child", 0, isDirectory = false, size = 1)),
            listOf(
                Pcv3ArchiveEntryData("file", -1, isDirectory = false, size = 1),
                Pcv3ArchiveEntryData("child", 0, isDirectory = false, size = 1),
            ),
            listOf(
                Pcv3ArchiveEntryData("same", -1, isDirectory = false, size = 1),
                Pcv3ArchiveEntryData("same", -1, isDirectory = false, size = 1),
            ),
            listOf(Pcv3ArchiveEntryData("bad\u0000name", -1, isDirectory = false, size = 1)),
            listOf(Pcv3ArchiveEntryData("bad\\name", -1, isDirectory = false, size = 1)),
            listOf(Pcv3ArchiveEntryData("C:relative", -1, isDirectory = false, size = 1)),
            listOf(Pcv3ArchiveEntryData("\uD800", -1, isDirectory = false, size = 1)),
        )

        invalid.forEach { entries ->
            assertNull(entries.toString(), capturePcv3SafManifest(RecordingArchiveSession(entries)))
        }

        assertNull(
            "total file bytes must reject Long.MAX_VALUE + 1 without wrapping",
            capturePcv3SafManifest(
                RecordingArchiveSession(
                    listOf(
                        Pcv3ArchiveEntryData("maximum", -1, isDirectory = false, size = Long.MAX_VALUE),
                        Pcv3ArchiveEntryData("overflow", -1, isDirectory = false, size = 1),
                    ),
                ),
            ),
        )
    }

    @Test
    fun `manifest capture enforces count component path depth and total path bounds`() {
        assertNull(capturePcv3SafManifest(CountOnlySession(0)))
        assertNull(capturePcv3SafManifest(CountOnlySession(65_537)))
        assertNotNull(
            capturePcv3SafManifest(
                RecordingArchiveSession(
                    listOf(Pcv3ArchiveEntryData("a".repeat(255), -1, false, 0)),
                ),
            ),
        )
        assertNull(
            capturePcv3SafManifest(
                RecordingArchiveSession(
                    listOf(Pcv3ArchiveEntryData("a".repeat(256), -1, false, 0)),
                ),
            ),
        )

        val maximumPath = deepManifest(directoryCount = 127, leafCount = 1, leafLength = 32)
        assertNotNull(capturePcv3SafManifest(RecordingArchiveSession(maximumPath)))
        val excessiveDepth = List(128) { index ->
            Pcv3ArchiveEntryData("d", index.toLong() - 1L, true, 0)
        } + Pcv3ArchiveEntryData("leaf", 127, false, 0)
        assertNull(capturePcv3SafManifest(RecordingArchiveSession(excessiveDepth)))

        assertNotNull(
            capturePcv3SafManifest(
                RecordingArchiveSession(deepManifest(127, 4_000, 32)),
            ),
        )
        assertNull(
            capturePcv3SafManifest(
                RecordingArchiveSession(deepManifest(127, 4_100, 32)),
            ),
        )
    }

    @Test
    fun `manifest capture accepts the exact 65536 entry bound`() {
        val entries = List(65_536) { index ->
            Pcv3ArchiveEntryData("f$index", -1, isDirectory = false, size = 0)
        }

        val manifest = capturePcv3SafManifest(RecordingArchiveSession(entries))

        assertNotNull(manifest)
        assertEquals(65_536, manifest?.entries?.size)
    }

    private fun deepManifest(
        directoryCount: Int,
        leafCount: Int,
        leafLength: Int,
    ): List<Pcv3ArchiveEntryData> = buildList {
        repeat(directoryCount) { index ->
            add(Pcv3ArchiveEntryData("d".repeat(31), index.toLong() - 1L, true, 0))
        }
        repeat(leafCount) { index ->
            val suffix = index.toString(36)
            add(
                Pcv3ArchiveEntryData(
                    "_".repeat(leafLength - suffix.length) + suffix,
                    directoryCount.toLong() - 1L,
                    false,
                    0,
                ),
            )
        }
    }

    @Test
    fun `provider orders attempt before each single create and verifies identity before acknowledgement`() {
        val events = mutableListOf<String>()
        val root = opaqueUri("provider")
        val normalizedRoot = opaqueUri("provider")
        val directory = opaqueUri("provider")
        val file = opaqueUri("provider")
        val descriptor = RecordingOriginalDescriptor(events)
        val session = RecordingArchiveSession(
            entries = listOf(
                Pcv3ArchiveEntryData("folder", -1, isDirectory = true, size = 0),
                Pcv3ArchiveEntryData("file.bin", 0, isDirectory = false, size = 7),
            ),
            events = events,
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val platform = RecordingSafPlatform(
            events = events,
            creations = ArrayDeque(listOf(directory, file)),
            metadata = ArrayDeque(
                listOf(
                    exactMetadata("provider", "directory-id", "folder", PCV3_SAF_DIRECTORY_MIME),
                    exactMetadata("provider", "file-id", "file.bin", "application/x-provider-file"),
                ),
            ),
            descriptor = descriptor,
            normalizer = { normalizedRoot },
        )

        val result = Pcv3SafArchiveProvider(platform).publish(
            root = root,
            manifest = manifest,
            session = session,
            cancellation = RecordingSafCancellation(events),
        )

        assertEquals(Pcv3SafPublicationResult.READY_TO_FINISH, result)
        assertEquals(
            listOf(
                "normalize",
                "attempt:0",
                "create:folder:$PCV3_SAF_DIRECTORY_MIME",
                "query:0",
                "ack:0",
                "attempt:1",
                "create:file.bin:$PCV3_SAF_FILE_MIME",
                "query:1",
                "open:w",
                "dup",
                "detach",
                "write:1:73",
                "write-return",
                "original-close",
            ),
            events,
        )
        assertSame(normalizedRoot, platform.createdParents.first())
        assertFalse(descriptor.duplicate.closed)
    }

    @Test
    fun `invalid tree URI fails before Attempt and provider effects`() {
        val events = mutableListOf<String>()
        val session = RecordingArchiveSession(
            listOf(Pcv3ArchiveEntryData("name", -1, isDirectory = false, size = 1)),
            events,
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val platform = RecordingSafPlatform(events, normalizer = { null })

        val result = Pcv3SafArchiveProvider(platform).publish(
            opaqueUri("provider"),
            manifest,
            session,
            RecordingSafCancellation(events),
        )

        assertEquals(Pcv3SafPublicationResult.NEEDS_ABORT, result)
        assertEquals(listOf("normalize"), events)
        assertEquals(0, session.attemptCalls)
        assertEquals(0, platform.createCalls)
        assertEquals(0, platform.queryCalls)
        assertEquals(0, platform.openCalls)
    }

    @Test
    fun `cancellation signal releases a blocked metadata query before publication settles`() {
        val events = mutableListOf<String>()
        val session = RecordingArchiveSession(
            listOf(Pcv3ArchiveEntryData("name", -1, isDirectory = false, size = 1)),
            events,
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val queryEntered = CountDownLatch(1)
        val cancellation = RecordingSafCancellation(events)
        val platform = RecordingSafPlatform(
            events = events,
            creations = ArrayDeque(listOf(opaqueUri("provider"))),
            queryEntered = queryEntered,
            waitForQueryCancellation = true,
        )
        var result: Pcv3SafPublicationResult? = null
        val worker = thread(start = true) {
            result = Pcv3SafArchiveProvider(platform).publish(
                opaqueUri("provider"),
                manifest,
                session,
                cancellation,
            )
        }
        assertTrue(queryEntered.await(5, TimeUnit.SECONDS))

        cancellation.cancel()
        worker.join(5_000)

        assertFalse("query cancellation must settle the provider call", worker.isAlive)
        assertEquals(Pcv3SafPublicationResult.NEEDS_ABORT, result)
        assertEquals(1, platform.queryCalls)
        assertEquals(0, platform.openCalls)
        assertEquals(0, session.writeCalls)
    }

    @Test
    fun `production query receives the exact lifecycle owned cancellation signal`() {
        val resolver = mockk<ContentResolver>()
        val cursor = mockk<Cursor>()
        val capturedSignals = mutableListOf<CancellationSignal>()
        every {
            resolver.query(
                any<Uri>(),
                any<Array<String>>(),
                null,
                null,
                null,
                capture(capturedSignals),
            )
        } returns cursor
        every { cursor.close() } just Runs
        every { cursor.moveToFirst() } returns false
        val platform = AndroidPcv3SafPlatform(resolver)
        val lifecycleCancellation = platform.newCancellation() as AndroidPcv3SafCancellation
        val unrelatedCancellation = platform.newCancellation() as AndroidPcv3SafCancellation

        assertNull(platform.queryDocument(mockk(relaxed = true), lifecycleCancellation))
        assertEquals(1, capturedSignals.size)
        assertSame(lifecycleCancellation.signal, capturedSignals.single())
        assertFalse("a fresh signal must not be substituted", unrelatedCancellation.signal === capturedSignals.single())
    }

    @Test
    fun `production cursor boundary rejects zero and multiple metadata rows`() {
        listOf(false, true).forEach { hasMultipleRows ->
            val resolver = mockk<ContentResolver>()
            val cursor = mockk<Cursor>()
            every {
                resolver.query(
                    any<Uri>(),
                    any<Array<String>>(),
                    null,
                    null,
                    null,
                    any<CancellationSignal>(),
                )
            } returns cursor
            every { cursor.close() } just Runs
            every { cursor.moveToFirst() } returns hasMultipleRows
            if (hasMultipleRows) {
                every { cursor.getColumnIndex(any()) } returnsMany listOf(0, 1, 2)
                every { cursor.getString(0) } returns "id"
                every { cursor.getString(1) } returns "name"
                every { cursor.getString(2) } returns PCV3_SAF_FILE_MIME
                every { cursor.moveToNext() } returns true
            }
            val platform = AndroidPcv3SafPlatform(resolver)

            val metadata = platform.queryDocument(mockk(relaxed = true), platform.newCancellation())

            assertNull(if (hasMultipleRows) "multiple rows" else "zero rows", metadata)
        }
    }

    @Test
    fun `metadata uncertainty stops after one provider effect without retry delete or acknowledgement`() {
        data class Case(
            val name: String,
            val metadata: Pcv3SafDocumentMetadata?,
            val expectedQueries: Int = 1,
        )

        val cases = listOf(
            Case(
                "auto rename",
                exactMetadata("provider", "id", "name (1)", PCV3_SAF_FILE_MIME),
            ),
            Case(
                "wrong mime",
                exactMetadata("provider", "id", "name", PCV3_SAF_DIRECTORY_MIME),
            ),
            Case(
                "document id mismatch",
                exactMetadata("provider", "queried", "name", PCV3_SAF_FILE_MIME).copy(
                    uriDocumentId = "uri",
                ),
            ),
            Case(
                "authority mismatch",
                exactMetadata("foreign", "id", "name", PCV3_SAF_FILE_MIME),
                expectedQueries = 0,
            ),
            Case("missing row", null),
        )

        cases.forEach { case ->
            val events = mutableListOf<String>()
            val root = opaqueUri("provider")
            val created = opaqueUri("provider")
            val entries = listOf(
                Pcv3ArchiveEntryData("name", -1, isDirectory = false, size = 1),
                Pcv3ArchiveEntryData("later", -1, isDirectory = false, size = 1),
            )
            val session = RecordingArchiveSession(entries, events)
            val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
            val platform = RecordingSafPlatform(
                events = events,
                creations = ArrayDeque(listOf(created)),
                metadata = ArrayDeque(listOf(case.metadata)),
            )

            val result = Pcv3SafArchiveProvider(platform).publish(
                root,
                manifest,
                session,
                RecordingSafCancellation(events),
            )

            assertEquals(case.name, Pcv3SafPublicationResult.NEEDS_ABORT, result)
            assertEquals(case.name, 1, platform.createCalls)
            assertEquals(case.name, case.expectedQueries, platform.queryCalls)
            assertEquals(case.name, 0, platform.openCalls)
            assertEquals(case.name, 0, session.ackCalls)
            assertEquals(case.name, 0, session.writeCalls)
            assertFalse(case.name, events.any { it.startsWith("create:later") })
        }
    }

    @Test
    fun `duplicate provider identities fail before a second directory acknowledgement`() {
        val events = mutableListOf<String>()
        val root = opaqueUri("provider")
        val first = opaqueUri("provider")
        val second = opaqueUri("provider")
        val session = RecordingArchiveSession(
            listOf(
                Pcv3ArchiveEntryData("one", -1, isDirectory = true, size = 0),
                Pcv3ArchiveEntryData("two", -1, isDirectory = true, size = 0),
            ),
            events,
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val platform = RecordingSafPlatform(
            events,
            ArrayDeque(listOf(first, second)),
            ArrayDeque(
                listOf(
                    exactMetadata("provider", "same-id", "one", PCV3_SAF_DIRECTORY_MIME),
                    exactMetadata("provider", "same-id", "two", PCV3_SAF_DIRECTORY_MIME),
                ),
            ),
        )

        val result = Pcv3SafArchiveProvider(platform).publish(
            root,
            manifest,
            session,
            RecordingSafCancellation(events),
        )

        assertEquals(Pcv3SafPublicationResult.NEEDS_ABORT, result)
        assertEquals(2, platform.createCalls)
        assertEquals(1, platform.queryCalls)
        assertEquals(1, session.ackCalls)
    }

    @Test
    fun `created root identity is rejected before metadata query`() {
        val events = mutableListOf<String>()
        val session = RecordingArchiveSession(
            listOf(Pcv3ArchiveEntryData("directory", -1, isDirectory = true, size = 0)),
            events,
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val rootIdentity = Pcv3SafDocumentIdentity("provider", "root-id")
        val platform = RecordingSafPlatform(
            events = events,
            creations = ArrayDeque(listOf(opaqueUri("provider"))),
            identityOverride = { _, _ -> rootIdentity },
        )

        val result = Pcv3SafArchiveProvider(platform).publish(
            opaqueUri("provider"),
            manifest,
            session,
            RecordingSafCancellation(events),
        )

        assertEquals(Pcv3SafPublicationResult.NEEDS_ABORT, result)
        assertEquals(1, platform.createCalls)
        assertEquals(0, platform.queryCalls)
        assertEquals(0, session.ackCalls)
    }

    @Test
    fun `rejected attempt produces zero provider calls`() {
        val events = mutableListOf<String>()
        val session = RecordingArchiveSession(
            entries = listOf(Pcv3ArchiveEntryData("name", -1, isDirectory = false, size = 1)),
            events = events,
            attemptResult = Pcv3ArchiveStepData("rejected", -1),
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val platform = RecordingSafPlatform(events)

        val result = Pcv3SafArchiveProvider(platform).publish(
            opaqueUri("provider"),
            manifest,
            session,
            RecordingSafCancellation(events),
        )

        assertEquals(Pcv3SafPublicationResult.NEEDS_ABORT, result)
        assertEquals(listOf("normalize", "attempt:0"), events)
        assertEquals(0, platform.createCalls)
    }

    @Test
    fun `detached descriptor is never closed by Kotlin when native write fails`() {
        val events = mutableListOf<String>()
        val session = RecordingArchiveSession(
            entries = listOf(Pcv3ArchiveEntryData("name", -1, isDirectory = false, size = 1)),
            events = events,
            writeResult = Pcv3ArchiveStepData("poisoned", -1),
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val descriptor = RecordingOriginalDescriptor(events)
        val platform = RecordingSafPlatform(
            events = events,
            creations = ArrayDeque(listOf(opaqueUri("provider"))),
            metadata = ArrayDeque(
                listOf(exactMetadata("provider", "id", "name", PCV3_SAF_FILE_MIME)),
            ),
            descriptor = descriptor,
        )

        val result = Pcv3SafArchiveProvider(platform).publish(
            opaqueUri("provider"),
            manifest,
            session,
            RecordingSafCancellation(events),
        )

        assertEquals(Pcv3SafPublicationResult.NEEDS_ABORT, result)
        assertFalse("detached raw FD belongs to Go even on an ambiguous return", descriptor.duplicate.closed)
        assertEquals(0, descriptor.closeCalls)
        assertEquals(1, descriptor.closeWithErrorCalls)
        assertTrue(events.contains("write:0:73"))
        assertTrue(events.contains("original-close-error:$PCV3_SAF_FIXED_WRITE_ERROR"))
    }

    @Test
    fun `descriptor duplication detach and close failures all fail closed`() {
        data class Case(
            val name: String,
            val descriptor: (MutableList<String>) -> RecordingOriginalDescriptor,
            val writeResult: Pcv3ArchiveStepData = Pcv3ArchiveStepData("ready", 1),
            val expectedWriteCalls: Int,
            val expectedOriginalCloseCalls: Int,
            val expectedCloseWithErrorCalls: Int,
            val expectedDuplicateCloseCalls: Int,
            val detached: Boolean,
        )
        val cases = listOf(
            Case(
                "duplicate",
                { RecordingOriginalDescriptor(it, duplicateFailure = IllegalStateException("dup")) },
                expectedWriteCalls = 0,
                expectedOriginalCloseCalls = 0,
                expectedCloseWithErrorCalls = 1,
                expectedDuplicateCloseCalls = 0,
                detached = false,
            ),
            Case(
                "detach",
                { RecordingOriginalDescriptor(it, detachFailure = IllegalStateException("detach")) },
                expectedWriteCalls = 0,
                expectedOriginalCloseCalls = 0,
                expectedCloseWithErrorCalls = 1,
                expectedDuplicateCloseCalls = 1,
                detached = false,
            ),
            Case(
                "normal close",
                { RecordingOriginalDescriptor(it, closeFailure = IllegalStateException("close")) },
                expectedWriteCalls = 1,
                expectedOriginalCloseCalls = 1,
                expectedCloseWithErrorCalls = 0,
                expectedDuplicateCloseCalls = 0,
                detached = true,
            ),
            Case(
                "close with error",
                { RecordingOriginalDescriptor(it, closeWithErrorFailure = IllegalStateException("close error")) },
                writeResult = Pcv3ArchiveStepData("poisoned", -1),
                expectedWriteCalls = 1,
                expectedOriginalCloseCalls = 0,
                expectedCloseWithErrorCalls = 1,
                expectedDuplicateCloseCalls = 0,
                detached = true,
            ),
        )

        cases.forEach { case ->
            val events = mutableListOf<String>()
            val session = RecordingArchiveSession(
                entries = listOf(Pcv3ArchiveEntryData("file", -1, false, 1)),
                events = events,
                writeResult = case.writeResult,
            )
            val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
            val descriptor = case.descriptor(events)
            val platform = RecordingSafPlatform(
                events = events,
                creations = ArrayDeque(listOf(opaqueUri("provider"))),
                metadata = ArrayDeque(listOf(exactMetadata("provider", "id", "file", PCV3_SAF_FILE_MIME))),
                descriptor = descriptor,
            )

            val result = Pcv3SafArchiveProvider(platform).publish(
                opaqueUri("provider"),
                manifest,
                session,
                RecordingSafCancellation(events),
            )

            assertEquals(case.name, Pcv3SafPublicationResult.NEEDS_ABORT, result)
            assertEquals("${case.name}: one Attempt", 1, session.attemptCalls)
            assertEquals("${case.name}: no create retry", 1, platform.createCalls)
            assertEquals("${case.name}: no query retry", 1, platform.queryCalls)
            assertEquals("${case.name}: no open retry", 1, platform.openCalls)
            assertEquals("${case.name}: native write ownership", case.expectedWriteCalls, session.writeCalls)
            assertEquals(
                "${case.name}: exact normal close ownership",
                case.expectedOriginalCloseCalls,
                descriptor.closeCalls,
            )
            assertEquals(
                "${case.name}: exact error close ownership",
                case.expectedCloseWithErrorCalls,
                descriptor.closeWithErrorCalls,
            )
            assertEquals(
                "${case.name}: exact duplicate close ownership",
                case.expectedDuplicateCloseCalls,
                descriptor.duplicate.closeCalls,
            )
            if (case.detached) {
                assertEquals("${case.name}: Kotlin must never close after detach", 0, descriptor.duplicate.closeCalls)
            }
        }
    }

    @Test
    fun `zero byte file still opens writes and closes its provider descriptor`() {
        val events = mutableListOf<String>()
        val session = RecordingArchiveSession(
            listOf(Pcv3ArchiveEntryData("empty", -1, false, 0)),
            events,
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val descriptor = RecordingOriginalDescriptor(events)
        val platform = RecordingSafPlatform(
            events = events,
            creations = ArrayDeque(listOf(opaqueUri("provider"))),
            metadata = ArrayDeque(listOf(exactMetadata("provider", "empty-id", "empty", "application/x-empty"))),
            descriptor = descriptor,
        )

        val result = Pcv3SafArchiveProvider(platform).publish(
            opaqueUri("provider"),
            manifest,
            session,
            RecordingSafCancellation(events),
        )

        assertEquals(Pcv3SafPublicationResult.READY_TO_FINISH, result)
        assertEquals(1, platform.openCalls)
        assertEquals(1, session.writeCalls)
        assertEquals(1, descriptor.closeCalls)
    }

    @Test
    fun `null provider descriptor stops after one open without native write`() {
        val events = mutableListOf<String>()
        val session = RecordingArchiveSession(
            entries = listOf(Pcv3ArchiveEntryData("name", -1, isDirectory = false, size = 1)),
            events = events,
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val platform = RecordingSafPlatform(
            events = events,
            creations = ArrayDeque(listOf(opaqueUri("provider"))),
            metadata = ArrayDeque(
                listOf(exactMetadata("provider", "id", "name", PCV3_SAF_FILE_MIME)),
            ),
            descriptor = null,
        )

        val result = Pcv3SafArchiveProvider(platform).publish(
            opaqueUri("provider"),
            manifest,
            session,
            RecordingSafCancellation(events),
        )

        assertEquals(Pcv3SafPublicationResult.NEEDS_ABORT, result)
        assertEquals(1, platform.openCalls)
        assertEquals(0, session.writeCalls)
    }

    @Test
    fun `JNI linkage ambiguity after detach never reclaims raw descriptor`() {
        val events = mutableListOf<String>()
        val session = RecordingArchiveSession(
            entries = listOf(Pcv3ArchiveEntryData("name", -1, isDirectory = false, size = 1)),
            events = events,
            writeFailure = NoSuchMethodError("stale test ABI"),
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val descriptor = RecordingOriginalDescriptor(events)
        val platform = RecordingSafPlatform(
            events = events,
            creations = ArrayDeque(listOf(opaqueUri("provider"))),
            metadata = ArrayDeque(
                listOf(exactMetadata("provider", "id", "name", PCV3_SAF_FILE_MIME)),
            ),
            descriptor = descriptor,
        )

        val result = Pcv3SafArchiveProvider(platform).publish(
            opaqueUri("provider"),
            manifest,
            session,
            RecordingSafCancellation(events),
        )

        assertEquals(Pcv3SafPublicationResult.NEEDS_ABORT, result)
        assertFalse("ownership may already have crossed JNI", descriptor.duplicate.closed)
        assertEquals(1, descriptor.closeWithErrorCalls)
    }

    @Test
    fun `cancellation during native write remains externally interruptible and returns abort ownership`() {
        val events = mutableListOf<String>()
        val writeEntered = CountDownLatch(1)
        val allowWriteReturn = CountDownLatch(1)
        val session = RecordingArchiveSession(
            entries = listOf(Pcv3ArchiveEntryData("name", -1, isDirectory = false, size = 1)),
            events = events,
            writeEntered = writeEntered,
            allowWriteReturn = allowWriteReturn,
            writeResult = Pcv3ArchiveStepData("poisoned", -1),
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val cancellation = RecordingSafCancellation(events)
        val platform = RecordingSafPlatform(
            events = events,
            creations = ArrayDeque(listOf(opaqueUri("provider"))),
            metadata = ArrayDeque(
                listOf(exactMetadata("provider", "id", "name", PCV3_SAF_FILE_MIME)),
            ),
            descriptor = RecordingOriginalDescriptor(events),
        )
        var result: Pcv3SafPublicationResult? = null
        val publisher = thread(start = true, name = "pcv3-saf-provider-test") {
            result = Pcv3SafArchiveProvider(platform).publish(
                opaqueUri("provider"),
                manifest,
                session,
                cancellation,
            )
        }

        assertTrue(writeEntered.await(5, TimeUnit.SECONDS))
        cancellation.cancel()
        session.cancel()
        allowWriteReturn.countDown()
        publisher.join(5_000)

        assertFalse("provider call must settle after the exact native writer is cancelled", publisher.isAlive)
        assertEquals(Pcv3SafPublicationResult.NEEDS_ABORT, result)
        assertEquals(1, cancellation.cancelCalls)
        assertEquals(1, session.cancelCalls)
        assertTrue(events.indexOf("cancel") < events.indexOf("write-return"))
    }

    @Test
    fun `URI values are passed opaquely without string path or log conversion`() {
        val events = mutableListOf<String>()
        val root = opaqueUri("provider", rejectStringConversion = true)
        val created = opaqueUri("provider", rejectStringConversion = true)
        val session = RecordingArchiveSession(
            listOf(Pcv3ArchiveEntryData("directory", -1, isDirectory = true, size = 0)),
            events,
        )
        val manifest = requireNotNull(capturePcv3SafManifest(session)).also { events.clear() }
        val platform = RecordingSafPlatform(
            events,
            ArrayDeque(listOf(created)),
            ArrayDeque(
                listOf(exactMetadata("provider", "id", "directory", PCV3_SAF_DIRECTORY_MIME)),
            ),
        )

        val result = Pcv3SafArchiveProvider(platform).publish(
            root,
            manifest,
            session,
            RecordingSafCancellation(events),
        )

        assertEquals(Pcv3SafPublicationResult.READY_TO_FINISH, result)
    }

    private fun opaqueUri(authority: String, rejectStringConversion: Boolean = false): Uri =
        mockk<Uri>().also { uri ->
            every { uri.authority } returns authority
            if (rejectStringConversion) {
                every { uri.toString() } throws AssertionError("URI string conversion")
                every { uri.path } throws AssertionError("URI path conversion")
            }
        }

    private fun exactMetadata(
        authority: String,
        id: String,
        displayName: String,
        mimeType: String,
    ) = Pcv3SafDocumentMetadata(
        authority = authority,
        queriedDocumentId = id,
        uriDocumentId = id,
        displayName = displayName,
        mimeType = mimeType,
    )

    private class RecordingArchiveSession(
        private val entries: List<Pcv3ArchiveEntryData>,
        private val events: MutableList<String> = mutableListOf(),
        private val attemptResult: Pcv3ArchiveStepData? = null,
        private val writeResult: Pcv3ArchiveStepData? = null,
        private val writeEntered: CountDownLatch? = null,
        private val allowWriteReturn: CountDownLatch? = null,
        private val writeFailure: Throwable? = null,
    ) : Pcv3ArchiveSessionCapability, Pcv3SafEntrySession {
        var attemptCalls = 0
            private set
        var ackCalls = 0
            private set
        var writeCalls = 0
            private set
        var cancelCalls = 0
            private set

        override fun entryCount(): Long {
            events += "entry-count"
            return entries.size.toLong()
        }

        override fun entry(index: Long): Pcv3ArchiveEntryData? {
            events += "entry:$index"
            return entries.getOrNull(index.toInt())
        }

        override fun confirmCrashReceiptPersisted(receipt: String) =
            Pcv3ArchiveStepData("ready", 0)

        override fun attempt(index: Long): Pcv3ArchiveStepData {
            attemptCalls += 1
            events += "attempt:$index"
            return attemptResult ?: Pcv3ArchiveStepData("attempted", index)
        }

        override fun ackDirectory(index: Long): Pcv3ArchiveStepData {
            ackCalls += 1
            events += "ack:$index"
            return Pcv3ArchiveStepData("ready", index + 1)
        }

        override fun writeFd(index: Long, descriptor: Long): Pcv3ArchiveStepData {
            writeCalls += 1
            events += "write:$index:$descriptor"
            writeEntered?.countDown()
            allowWriteReturn?.await(5, TimeUnit.SECONDS)
            events += "write-return"
            writeFailure?.let { throw it }
            return writeResult ?: Pcv3ArchiveStepData("ready", index + 1)
        }

        override fun cancel(): Pcv3ArchiveStepData {
            cancelCalls += 1
            events += "cancel"
            return Pcv3ArchiveStepData("poisoned", -1)
        }

        override fun finish(): Pcv3SnapshotData = error("provider must not own Finish")

        override fun abort(): Pcv3SnapshotData = error("provider must not own Abort")
    }

    private class CountOnlySession(
        private val count: Long,
    ) : Pcv3ArchiveSessionCapability {
        override fun entryCount(): Long = count
        override fun entry(index: Long): Pcv3ArchiveEntryData? = error("out-of-range count must fail before Entry")
        override fun confirmCrashReceiptPersisted(receipt: String) = Pcv3ArchiveStepData("rejected", -1)
        override fun attempt(index: Long) = Pcv3ArchiveStepData("rejected", -1)
        override fun ackDirectory(index: Long) = Pcv3ArchiveStepData("rejected", -1)
        override fun writeFd(index: Long, descriptor: Long) = Pcv3ArchiveStepData("rejected", -1)
        override fun cancel() = Pcv3ArchiveStepData("rejected", -1)
        override fun finish(): Pcv3SnapshotData = error("not used")
        override fun abort(): Pcv3SnapshotData = error("not used")
    }

    private class RecordingSafCancellation(
        private val events: MutableList<String>,
    ) : Pcv3SafCancellation {
        private val cancellation = CountDownLatch(1)
        @Volatile
        private var cancelled = false
        var cancelCalls = 0
            private set

        override fun isCancelled(): Boolean = cancelled

        override fun cancel() {
            cancelCalls += 1
            cancelled = true
            events += "provider-cancel"
            cancellation.countDown()
        }

        fun awaitCancellation(): Boolean = cancellation.await(5, TimeUnit.SECONDS)
    }

    private class RecordingSafPlatform(
        private val events: MutableList<String>,
        private val creations: ArrayDeque<Uri> = ArrayDeque(),
        private val metadata: ArrayDeque<Pcv3SafDocumentMetadata?> = ArrayDeque(),
        private val descriptor: RecordingOriginalDescriptor? = null,
        private val normalizer: (Uri) -> Uri? = { it },
        private val queryEntered: CountDownLatch? = null,
        private val waitForQueryCancellation: Boolean = false,
        private val identityOverride: ((Uri, Int) -> Pcv3SafDocumentIdentity?)? = null,
    ) : Pcv3SafPlatform {
        private var identityCalls = 0
        var createCalls = 0
            private set
        var queryCalls = 0
            private set
        var openCalls = 0
            private set
        val createdParents = mutableListOf<Uri>()

        override fun newCancellation(): Pcv3SafCancellation = RecordingSafCancellation(events)

        override fun normalizeTreeRoot(tree: Uri): Uri? {
            events += "normalize"
            return normalizer(tree)
        }

        override fun documentIdentity(document: Uri): Pcv3SafDocumentIdentity? {
            val call = identityCalls++
            identityOverride?.let { return it(document, call) }
            if (call == 0) return Pcv3SafDocumentIdentity("provider", "root-id")
            val next = metadata.firstOrNull()
            return if (next != null) {
                val authority = next.authority ?: return null
                val id = next.uriDocumentId ?: return null
                Pcv3SafDocumentIdentity(authority, id)
            } else {
                Pcv3SafDocumentIdentity("provider", "created-$call")
            }
        }

        override fun createDocument(parent: Uri, mimeType: String, displayName: String): Uri? {
            createCalls += 1
            createdParents += parent
            events += "create:$displayName:$mimeType"
            return if (creations.isEmpty()) null else creations.removeFirst()
        }

        override fun queryDocument(
            document: Uri,
            cancellation: Pcv3SafCancellation,
        ): Pcv3SafDocumentMetadata? {
            queryCalls += 1
            events += "query:${queryCalls - 1}"
            queryEntered?.countDown()
            if (waitForQueryCancellation) {
                (cancellation as? RecordingSafCancellation)?.awaitCancellation()
                    ?: return null
            }
            return if (metadata.isEmpty()) null else metadata.removeFirst()
        }

        override fun openDocument(
            document: Uri,
            mode: String,
            cancellation: Pcv3SafCancellation,
        ): Pcv3SafOriginalDescriptor? {
            openCalls += 1
            events += "open:$mode"
            return descriptor
        }
    }

    private class RecordingOriginalDescriptor(
        private val events: MutableList<String>,
        private val duplicateFailure: Throwable? = null,
        detachFailure: Throwable? = null,
        private val closeFailure: Throwable? = null,
        private val closeWithErrorFailure: Throwable? = null,
    ) : Pcv3SafOriginalDescriptor {
        val duplicate = RecordingDuplicateDescriptor(events, detachFailure)
        var closeCalls = 0
            private set
        var closeWithErrorCalls = 0
            private set

        override fun duplicate(): Pcv3SafDuplicateDescriptor {
            events += "dup"
            duplicateFailure?.let { throw it }
            return duplicate
        }

        override fun close() {
            closeCalls += 1
            events += "original-close"
            closeFailure?.let { throw it }
        }

        override fun closeWithError(message: String) {
            closeWithErrorCalls += 1
            events += "original-close-error:$message"
            closeWithErrorFailure?.let { throw it }
        }
    }

    private class RecordingDuplicateDescriptor(
        private val events: MutableList<String>,
        private val detachFailure: Throwable? = null,
    ) : Pcv3SafDuplicateDescriptor {
        var closed = false
            private set
        var closeCalls = 0
            private set

        override fun detachFd(): Int {
            events += "detach"
            detachFailure?.let { throw it }
            return 73
        }

        override fun close() {
            closeCalls += 1
            closed = true
            events += "duplicate-close"
        }
    }
}
