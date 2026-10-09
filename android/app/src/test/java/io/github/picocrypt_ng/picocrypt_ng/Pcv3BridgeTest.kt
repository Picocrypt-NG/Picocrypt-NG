package io.github.picocrypt_ng.picocrypt_ng

import android.os.ParcelFileDescriptor
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.verify
import java.io.IOException
import kotlin.coroutines.cancellation.CancellationException
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** JVM contracts at the Kotlin-owned PCV3 transport boundary. */
class Pcv3BridgeTest {
    @Test
    fun `journal cleanup wrapper accepts only closed native states and calls once`() {
        listOf(
            "absent" to Pcv3JournalCleanupState.ABSENT,
            "cleaned" to Pcv3JournalCleanupState.CLEANED,
            "incomplete" to Pcv3JournalCleanupState.INCOMPLETE,
            "future" to Pcv3JournalCleanupState.INCOMPLETE,
            "" to Pcv3JournalCleanupState.INCOMPLETE,
        ).forEach { (nativeState, expected) ->
            var calls = 0
            val path = "/data/user/0/app/files/picocrypt_files"

            val actual = cleanupPcv3Journal(path, Pcv3JournalCleanupNative { received ->
                calls++
                assertEquals(path, received)
                nativeState
            })

            assertEquals(expected, actual)
            assertEquals(1, calls)
        }
        assertEquals(
            Pcv3JournalCleanupState.INCOMPLETE,
            cleanupPcv3Journal("/private", Pcv3JournalCleanupNative { throw IOException("raw path detail") }),
        )
        assertEquals(
            Pcv3JournalCleanupState.INCOMPLETE,
            cleanupPcv3Journal("/private", Pcv3JournalCleanupNative { throw NoSuchMethodError("stale AAR") }),
        )
    }

    @Test
    fun `journal cleanup wrapper preserves cancellation identity`() {
        val cancellation = CancellationException("startup journal cleanup cancelled")

        try {
            cleanupPcv3Journal(
                "/data/user/0/app/files/picocrypt_files",
                Pcv3JournalCleanupNative { throw cancellation },
            )
            fail("Cancellation must reach the startup owner")
        } catch (actual: CancellationException) {
            assertSame(cancellation, actual)
        }
    }

    @Test
    fun `Android PCV3 presentation policy accepts only the closed configured state`() {
        assertEquals(
            Pcv3AndroidPolicyState.CONFIGURED,
            readPcv3AndroidPolicyState { "configured" },
        )
        listOf("unconfigured", "future-state", "").forEach { raw ->
            assertEquals(
                "raw state $raw must not activate Android PCV3 controls",
                Pcv3AndroidPolicyState.UNCONFIGURED,
                readPcv3AndroidPolicyState { raw },
            )
        }
        assertEquals(
            Pcv3AndroidPolicyState.UNCONFIGURED,
            readPcv3AndroidPolicyState { throw IllegalStateException("native failure") },
        )
        assertEquals(
            Pcv3AndroidPolicyState.UNCONFIGURED,
            readPcv3AndroidPolicyState { throw NoSuchMethodError("stale AAR") },
        )
    }

    @Test
    fun `PCV3 route codes remain closed and distinguish normal from refused claims`() {
        assertEquals(Pcv3Route.LEGACY, GoBridge.parsePcv3Route("legacy"))
        assertEquals(Pcv3Route.NORMAL, GoBridge.parsePcv3Route("normal"))
        assertEquals(Pcv3Route.UNSUPPORTED, GoBridge.parsePcv3Route("unsupported"))
        assertEquals(Pcv3Route.INVALID, GoBridge.parsePcv3Route("invalid"))

        val unknown = runCatching { GoBridge.parsePcv3Route("future-route") }
        assertTrue("unknown native route must fail closed", unknown.isFailure)
    }

    @Test
    fun `PCV3 request is a strict non-secret envelope`() {
        val request = validRequest()

        val json = JSONObject(GoBridge.buildPcv3RequestJson(request))

        assertEquals(1, json.getInt("version"))
        assertEquals("read-normal", json.getString("mode"))
        assertEquals("password", json.getString("factorPolicy"))
        assertEquals("none", json.getString("keyfileOrder"))
        assertEquals("input", json.getString("source"))
        assertEquals("output", json.getString("target"))
        assertEquals(0, json.getJSONArray("keyfiles").length())
        assertFalse("password must never enter the request JSON", json.has("password"))
        assertFalse("native capability state must not become request authority", json.has("archivePending"))
    }

    @Test
    fun `PCV3 write request is a strict write-shaped non-secret envelope`() {
        val request = validWriteRequest()

        val json = JSONObject(GoBridge.buildPcv3WriteRequestJson(request)!!)

        assertEquals(
            setOf(
                "version", "mode", "factorPolicy", "keyfileOrder",
                "source", "target", "keyfiles", "comment", "suite", "payloadRS",
                "inputFiles", "onlyFiles", "onlyFolders", "compress",
            ),
            json.names()!!.let { names -> (0 until names.length()).map(names::getString).toSet() },
        )
        assertEquals(1, json.getInt("version"))
        assertEquals("write-normal", json.getString("mode"))
        assertEquals("password", json.getString("factorPolicy"))
        assertEquals("none", json.getString("keyfileOrder"))
        assertEquals("input", json.getString("source"))
        assertEquals("output", json.getString("target"))
        assertEquals(0, json.getJSONArray("keyfiles").length())
        assertEquals("plaintext comment", json.getString("comment"))
        assertEquals("standard", json.getString("suite"))
        assertFalse(json.getBoolean("payloadRS"))
        assertFalse("password must never enter the request JSON", json.has("password"))
    }

    @Test
    fun `PCV3 write envelope admits the exact keyfile and D1 shapes`() {
        val withKeyfiles = validWriteRequest().copy(
            factorPolicy = "password-and-keyfiles",
            keyfileOrder = "ordered",
            keyfiles = listOf("keyfile-a", "keyfile-b"),
        )
        val keyfileJson = JSONObject(GoBridge.buildPcv3WriteRequestJson(withKeyfiles)!!)
        assertEquals("ordered", keyfileJson.getString("keyfileOrder"))
        assertEquals(2, keyfileJson.getJSONArray("keyfiles").length())

        val d1 = validWriteRequest().copy(mode = "write-d1", suite = "paranoid", comment = "")
        val d1Json = JSONObject(GoBridge.buildPcv3WriteRequestJson(d1)!!)
        assertEquals("write-d1", d1Json.getString("mode"))
        assertEquals("paranoid", d1Json.getString("suite"))

        // The comment bound mirrors header.MaxCommentLen and is counted in UTF-8 bytes.
        val atCommentBound = validWriteRequest().copy(comment = "x".repeat(99999))
        assertTrue(GoBridge.buildPcv3WriteRequestJson(atCommentBound) != null)
    }

    @Test
    fun `PCV3 write envelope refuses every wrong shape before the native boundary`() {
        listOf(
            "unknown mode" to validWriteRequest().copy(mode = "migrate-normal"),
            "read shape is not a write shape" to validWriteRequest().copy(mode = "read-normal"),
            "unknown suite" to validWriteRequest().copy(suite = "future"),
            "D1 has no standard suite choice" to validWriteRequest().copy(mode = "write-d1", suite = "standard"),
            "password policy has no keyfile order" to validWriteRequest().copy(keyfileOrder = "ordered"),
            "password policy has no keyfiles" to validWriteRequest().copy(keyfiles = listOf("keyfile-a")),
            "keyfile policy needs keyfiles" to validWriteRequest().copy(factorPolicy = "keyfiles", keyfileOrder = "ordered"),
            "keyfile policy needs an order" to validWriteRequest().copy(factorPolicy = "keyfiles", keyfiles = listOf("keyfile-a")),
            "keyfile count is bounded" to validWriteRequest().copy(
                factorPolicy = "keyfiles",
                keyfileOrder = "unordered",
                keyfiles = (1..65).map { "keyfile-$it" },
            ),
            "blank source" to validWriteRequest().copy(source = " "),
            "blank target" to validWriteRequest().copy(target = ""),
            "blank keyfile" to validWriteRequest().copy(
                factorPolicy = "keyfiles",
                keyfileOrder = "ordered",
                keyfiles = listOf(""),
            ),
            "oversized comment" to validWriteRequest().copy(comment = "x".repeat(100000)),
        ).forEach { (label, request) ->
            assertNull(
                "$label must be refused locally as PCV3_BRIDGE_INVALID_REQUEST",
                GoBridge.buildPcv3WriteRequestJson(request),
            )
        }
    }

    @Test
    fun `PCV3 locally refused write envelope clears caller password before transport`() {
        val transport = RecordingTransport { _, _ ->
            error("a locally refused write envelope must not reach the native transport")
        }
        val callerPassword = "sensitive".toCharArray()
        val invalid = validWriteRequest().copy(suite = "future")

        val result = Pcv3Bridge(transport).start(invalid, callerPassword)

        assertTrue(result.isFailure)
        assertEquals("PCV3_BRIDGE_INVALID_REQUEST", result.exceptionOrNull()?.message)
        assertEquals(0, transport.startCalls)
        assertTrue(callerPassword.all { it == '\u0000' })
    }

    @Test
    fun `PCV3 bridge clears caller chars and UTF8 bytes after native refusal`() {
        val transport = RecordingTransport { _, _ -> Pcv3StartData("PCV3_BRIDGE_INPUT_UNAVAILABLE", null) }
        val callerPassword = "sensitive".toCharArray()

        val result = Pcv3Bridge(transport).start(validRequest(), callerPassword)

        assertTrue(result.isSuccess)
        assertEquals("PCV3_BRIDGE_INPUT_UNAVAILABLE", result.getOrThrow().code)
        assertTrue("the caller-owned CharArray is zeroed on every exit", callerPassword.all { it == '\u0000' })
        assertTrue("the bridge-owned UTF-8 bytes are zeroed on every exit", transport.observedPassword!!.all { it == 0.toByte() })
    }

    @Test
    fun `PCV3 encodes the complete large password before the native size refusal and wipes both owners`() {
        var encodedSize = 0
        var encodedTail = ByteArray(0)
        val transport = RecordingTransport { _, password ->
            encodedSize = password.size
            encodedTail = password.takeLast(3).toByteArray()
            Pcv3StartData("PCV3_BRIDGE_INVALID_REQUEST", null)
        }
        val callerPassword = CharArray(5_592_407) { '\u0800' }.also { it[it.lastIndex] = '\u0801' }
        val result = Pcv3Bridge(transport).start(validRequest(), callerPassword)
        assertEquals("PCV3_BRIDGE_INVALID_REQUEST", result.getOrThrow().code)
        assertEquals(16_777_221, encodedSize)
        assertArrayEquals(byteArrayOf(0xe0.toByte(), 0xa0.toByte(), 0x81.toByte()), encodedTail)
        assertTrue(callerPassword.all { it == '\u0000' })
        assertTrue(transport.observedPassword!!.all { it == 0.toByte() })
    }

    @Test
    fun `PCV3 malformed UTF16 is refused before transport and clears caller chars`() {
        val transport = RecordingTransport { _, _ ->
            error("malformed UTF-16 must not reach the native transport")
        }
        val callerPassword = charArrayOf('\uD800')

        val result = Pcv3Bridge(transport).start(validRequest(), callerPassword)

        assertTrue(result.isFailure)
        assertEquals("PCV3_BRIDGE_INVALID_REQUEST", result.exceptionOrNull()?.message)
        assertEquals(0, transport.startCalls)
        assertTrue(callerPassword.all { it == '\u0000' })
    }

    @Test
    fun `PCV3 transport exception clears both password buffers and hides diagnostics`() {
        val transport = RecordingTransport { _, _ -> throw IllegalStateException("unbounded native diagnostic") }
        val callerPassword = "sensitive".toCharArray()

        val result = Pcv3Bridge(transport).start(validRequest(), callerPassword)

        assertTrue(result.isFailure)
        assertEquals("PCV3_BRIDGE_FAILURE", result.exceptionOrNull()?.message)
        assertTrue(callerPassword.all { it == '\u0000' })
        assertTrue(transport.observedPassword!!.all { it == 0.toByte() })
    }

    @Test
    fun `PCV3 nonempty start code retains returned handle for lifecycle drain`() {
        val operation = TestOperation("retained-operation")
        val transport = RecordingTransport { _, _ ->
            Pcv3StartData("PCV3_BRIDGE_INPUT_UNAVAILABLE", operation)
        }

        val result = Pcv3Bridge(transport).start(validRequest(), "password".toCharArray())

        assertEquals("PCV3_BRIDGE_INPUT_UNAVAILABLE", result.getOrThrow().code)
        assertSame("a code does not authorize Kotlin to discard a native operation", operation, result.getOrThrow().operation)
    }

    @Test
    fun `PCV3 archive wrapper exposes only closed SAF begin and close capabilities`() {
        val session = mockk<Pcv3ArchiveSessionCapability>()
        val active = mockk<Pcv3SnapshotData>()
        val terminal = mockk<Pcv3SnapshotData>()
        val begin = Pcv3ArchiveBeginData("session", "", session, active)
        var beginCalls = 0
        var closeCalls = 0
        val archive = GoPcv3Archive(object : Pcv3ArchiveNative {
            override fun cancelPreparation() = Unit
            override fun beginSaf(): Pcv3ArchiveBeginData {
                beginCalls += 1
                return begin
            }

            override fun close(): Pcv3SnapshotData {
                closeCalls += 1
                return terminal
            }
        })

        assertSame(begin, archive.beginSaf())
        assertSame(terminal, archive.close())
        assertEquals(1, beginCalls)
        assertEquals(1, closeCalls)
    }

    @Test
    fun `gomobile SAF begin projection retains the prepared session when a later field fails`() {
        val session = mockk<Pcv3ArchiveSessionCapability>()
        val calls = mutableListOf<String>()

        val begin = projectPcv3ArchiveBegin(
            capturedSession = session,
            kind = {
                calls += "kind"
                "session"
            },
            code = {
                calls += "code"
                ""
            },
            snapshot = {
                calls += "snapshot"
                throw NoSuchMethodError("stale snapshot projection")
            },
        )

        assertFalse("projection failure must not retain an actionable kind", begin.kind in setOf("session", "terminal"))
        assertEquals("PCV3_ARCHIVE_UNAVAILABLE", begin.code)
        assertSame("the lifecycle must retain authority to Cancel and Abort", session, begin.session)
        assertNull(begin.snapshot)
        assertEquals(listOf("kind", "code", "snapshot"), calls)
    }

    @Test
    fun `PCV3 output save detaches once before native entry and projects only the closed result`() {
        val destination = mockk<ParcelFileDescriptor>()
        val events = mutableListOf<String>()
        val native = RecordingOutputNative(
            onSave = { descriptor ->
                events += "save:$descriptor"
                Pcv3OutputResultData("saved-cleanup-incomplete", cleanupIncomplete = true)
            },
        )
        every { destination.detachFd() } answers {
            events += "detach"
            43
        }

        val result = GoPcv3Output(native).save(destination)

        assertEquals(Pcv3OutputResultData("saved-cleanup-incomplete", cleanupIncomplete = true), result)
        assertEquals(listOf("detach", "save:43"), events)
        verify(exactly = 1) { destination.detachFd() }
        verify(exactly = 0) { destination.close() }
    }

    @Test
    fun `PCV3 output save closes an attached descriptor when detach fails before native entry`() {
        val destination = mockk<ParcelFileDescriptor>()
        val native = RecordingOutputNative()
        every { destination.detachFd() } throws IOException("provider closed before transfer")
        every { destination.close() } just Runs

        val result = GoPcv3Output(native).save(destination)

        assertEquals(Pcv3OutputResultData("save-failed-cleanup-incomplete", cleanupIncomplete = true), result)
        verify(exactly = 1) { destination.detachFd() }
        verify(exactly = 1) { destination.close() }
        assertEquals(0, native.saveCalls)
    }

    @Test
    fun `PCV3 output save keeps transferred fd owned by Go after an ordinary native failure`() {
        val destination = mockk<ParcelFileDescriptor>()
        val native = RecordingOutputNative(onSave = { throw IllegalStateException("native entry started then failed") })
        every { destination.detachFd() } returns 47
        mockkStatic(ParcelFileDescriptor::class)

        try {
            val result = GoPcv3Output(native).save(destination)

            assertEquals(Pcv3OutputResultData("save-failed-cleanup-incomplete", cleanupIncomplete = true), result)
            verify(exactly = 1) { destination.detachFd() }
            assertEquals(listOf(47L), native.savedDescriptors)
            verify(exactly = 0) { ParcelFileDescriptor.adoptFd(any()) }
            verify(exactly = 0) { destination.close() }
        } finally {
            unmockkStatic(ParcelFileDescriptor::class)
        }
    }

    @Test
    fun `PCV3 output save keeps transferred fd owned by Go after a linkage failure`() {
        val destination = mockk<ParcelFileDescriptor>()
        val native = RecordingOutputNative(onSave = { throw NoSuchMethodError("SaveFD missing from stale AAR") })
        every { destination.detachFd() } returns 49
        mockkStatic(ParcelFileDescriptor::class)

        try {
            val result = GoPcv3Output(native).save(destination)

            assertEquals(Pcv3OutputResultData("save-failed-cleanup-incomplete", cleanupIncomplete = true), result)
            verify(exactly = 1) { destination.detachFd() }
            assertEquals(listOf(49L), native.savedDescriptors)
            verify(exactly = 0) { ParcelFileDescriptor.adoptFd(any()) }
            verify(exactly = 0) { destination.close() }
        } finally {
            unmockkStatic(ParcelFileDescriptor::class)
        }
    }

    @Test
    fun `PCV3 output save propagates the exact cancellation after Go owns the fd`() {
        val destination = mockk<ParcelFileDescriptor>()
        val cancellation = kotlin.coroutines.cancellation.CancellationException("caller cancelled after native entry")
        val native = RecordingOutputNative(onSave = { throw cancellation })
        every { destination.detachFd() } returns 51
        mockkStatic(ParcelFileDescriptor::class)

        try {
            val thrown = runCatching { GoPcv3Output(native).save(destination) }.exceptionOrNull()

            assertSame(cancellation, thrown)
            verify(exactly = 1) { destination.detachFd() }
            assertEquals(listOf(51L), native.savedDescriptors)
            verify(exactly = 0) { ParcelFileDescriptor.adoptFd(any()) }
            verify(exactly = 0) { destination.close() }
        } finally {
            unmockkStatic(ParcelFileDescriptor::class)
        }
    }

    @Test
    fun `PCV3 output discard projects a closed path-free result`() {
        val native = RecordingOutputNative(
            onDiscard = { Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true) },
        )

        val result = GoPcv3Output(native).discard()

        assertEquals(Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true), result)
        assertEquals(1, native.discardCalls)
    }

    @Test
    fun `PCV3 resource challenge forwards the exact observation and fails closed at a stale AAR`() {
        val firstObservation = Pcv3AndroidResourceObservation(
            totalRamBytes = 8_589_934_592L,
            effectiveAvailableBytes = 3_221_225_472L,
            platformThresholdBytes = 536_870_912L,
            processFootprintBytes = 134_217_728L,
            processIs64Bit = false,
            lowMemory = false,
        )
        val secondObservation = firstObservation.copy(
            processIs64Bit = true,
            lowMemory = false,
        )
        val firstNative = RecordingResourceChallengeNative()
        val secondNative = RecordingResourceChallengeNative()

        assertTrue(GoPcv3ResourceChallenge(firstNative).submit(firstObservation))
        assertTrue(GoPcv3ResourceChallenge(secondNative).submit(secondObservation))
        assertEquals(listOf(firstObservation), firstNative.submissions)
        assertEquals(listOf(secondObservation), secondNative.submissions)

        firstNative.failure = NoSuchMethodError("stale AAR diagnostic must not escape")
        assertFalse(GoPcv3ResourceChallenge(firstNative).submit(firstObservation))
        assertEquals("a failed stale-AAR call is bounded and never retried", 2, firstNative.calls)
    }

    @Test
    fun `PCV3 artifact adapter preserves canonical uint64 metadata and one bounded immutable page`() {
        val rows = (0 until 128).map { index ->
            Pcv3ArtifactRangeData(
                recordIndex = if (index == 127) "18446744073709551615" else index.toString(),
                start = (index * 2L).toString(),
                end = if (index == 127) "18446744073709551615" else (index * 2L + 1L).toString(),
                status = when (index % 3) {
                    0 -> "verified"
                    1 -> "unverified"
                    else -> "missing"
                },
            )
        }.toMutableList()
        val native = RecordingArtifactInspectionNative(
            plaintextLength = "18446744073709551615",
            rangeCount = "18446744073709551615",
            verifiedCount = "18446744073709551615",
            pageBlock = { _, _ -> LiteralArtifactPageNative(rows) },
        )
        val inspection = GoPcv3ArtifactInspection(native)

        assertEquals(
            Pcv3ArtifactMetadataData(
                kind = "partial",
                role = "none",
                plaintextLength = "18446744073709551615",
                finalStatus = "missing",
                rangeCount = "18446744073709551615",
                verifiedCount = "18446744073709551615",
                unverifiedCount = "0",
                missingCount = "0",
            ),
            inspection.metadata(),
        )
        val page = inspection.page("18446744073709551615", 128)
        assertEquals("18446744073709551615", page?.offsetDecimal)
        assertEquals(128, page?.ranges?.size)
        assertEquals(Pcv3ArtifactRangeData("0", "0", "1", "verified"), page?.ranges?.first())
        assertEquals(
            Pcv3ArtifactRangeData(
                "18446744073709551615",
                "254",
                "18446744073709551615",
                "unverified",
            ),
            page?.ranges?.last(),
        )
        assertEquals(listOf("18446744073709551615" to 128L), native.pageRequests)

        rows[0] = rows[0].copy(status = "missing")
        assertEquals(
            "the adapter must return an immutable page copy",
            "verified",
            page?.ranges?.first()?.status,
        )
    }

    @Test
    fun `PCV3 artifact adapter rejects noncanonical metadata pages and native diagnostics`() {
        val invalidMetadata = listOf(
            RecordingArtifactInspectionNative(kind = "future-kind"),
            RecordingArtifactInspectionNative(role = "artifact/path"),
            RecordingArtifactInspectionNative(finalStatus = "trusted"),
            RecordingArtifactInspectionNative(plaintextLength = "01"),
            RecordingArtifactInspectionNative(rangeCount = "18446744073709551616"),
            RecordingArtifactInspectionNative(rangeCount = "2", verifiedCount = "1", missingCount = "0"),
        )
        invalidMetadata.forEach { native ->
            assertNull("invalid artifact metadata must be denied as one unit", GoPcv3ArtifactInspection(native).metadata())
        }

        val native = RecordingArtifactInspectionNative(
            pageBlock = { _, _ -> LiteralArtifactPageNative(listOf(Pcv3ArtifactRangeData("0", "0", "1", "verified"))) },
        )
        val inspection = GoPcv3ArtifactInspection(native)
        listOf("", "00", "+1", "-1", " 1", "18446744073709551616").forEach { offset ->
            assertNull("noncanonical offset $offset must not reach native code", inspection.page(offset, 1))
        }
        assertNull(inspection.page("0", 0))
        assertNull(inspection.page("0", 129))
        assertEquals(0, native.pageRequests.size)

        listOf(
            LiteralArtifactPageNative(
                rows = listOf(Pcv3ArtifactRangeData("0", "0", "1", "unknown")),
            ),
            LiteralArtifactPageNative(
                rows = listOf(Pcv3ArtifactRangeData("0", "01", "1", "verified")),
            ),
            LiteralArtifactPageNative(
                rows = listOf(Pcv3ArtifactRangeData("0", "2", "1", "verified")),
            ),
            LiteralArtifactPageNative(
                rows = listOf(Pcv3ArtifactRangeData("0", "0", "1", "verified")),
                count = 129,
            ),
        ).forEach { invalidPage ->
            val invalid = GoPcv3ArtifactInspection(
                RecordingArtifactInspectionNative(pageBlock = { _, _ -> invalidPage }),
            )
            assertNull("malformed or oversized native page must be denied", invalid.page("0", 128))
        }

        val sentinel = "content://private.provider/a-secret-path"
        listOf<Throwable>(
            IllegalStateException(sentinel),
            NoSuchMethodError(sentinel),
        ).forEach { failure ->
            val failedMetadata = GoPcv3ArtifactInspection(
                RecordingArtifactInspectionNative(metadataFailure = failure),
            )
            val failedPage = GoPcv3ArtifactInspection(
                RecordingArtifactInspectionNative(pageFailure = failure),
            )
            assertNull(failedMetadata.metadata())
            assertNull(failedPage.page("0", 1))
        }
    }

    private fun validRequest() = Pcv3Request(
        mode = "read-normal",
        factorPolicy = "password",
        keyfileOrder = "none",
        source = "input",
        target = "output",
        keyfiles = emptyList(),
    )

    private fun validWriteRequest() = Pcv3WriteRequest(
        mode = "write-normal",
        factorPolicy = "password",
        keyfileOrder = "none",
        source = "input",
        target = "output",
        keyfiles = emptyList(),
        comment = "plaintext comment",
        suite = "standard",
        payloadRS = false,
    )

    private class RecordingTransport(
        private val startBlock: (String, ByteArray) -> Pcv3StartData,
    ) : Pcv3Transport {
        var startCalls = 0
        var observedPassword: ByteArray? = null

        override fun start(requestJson: String, password: ByteArray): Pcv3StartData {
            startCalls += 1
            observedPassword = password
            return startBlock(requestJson, password)
        }

        override fun restoreReceipt(receipt: String): Pcv3RestoredReceiptData =
            Pcv3RestoredReceiptData("PCV3_RECEIPT_INVALID", "", "", null)
    }

    private class RecordingOutputNative(
        private val onSave: (Long) -> Pcv3OutputResultData = {
            Pcv3OutputResultData("saved", cleanupIncomplete = false)
        },
        private val onDiscard: () -> Pcv3OutputResultData = {
            Pcv3OutputResultData("discarded", cleanupIncomplete = false)
        },
    ) : Pcv3OutputNative {
        val savedDescriptors = mutableListOf<Long>()
        var saveCalls = 0
            private set
        var discardCalls = 0
            private set

        override fun saveFD(descriptor: Long): Pcv3OutputResultData {
            saveCalls += 1
            savedDescriptors += descriptor
            return onSave(descriptor)
        }

        override fun discard(): Pcv3OutputResultData {
            discardCalls += 1
            return onDiscard()
        }
    }

    private class RecordingResourceChallengeNative : Pcv3ResourceChallengeNative {
        val submissions = mutableListOf<Pcv3AndroidResourceObservation>()
        var calls = 0
        var failure: Throwable? = null

        override fun submit(
            totalRamBytes: Long,
            effectiveAvailableBytes: Long,
            platformThresholdBytes: Long,
            processFootprintBytes: Long,
            processIs64Bit: Boolean,
            lowMemory: Boolean,
        ): Boolean {
            calls += 1
            failure?.let { throw it }
            submissions += Pcv3AndroidResourceObservation(
                totalRamBytes,
                effectiveAvailableBytes,
                platformThresholdBytes,
                processFootprintBytes,
                processIs64Bit,
                lowMemory,
            )
            return true
        }
    }

    private class RecordingArtifactInspectionNative(
        private val kind: String = "partial",
        private val role: String = "none",
        private val plaintextLength: String = "1",
        private val finalStatus: String = "missing",
        private val rangeCount: String = "1",
        private val verifiedCount: String = "1",
        private val unverifiedCount: String = "0",
        private val missingCount: String = "0",
        private val metadataFailure: Throwable? = null,
        private val pageFailure: Throwable? = null,
        private val pageBlock: (String, Long) -> Pcv3ArtifactPageNative? = { _, _ -> null },
    ) : Pcv3ArtifactInspectionNative {
        val pageRequests = mutableListOf<Pair<String, Long>>()

        private fun failMetadataIfRequested() {
            metadataFailure?.let { throw it }
        }

        override fun kind(): String = kind.also { failMetadataIfRequested() }
        override fun role(): String = role.also { failMetadataIfRequested() }
        override fun plaintextLength(): String = plaintextLength.also { failMetadataIfRequested() }
        override fun finalStatus(): String = finalStatus.also { failMetadataIfRequested() }
        override fun rangeCount(): String = rangeCount.also { failMetadataIfRequested() }
        override fun verifiedCount(): String = verifiedCount.also { failMetadataIfRequested() }
        override fun unverifiedCount(): String = unverifiedCount.also { failMetadataIfRequested() }
        override fun missingCount(): String = missingCount.also { failMetadataIfRequested() }

        override fun page(offsetDecimal: String, limit: Long): Pcv3ArtifactPageNative? {
            pageRequests += offsetDecimal to limit
            pageFailure?.let { throw it }
            return pageBlock(offsetDecimal, limit)
        }
    }

    private class LiteralArtifactPageNative(
        private val rows: List<Pcv3ArtifactRangeData>,
        private val count: Long = rows.size.toLong(),
    ) : Pcv3ArtifactPageNative {
        override fun count(): Long = count
        override fun recordIndexAt(index: Long): String = rows[index.toInt()].recordIndex
        override fun startAt(index: Long): String = rows[index.toInt()].start
        override fun endAt(index: Long): String = rows[index.toInt()].end
        override fun statusAt(index: Long): String = rows[index.toInt()].status
    }

    private class TestOperation(override val id: String) : Pcv3OperationCapability {
        override fun snapshot(): Pcv3SnapshotData = error("not needed by bridge serialization test")
        override fun consent(): Pcv3ConsentCapability? = null
        override fun archive(): Pcv3ArchiveCapability? = null
        override fun output(): Pcv3OutputCapability? = null
        override fun artifactInspection(): Pcv3ArtifactInspectionCapability? = null
        override fun cancel(): Pcv3SnapshotData = error("not needed by bridge serialization test")
        override fun release(): String = ""
    }
}
