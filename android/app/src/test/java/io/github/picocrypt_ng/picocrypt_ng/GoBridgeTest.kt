package io.github.picocrypt_ng.picocrypt_ng

import org.junit.Assert.*
import org.junit.Test
import org.json.JSONException
import org.json.JSONObject

/**
 * Pure-logic tests for GoBridge (request-JSON building, response parsing, password
 * zeroing, and option defaults). They run on the plain JVM and assert the real
 * production code paths, so they fail if the production serialization/parsing changes.
 */
class GoBridgeTest {

    @Test
    fun `input publication grants target cleanup only for exact confirmed native outcomes`() {
        assertEquals(InputCopyPublication.PUBLISHED, publishInputCopy { "published" })
        assertEquals(InputCopyPublication.PUBLISHED_ERROR, publishInputCopy { "published-error" })
        assertEquals(InputCopyPublication.NOT_PUBLISHED, publishInputCopy { "not-published" })
        for (result in listOf("indeterminate", "", "Published", "published ", "future-status")) {
            assertEquals(InputCopyPublication.INDETERMINATE, publishInputCopy { result })
        }
        assertEquals(InputCopyPublication.INDETERMINATE, publishInputCopy { throw java.io.IOException("native failure") })
        assertEquals(InputCopyPublication.INDETERMINATE, publishInputCopy { throw UnsatisfiedLinkError("stale binding") })
        val cancelled = kotlin.coroutines.cancellation.CancellationException("cancelled native handoff")
        try {
            publishInputCopy { throw cancelled }
            fail("Cancellation must remain cancellation")
        } catch (actual: kotlin.coroutines.cancellation.CancellationException) {
            assertSame(cancelled, actual)
        }
    }

    // --- Request JSON building: asserts the REAL production builders ------------------
    // These call GoBridge.build*RequestJson (the exact code startEncrypt/startDecrypt
    // send to Go), so they fail if a field is dropped, renamed, or retyped. No AAR needed.

    @Test
    fun `PCV3 envelope keeps maximum comments and bounded file selections`() {
        val request = Pcv3WriteRequest("write-normal", "password", "none", "/source", "/target",
            emptyList(), "x".repeat(99999), "standard", false)
        assertEquals(99999, JSONObject(requireNotNull(GoBridge.buildPcv3WriteRequestJson(request))).getString("comment").length)
        val selected = List(4096) { "/selected/file-$it" }
        assertNotNull(GoBridge.buildPcv3WriteRequestJson(request.copy(source = selected.first(), inputFiles = selected, onlyFiles = selected)))
        val tooLarge = List(4096) { "/selected/" + "x".repeat(1000) + it }
        assertNull("aggregate JSON limit must be enforced before JNI", GoBridge.buildPcv3WriteRequestJson(request.copy(source = tooLarge.first(), inputFiles = tooLarge, onlyFiles = tooLarge)))
        assertNull(GoBridge.buildPcv3WriteRequestJson(request.copy(source = "/" + "x".repeat(4096))))
        assertNull(GoBridge.buildPcv3WriteRequestJson(request.copy(inputFiles = List(4097) { "/input" })))
        val escapedPaths = List(4096) { "/selected/" + "\t".repeat(400) + it }
        assertNull("JSON escaping counts toward the aggregate cap",
            GoBridge.buildPcv3WriteRequestJson(request.copy(source = escapedPaths.first(), inputFiles = escapedPaths, onlyFiles = escapedPaths)))
        val multibytePaths = List(4096) { "/selected/" + "界".repeat(200) + it }
        assertNull("UTF-8 bytes, not UTF-16 character count, bound the aggregate",
            GoBridge.buildPcv3WriteRequestJson(request.copy(source = multibytePaths.first(), inputFiles = multibytePaths, onlyFiles = multibytePaths)))
    }

    @Test
    fun `buildEncryptRequestJson serializes every option and never the password`() {
        val json = JSONObject(
            GoBridge.buildEncryptRequestJson(
                operationID = "test_op_123",
                inputFile = "/path/to/input.txt",
                outputFile = "/path/to/output.pcv",
                options = EncryptOptions(
                    comments = "Test comments",
                    paranoid = true,
                    reedSolomon = true,
                    deniability = false,
                    compress = true,
                    keyfiles = listOf("keyfile1", "keyfile2"),
                    keyfileOrdered = true
                )
            )
        )

        assertEquals("test_op_123", json.getString("operationID"))
        assertEquals("/path/to/input.txt", json.getString("inputFile"))
        assertEquals("/path/to/output.pcv", json.getString("outputFile"))
        assertEquals("Test comments", json.getString("comments"))
        assertTrue(json.getBoolean("paranoid"))
        assertTrue(json.getBoolean("reedSolomon"))
        assertFalse(json.getBoolean("deniability"))
        assertTrue(json.getBoolean("compress"))
        assertTrue(json.getBoolean("keyfileOrdered"))

        val keyfiles = json.getJSONArray("keyfiles")
        assertEquals(2, keyfiles.length())
        assertEquals("keyfile1", keyfiles.getString(0))
        assertEquals("keyfile2", keyfiles.getString(1))

        // SECURITY: the password is handed to Mobile as raw bytes, never serialized.
        assertFalse("password must never appear in the JSON", json.has("password"))
    }

    @Test
    fun buildEncryptRequestJson_includesSelectionArrays() {
        // A folder/multi-file selection is forwarded to Go as inputFiles/onlyFolders/
        // onlyFiles arrays (Go zips them). The single-file path leaves these empty.
        // This asserts the REAL serialization so a dropped/renamed array fails the build.
        val json = GoBridge.buildEncryptRequestJson(
            operationID = "op1",
            inputFile = "",
            outputFile = "/data/out.pcv",
            options = EncryptOptions(),
            inputFiles = listOf("/s/Root/a.txt", "/s/Root/sub/b.txt"),
            onlyFolders = listOf("/s/Root"),
            onlyFiles = emptyList(),
        )
        val obj = JSONObject(json)
        assertEquals(2, obj.getJSONArray("inputFiles").length())
        assertEquals("/s/Root", obj.getJSONArray("onlyFolders").getString(0))
        assertEquals(0, obj.getJSONArray("onlyFiles").length())
    }

    @Test
    fun buildEncryptRequestJson_singleFileEmitsEmptySelectionArrays() {
        // The single-file path must stay the degenerate case: inputFile carries the path
        // and the three selection arrays are present but empty (Go treats it as one file).
        val json = GoBridge.buildEncryptRequestJson(
            operationID = "op1",
            inputFile = "/data/in.txt",
            outputFile = "/data/out.pcv",
            options = EncryptOptions(),
        )
        val obj = JSONObject(json)
        assertEquals("/data/in.txt", obj.getString("inputFile"))
        assertEquals(0, obj.getJSONArray("inputFiles").length())
        assertEquals(0, obj.getJSONArray("onlyFolders").length())
        assertEquals(0, obj.getJSONArray("onlyFiles").length())
    }

    @Test
    fun `buildDecryptRequestJson serializes every option and never the password`() {
        val json = JSONObject(
            GoBridge.buildDecryptRequestJson(
                operationID = "test_op_123",
                inputFile = "/path/to/input.pcv",
                outputFile = "/path/to/output.txt",
                options = DecryptOptions(
                    keyfiles = listOf("keyfile1"),
                    forceDecrypt = true,
                    verifyFirst = true,
                    autoUnzip = false,
                    sameLevel = true,
                    recombine = false,
                    deniability = true
                )
            )
        )

        assertEquals("test_op_123", json.getString("operationID"))
        assertEquals("/path/to/input.pcv", json.getString("inputFile"))
        assertEquals("/path/to/output.txt", json.getString("outputFile"))
        assertTrue(json.getBoolean("forceDecrypt"))
        assertTrue(json.getBoolean("verifyFirst"))
        assertFalse(json.getBoolean("autoUnzip"))
        assertTrue(json.getBoolean("sameLevel"))
        assertFalse(json.getBoolean("recombine"))
        assertTrue(json.getBoolean("deniability"))

        val keyfiles = json.getJSONArray("keyfiles")
        assertEquals(1, keyfiles.length())
        assertEquals("keyfile1", keyfiles.getString(0))

        assertFalse("password must never appear in the JSON", json.has("password"))
    }

    // --- Response parsing: asserts the REAL production parser -------------------------

    @Test
    fun `parseDecryptionInfo maps every header field`() {
        val info = GoBridge.parseDecryptionInfo(
            """
            {
                "keyfilesRequired": true,
                "keyfileOrdered": true,
                "reedSolomon": true,
                "deniability": false,
                "paranoid": true,
                "comments": "Test comments",
                "readable": true
            }
            """.trimIndent()
        )

        assertTrue(info.keyfilesRequired)
        assertTrue(info.keyfileOrdered)
        assertTrue(info.reedSolomon)
        assertFalse(info.deniability)
        assertTrue(info.paranoid)
        assertEquals("Test comments", info.comments)
        assertTrue(info.readable)
    }

    @Test
    fun `parseDecryptionInfo throws on a missing required field`() {
        // SECURITY: a malformed header response must fail loud, not silently default
        // (e.g. defaulting keyfilesRequired=false would let the UI skip the keyfile
        // prompt). The production parser uses getBoolean, which throws on a missing key.
        val missingKeyfilesRequired = """
            {
                "keyfileOrdered": false,
                "reedSolomon": false,
                "deniability": false,
                "paranoid": false,
                "comments": "",
                "readable": true
            }
        """.trimIndent()

        assertThrows(JSONException::class.java) {
            GoBridge.parseDecryptionInfo(missingKeyfilesRequired)
        }
    }

    // --- Password zeroing: security contract that holds even when the call fails ------
    // GoBridge.start{Encrypt,Decrypt} zero the caller's password in a finally block. On
    // the JVM the native Mobile call throws, but finally still runs, so these verify the
    // wipe WITHOUT the AAR (and on-device, where Mobile returns, the finally still runs).

    @Test
    fun `startEncrypt zeroes the password even when the bridge call fails`() {
        val password = "hunter2".toByteArray(Charsets.UTF_8)
        try {
            GoBridge.startEncrypt("op_missing", "/no/such/in", "/tmp/out.pcv", password, EncryptOptions())
        } catch (t: Throwable) {
            // Native bridge unavailable on the JVM; the finally block has already run.
        }
        assertTrue("password bytes must be zeroed", password.all { it == 0.toByte() })
    }

    @Test
    fun `startDecrypt zeroes the password even when the bridge call fails`() {
        val password = "hunter2".toByteArray(Charsets.UTF_8)
        try {
            GoBridge.startDecrypt("op_missing", "/no/such/in.pcv", "/tmp/out", password, DecryptOptions())
        } catch (t: Throwable) {
            // Native bridge unavailable on the JVM; the finally block has already run.
        }
        assertTrue("password bytes must be zeroed", password.all { it == 0.toByte() })
    }

    // --- Option/struct defaults: guard against accidental default changes -------------

    @Test
    fun `EncryptOptions has correct defaults`() {
        val options = EncryptOptions()
        assertEquals("", options.comments)
        assertFalse(options.paranoid)
        assertFalse(options.reedSolomon)
        assertFalse(options.deniability)
        assertFalse(options.compress)
        assertEquals(emptyList<String>(), options.keyfiles)
        assertFalse(options.keyfileOrdered)
    }

    @Test
    fun `DecryptOptions has correct defaults`() {
        // autoUnzip MUST default false: Go auto-unzip orphans Android's single-file
        // export (see OperationManager). A regression here re-introduces SaveFailed.
        val options = DecryptOptions()
        assertEquals(emptyList<String>(), options.keyfiles)
        assertFalse(options.forceDecrypt)
        assertFalse(options.verifyFirst)
        assertFalse(options.autoUnzip)
        assertFalse(options.sameLevel)
        assertFalse(options.recombine)
        assertFalse(options.deniability)
    }

}
