package io.github.picocrypt_ng.picocrypt_ng

import java.io.File
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

    // --- Request JSON building: asserts the REAL production builders ------------------
    // These call GoBridge.build*RequestJson (the exact code startEncrypt/startDecrypt
    // send to Go), so they fail if a field is dropped, renamed, or retyped. No AAR needed.

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

    @Test
    fun `ProgressState keeps semantic progress and technical errors distinct`() {
        val progressState = ProgressState(
            status = OperationStatusData(
                code = "ENCRYPTING_RATE",
                speedMiBPerSecond = 12.34,
                eta = "01:02:03",
            ),
            detail = OperationProgressDetail(
                code = "ITEM_COUNT",
                current = 3,
                total = 10,
            ),
            progress = 0.5f,
            done = false,
            technicalError = "diagnostic only",
            errorCode = "GENERIC",
        )
        assertEquals("ENCRYPTING_RATE", progressState.status.code)
        assertEquals(12.34, progressState.status.speedMiBPerSecond, 0.001)
        assertEquals("01:02:03", progressState.status.eta)
        assertEquals("ITEM_COUNT", progressState.detail.code)
        assertEquals(3, progressState.detail.current)
        assertEquals(10, progressState.detail.total)
        assertEquals(0.5f, progressState.progress, 0.001f)
        assertFalse(progressState.done)
        assertEquals("diagnostic only", progressState.technicalError)
        assertEquals("GENERIC", progressState.errorCode)
    }

    @Test
    fun `getProgress consumes every structured getter without carrying raw status or info`() {
        val source = File(
            "src/main/java/io/github/picocrypt_ng/picocrypt_ng/GoBridge.kt"
        ).readText()

        listOf(
            "result.getStatusCode()",
            "result.getStatusSpeedMiBPerSecond()",
            "result.getStatusETA()",
            "result.getInfoCode()",
            "result.getInfoCurrent()",
            "result.getInfoTotal()",
        ).forEach { getter ->
            assertTrue("GoBridge.getProgress must consume $getter", source.contains(getter))
        }
        assertTrue(
            "Raw Go errors must populate only the technicalError field",
            Regex("technicalError\\s*=\\s*result\\.getError\\(\\)").containsMatchIn(source),
        )
        assertTrue(
            "Stable Go error codes must populate the errorCode field",
            Regex("errorCode\\s*=\\s*result\\.getCode\\(\\)").containsMatchIn(source),
        )
        assertFalse("Raw Go status must not enter durable Kotlin state", source.contains("result.getStatus()"))
        assertFalse("Raw Go info must not enter durable Kotlin state", source.contains("result.getInfo()"))
    }

}
