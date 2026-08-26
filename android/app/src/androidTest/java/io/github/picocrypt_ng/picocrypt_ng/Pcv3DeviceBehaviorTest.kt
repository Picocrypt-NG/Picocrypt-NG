package io.github.picocrypt_ng.picocrypt_ng

import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import mobile.Mobile
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Final-device behavior for the untagged production AAR.
 *
 * This class is source-authored before the final device boundary. It is not
 * product support evidence until the exact whole selector passes on every
 * approved physical serial and its separate observations validate. It drives
 * only the public gomobile bridge surface and observes credentials,
 * descriptors, files, and restored receipts from the device side.
 */
@RunWith(AndroidJUnit4::class)
class Pcv3DeviceBehaviorTest {
    @Test
    fun v08PasswordAndDescriptorOwnership() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val directory = File(context.cacheDir, "pcv3-v08-ownership")
        assertFalse("v08 workspace residue from an earlier attempt", directory.exists())
        if (!directory.mkdir()) {
            throw AssertionError("v08 workspace must be newly owned")
        }
        val source = File(directory, "ownership-source.pcv")
        val keyfile = File(directory, "ownership-factor.key")
        val link = File(directory, "ownership-link.pcv")
        val target = File(directory, "ownership-output.bin")
        var primaryFailure: Throwable? = null
        try {
            source.writeBytes(NON_VOLUME_SOURCE)
            keyfile.writeBytes(KEYFILE_FACTOR)

            val password = CALLER_PASSWORD.copyOf()
            val start = Mobile.startPCV3(
                envelope("read-normal", "password-and-keyfiles", "ordered", source, target, listOf(keyfile)),
                password,
            )
            val operation = start.operation()
            try {
                assertEquals("ownership start must succeed", "", start.code())
                assertTrue(
                    "bridge must zero the caller password before returning",
                    password.all { it == 0.toByte() },
                )
                val liveOperation = operation
                    ?: throw AssertionError("ownership start returned no operation")
                val terminal = awaitTerminal(liveOperation)
                assertEquals(
                    "unsupported routing terminal must stay exact",
                    unsupportedRoutingTerminal(),
                    TerminalObservation.from(start.code(), liveOperation, terminal),
                )
                assertFalse("a refused operation must create no output", target.exists())
                assertEquals(
                    "no descriptor may resolve to the source after the operation",
                    emptyList<String>(),
                    descriptorsResolvingTo(source),
                )
                assertEquals(
                    "no descriptor may resolve to the keyfile after the operation",
                    emptyList<String>(),
                    descriptorsResolvingTo(keyfile),
                )
                assertEquals("terminal release must succeed", "", liveOperation.release())
                assertEquals(
                    "a released operation must not act twice",
                    RELEASE_DENIED,
                    liveOperation.release(),
                )
                assertEquals(
                    "a released operation exposes only the unknown snapshot",
                    "unknown",
                    liveOperation.snapshot().completionClass(),
                )
            } catch (failure: Throwable) {
                primaryFailure = failure
                throw failure
            } finally {
                if (operation != null) {
                    attachCleanupFailure(primaryFailure) { release(operation, "ownership") }
                }
            }

            Os.symlink(source.absolutePath, link.absolutePath)
            val linkPassword = CALLER_PASSWORD.copyOf()
            val rejected = Mobile.startPCV3(
                envelope("read-normal", "password", "none", link, target, emptyList()),
                linkPassword,
            )
            assertEquals(
                "a symlink source must be refused before any descriptor is owned",
                BRIDGE_INPUT_UNAVAILABLE,
                rejected.code(),
            )
            assertNull("a refused start must return no operation", rejected.operation())
            assertTrue(
                "input refusal must still zero the caller password",
                linkPassword.all { it == 0.toByte() },
            )
            assertFalse("a refused start must create no output", target.exists())
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            attachCleanupFailure(primaryFailure) {
                cleanupFiles(
                    target to "ownership output",
                    link to "ownership symlink",
                    keyfile to "ownership keyfile",
                    source to "ownership source",
                    directory to "v08 workspace",
                )
            }
        }
    }

    @Test
    fun v09RestoredReceiptIsDenyOnly() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val directory = File(context.cacheDir, "pcv3-v09-receipt")
        assertFalse("v09 workspace residue from an earlier attempt", directory.exists())
        if (!directory.mkdir()) {
            throw AssertionError("v09 workspace must be newly owned")
        }
        val receiptFile = File(directory, "restored-receipt.json")
        var primaryFailure: Throwable? = null
        try {
            // Restoration consumes only retained bytes; the live registry entry
            // is gone after process death, which is exactly this fresh state.
            // This proves deny-only restoration, never causal LMK survival.
            receiptFile.writeText(RESTORABLE_RECEIPT, Charsets.UTF_8)
            val retained = receiptFile.readText(Charsets.UTF_8)
            val restored = Mobile.restorePCV3Receipt(retained)
            assertEquals("retained receipt must restore", "", restored.code())
            assertEquals(RECEIPT_ID, restored.receiptID())
            assertEquals(RECEIPT_OPERATION_ID, restored.operationID())
            val snapshot = restored.snapshot()
                ?: throw AssertionError("restored receipt returned no display snapshot")
            assertEquals(
                "restored display state must stay exact",
                restoredUncertainTerminal(),
                TerminalObservation.from("", null, snapshot),
            )

            val reminted = snapshot.restoredReceipt()
            assertTrue("a restorable display state must re-mint a receipt", reminted.isNotEmpty())
            val restoredAgain = Mobile.restorePCV3Receipt(reminted)
            assertEquals("a re-minted receipt must restore", "", restoredAgain.code())
            assertEquals(
                "a re-minted receipt must restore the same exact display state",
                restoredUncertainTerminal(),
                TerminalObservation.from("", null, restoredAgain.snapshot()),
            )

            val exposed = restored.javaClass.methods.map { it.name.lowercase() }
                .filter { it in FORBIDDEN_RECEIPT_AUTHORITIES }
            assertEquals(
                "restored receipt must not expose any authority method",
                emptyList<String>(),
                exposed,
            )
            assertIdAuthorityDenied("cancelOperation") { Mobile.cancelOperation(restored.operationID()) }
            assertIdAuthorityDenied("getProgress") { Mobile.getProgress(restored.operationID()) }

            val unknownField = JSONObject(retained).put("source", "/private/plaintext").toString()
            val rejectedField = Mobile.restorePCV3Receipt(unknownField)
            assertEquals("an unknown receipt field must be refused", RECEIPT_INVALID, rejectedField.code())
            assertNull("a refused receipt must return no snapshot", rejectedField.snapshot())

            val durableTamper = JSONObject(retained)
                .put("publicationState", 2)
                .put("publicationStage", 0)
                .put("publicationCode", 8)
                .put("warnings", JSONArray())
                .toString()
            val rejectedTamper = Mobile.restorePCV3Receipt(durableTamper)
            assertEquals(
                "a receipt claiming durable publication must be refused",
                RECEIPT_INVALID,
                rejectedTamper.code(),
            )
            assertNull("a refused receipt must return no snapshot", rejectedTamper.snapshot())

            val oversized = Mobile.restorePCV3Receipt("x".repeat(MAX_RECEIPT_BYTES + 1))
            assertEquals("an oversized receipt must be refused", RECEIPT_INVALID, oversized.code())
            assertNull("a refused receipt must return no snapshot", oversized.snapshot())
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            attachCleanupFailure(primaryFailure) {
                cleanupFiles(
                    receiptFile to "restored receipt",
                    directory to "v09 workspace",
                )
            }
        }
    }

    @Test
    fun v10FinalAarDeviceBehavior() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val directory = File(context.cacheDir, "pcv3-v10-final-aar")
        assertFalse("v10 workspace residue from an earlier attempt", directory.exists())
        if (!directory.mkdir()) {
            throw AssertionError("v10 workspace must be newly owned")
        }
        val source = File(directory, "final-source.pcv")
        val target = File(directory, "final-output.bin")
        var primaryFailure: Throwable? = null
        try {
            val calibrationSeams = Mobile::class.java.methods
                .map { it.name }
                .filter { it.contains("calibration", ignoreCase = true) }
            assertEquals(
                "the untagged final AAR must expose no calibration seam",
                emptyList<String>(),
                calibrationSeams,
            )
            assertTrue(
                "the Android policy state must stay closed",
                Mobile.pcV3AndroidPolicyState() in POLICY_STATES,
            )
            val routeProbe = File(directory, ROUTE_PROBE_NAME)
            routeProbe.writeBytes(NON_VOLUME_SOURCE)
            assertEquals(
                "an arbitrary source must never claim the PCV3 normal route",
                "legacy",
                Mobile.detectPCV3Route(routeProbe.absolutePath),
            )
            try {
                Mobile.detectPCV3Route(File(directory, "route-missing.bin").absolutePath)
                fail("route classification must fail closed for an unreadable input")
            } catch (expected: Exception) {
                assertEquals(BRIDGE_INPUT_UNAVAILABLE, expected.message)
            }

            source.writeBytes(NON_VOLUME_SOURCE)
            for (mode in listOf("write-normal", "migrate-normal")) {
                val password = CALLER_PASSWORD.copyOf()
                val rejected = Mobile.startPCV3(
                    envelope(mode, "password", "none", source, target, emptyList()),
                    password,
                )
                assertEquals("the $mode seam must stay refused", BRIDGE_INVALID_REQUEST, rejected.code())
                assertNull("a refused $mode seam must return no operation", rejected.operation())
                assertTrue(
                    "a refused $mode seam must zero the caller password",
                    password.all { it == 0.toByte() },
                )
                assertFalse("a refused $mode seam must create no output", target.exists())
            }

            val password = CALLER_PASSWORD.copyOf()
            val start = Mobile.startPCV3(
                envelope("read-normal", "password", "none", source, target, emptyList()),
                password,
            )
            val operation = start.operation()
            try {
                assertEquals("final read start must succeed", "", start.code())
                assertTrue(
                    "bridge must zero the caller password before returning",
                    password.all { it == 0.toByte() },
                )
                val liveOperation = operation
                    ?: throw AssertionError("final read start returned no operation")
                val terminal = awaitTerminal(liveOperation)
                assertEquals(
                    "final read terminal must stay exact",
                    unsupportedRoutingTerminal(),
                    TerminalObservation.from(start.code(), liveOperation, terminal),
                )
                assertFalse("a refused operation must create no output", target.exists())
                assertEquals(
                    "no descriptor may resolve to the source after the operation",
                    emptyList<String>(),
                    descriptorsResolvingTo(source),
                )
                assertEquals("terminal release must succeed", "", liveOperation.release())
            } catch (failure: Throwable) {
                primaryFailure = failure
                throw failure
            } finally {
                if (operation != null) {
                    attachCleanupFailure(primaryFailure) { release(operation, "final read") }
                }
            }
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            attachCleanupFailure(primaryFailure) {
                cleanupFiles(
                    target to "final output",
                    source to "final source",
                    File(directory, ROUTE_PROBE_NAME) to "route probe",
                    directory to "v10 workspace",
                )
            }
        }
    }

    private fun awaitTerminal(operation: mobile.PCV3Operation): mobile.PCV3Snapshot {
        val deadline = SystemClock.elapsedRealtime() + TERMINAL_TIMEOUT_MILLIS
        while (SystemClock.elapsedRealtime() < deadline) {
            val snapshot = operation.snapshot()
            if (snapshot.completionClass() != "unknown") {
                return snapshot
            }
            SystemClock.sleep(POLL_MILLIS)
        }
        throw AssertionError("PCV3 operation did not reach a terminal state")
    }

    private fun release(operation: mobile.PCV3Operation, label: String) {
        var cleanupFailure: Throwable? = null
        val initiallyReleased = try {
            operation.release().isEmpty()
        } catch (failure: Throwable) {
            cleanupFailure = failure
            false
        }
        if (initiallyReleased) {
            return
        }
        try {
            operation.cancel()
        } catch (failure: Throwable) {
            cleanupFailure = accumulateFailure(cleanupFailure, failure)
        }
        try {
            awaitTerminal(operation)
        } catch (failure: Throwable) {
            cleanupFailure = accumulateFailure(cleanupFailure, failure)
        }
        try {
            val releaseCode = operation.release()
            if (releaseCode.isNotEmpty()) {
                cleanupFailure = accumulateFailure(
                    cleanupFailure,
                    AssertionError("$label operation remained live after cleanup: $releaseCode"),
                )
            }
        } catch (failure: Throwable) {
            cleanupFailure = accumulateFailure(cleanupFailure, failure)
        }
        cleanupFailure?.let { throw it }
    }

    private fun descriptorsResolvingTo(file: File): List<String> {
        val table = File("/proc/self/fd")
        val entries = table.list() ?: throw AssertionError("process descriptor table is unavailable")
        return entries.mapNotNull { entry ->
            val resolved = try {
                Os.readlink(File(table, entry).absolutePath)
            } catch (_: ErrnoException) {
                null
            }
            if (resolved == file.absolutePath) entry else null
        }
    }

    private fun assertIdAuthorityDenied(label: String, action: () -> Unit) {
        try {
            action()
            fail("restored receipt id must not authorize $label")
        } catch (expected: Exception) {
            assertTrue(
                "$label denial must stay a closed lookup failure",
                expected.message?.contains("not found") == true,
            )
        }
    }

    private fun envelope(
        mode: String,
        factorPolicy: String,
        keyfileOrder: String,
        source: File,
        target: File,
        keyfiles: List<File>,
    ): String {
        val keys = keyfiles.joinToString(separator = ",") { jsonString(it.absolutePath) }
        return """{"version":1,"mode":${jsonString(mode)},"factorPolicy":${jsonString(factorPolicy)},"keyfileOrder":${jsonString(keyfileOrder)},"source":${jsonString(source.absolutePath)},"target":${jsonString(target.absolutePath)},"keyfiles":[$keys]}"""
    }

    private fun deleteExactly(file: File, label: String) {
        if (file.exists() && !file.delete()) {
            throw AssertionError("$label could not be deleted")
        }
        assertFalse("$label must be absent after cleanup", file.exists())
    }

    private fun cleanupFiles(vararg files: Pair<File, String>) {
        var cleanupFailure: Throwable? = null
        files.forEach { (file, label) ->
            try {
                deleteExactly(file, label)
            } catch (failure: Throwable) {
                cleanupFailure = accumulateFailure(cleanupFailure, failure)
            }
        }
        if (cleanupFailure != null) {
            throw cleanupFailure
        }
    }

    private fun attachCleanupFailure(primaryFailure: Throwable?, cleanup: () -> Unit) {
        try {
            cleanup()
        } catch (failure: Throwable) {
            if (primaryFailure == null) {
                throw failure
            }
            primaryFailure.addSuppressed(failure)
        }
    }

    private fun accumulateFailure(current: Throwable?, next: Throwable): Throwable {
        if (current == null) {
            return next
        }
        current.addSuppressed(next)
        return current
    }

    private fun jsonString(value: String): String =
        buildString(value.length + 2) {
            append('"')
            value.forEach { character ->
                when (character) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    else -> append(character)
                }
            }
            append('"')
        }

    private data class TerminalObservation(
        val startCode: String,
        val statusCode: String,
        val statusArgs: List<String>,
        val outcome: String,
        val stage: String,
        val code: String,
        val forceProvenance: String,
        val d1BootstrapProvenance: String,
        val detailStage: String,
        val diagnostic: String,
        val completion: String,
        val publicationAttempted: Boolean,
        val publicationState: String,
        val publicationStage: String,
        val publicationCode: String,
        val resultArgs: List<String>,
        val warnings: List<String>,
        val archivePending: Boolean,
        val consentPresent: Boolean,
        val archivePresent: Boolean,
        val restoredReceiptPresent: Boolean,
    ) {
        companion object {
            fun from(
                startCode: String,
                operation: mobile.PCV3Operation?,
                snapshot: mobile.PCV3Snapshot,
            ) = TerminalObservation(
                startCode = startCode,
                statusCode = snapshot.statusCode(),
                statusArgs = (0 until snapshot.statusArgCount()).map { snapshot.statusArgAt(it) },
                outcome = snapshot.outcome(),
                stage = snapshot.stage(),
                code = snapshot.code(),
                forceProvenance = snapshot.forceProvenance(),
                d1BootstrapProvenance = snapshot.d1BootstrapProvenance(),
                detailStage = snapshot.detailStage(),
                diagnostic = snapshot.diagnostic(),
                completion = snapshot.completionClass(),
                publicationAttempted = snapshot.publicationAttempted(),
                publicationState = snapshot.publicationState(),
                publicationStage = snapshot.publicationStage(),
                publicationCode = snapshot.publicationCode(),
                resultArgs = (0 until snapshot.argCount()).map { snapshot.argAt(it) },
                warnings = (0 until snapshot.warningCount()).map { snapshot.warningAt(it) },
                archivePending = snapshot.archivePending(),
                consentPresent = operation?.consent() != null,
                archivePresent = operation?.archive() != null,
                restoredReceiptPresent = snapshot.restoredReceipt().isNotEmpty(),
            )
        }
    }

    private fun unsupportedRoutingTerminal() = TerminalObservation(
        startCode = "",
        statusCode = "authenticating",
        statusArgs = emptyList(),
        outcome = "unsupported-routing-pre-kdf",
        stage = "routing",
        code = "PCV3_UNSUPPORTED",
        forceProvenance = "none",
        d1BootstrapProvenance = "none",
        detailStage = "none",
        diagnostic = "none",
        completion = "refused",
        publicationAttempted = false,
        publicationState = "none",
        publicationStage = "none",
        publicationCode = "none",
        resultArgs = emptyList(),
        warnings = emptyList(),
        archivePending = false,
        consentPresent = false,
        archivePresent = false,
        restoredReceiptPresent = false,
    )

    private fun restoredUncertainTerminal() = TerminalObservation(
        startCode = "",
        statusCode = "none",
        statusArgs = emptyList(),
        outcome = "success",
        stage = "none",
        code = "PCV3_SUCCESS",
        forceProvenance = "verified",
        d1BootstrapProvenance = "matching",
        detailStage = "metadata",
        diagnostic = "none",
        completion = "durability-uncertain",
        publicationAttempted = true,
        publicationState = "published-durability-uncertain",
        publicationStage = "directory-sync",
        publicationCode = "PCV3_PUBLICATION_DURABILITY_UNCERTAIN",
        resultArgs = listOf("7", "11", "13", "17"),
        warnings = listOf("cleanup-incomplete", "durability-uncertain"),
        archivePending = false,
        consentPresent = false,
        archivePresent = false,
        restoredReceiptPresent = true,
    )

    private companion object {
        const val BRIDGE_INVALID_REQUEST = "PCV3_BRIDGE_INVALID_REQUEST"
        const val BRIDGE_INPUT_UNAVAILABLE = "PCV3_BRIDGE_INPUT_UNAVAILABLE"
        const val RECEIPT_INVALID = "PCV3_RECEIPT_INVALID"
        const val RELEASE_DENIED = "PCV3_OPERATION_RELEASE_DENIED"
        const val MAX_RECEIPT_BYTES = 4096
        const val ROUTE_PROBE_NAME = "route-probe.bin"
        const val POLL_MILLIS = 25L
        const val TERMINAL_TIMEOUT_MILLIS = 5L * 60L * 1000L

        const val RECEIPT_ID = "r_00112233445566778899aabbccddeeff"
        const val RECEIPT_OPERATION_ID = "op_1700000000000000000_7"
        const val RESTORABLE_RECEIPT = "{\"version\":1,\"receiptID\":\"r_00112233445566778899aabbccddeeff\",\"operationID\":\"op_1700000000000000000_7\",\"outcome\":7,\"stage\":0,\"code\":7,\"forceProvenance\":1,\"d1BootstrapProvenance\":3,\"detailStage\":13,\"publicationAttempted\":true,\"publicationState\":3,\"publicationStage\":24,\"publicationCode\":9,\"args\":[7,11,13,17],\"warnings\":[6,4],\"diagnostic\":0}"

        val NON_VOLUME_SOURCE = "device behavior source without any PCV3 claim".toByteArray(Charsets.UTF_8)
        val KEYFILE_FACTOR = "device behavior keyfile factor".toByteArray(Charsets.UTF_8)
        val CALLER_PASSWORD = "device behavior caller password".toByteArray(Charsets.UTF_8)
        val POLICY_STATES = setOf("configured", "unconfigured")
        val FORBIDDEN_RECEIPT_AUTHORITIES = setOf(
            "operation", "consent", "archive", "retry", "resume",
            "extract", "export", "discard", "cleanup", "delete",
        )
    }
}
