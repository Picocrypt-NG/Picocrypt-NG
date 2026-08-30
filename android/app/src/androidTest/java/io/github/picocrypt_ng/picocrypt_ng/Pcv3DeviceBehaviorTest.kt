package io.github.picocrypt_ng.picocrypt_ng

import android.app.ActivityManager
import android.os.Debug
import android.os.ParcelFileDescriptor
import android.os.Process
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
import org.junit.Assume
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
            // The cleanup helper cannot distinguish an already-released
            // operation from a just-started one through the bridge, so the
            // success path records its own release.
            var operationReleased = false
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
                operationReleased = true
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
                    attachCleanupFailure(primaryFailure) { release(operation, "ownership", operationReleased) }
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
            assertEquals(
                "the production AAR must use fresh runtime admission",
                "configured",
                Mobile.pcV3AndroidPolicyState(),
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
            // The migrate seam is not a bridge mode at all: it stays refused wholesale.
            val migratePassword = CALLER_PASSWORD.copyOf()
            val rejectedMigrate = Mobile.startPCV3(
                envelope("migrate-normal", "password", "none", source, target, emptyList()),
                migratePassword,
            )
            assertEquals(
                "the migrate-normal seam must stay refused",
                BRIDGE_INVALID_REQUEST,
                rejectedMigrate.code(),
            )
            assertNull("a refused migrate-normal seam must return no operation", rejectedMigrate.operation())
            assertTrue(
                "a refused migrate-normal seam must zero the caller password",
                migratePassword.all { it == 0.toByte() },
            )
            assertFalse("a refused migrate-normal seam must create no output", target.exists())

            // write-normal is a live creation mode now, but the exact write-shaped
            // field set (comment/suite/payloadRS in addition to the shared fields) is
            // enforced: a read-shaped envelope is refused as the wrong shape before any
            // operation or output exists.
            val writePassword = CALLER_PASSWORD.copyOf()
            val rejectedWrite = Mobile.startPCV3(
                envelope("write-normal", "password", "none", source, target, emptyList()),
                writePassword,
            )
            assertEquals(
                "a read-shaped write-normal envelope must be refused as the wrong shape",
                BRIDGE_INVALID_REQUEST,
                rejectedWrite.code(),
            )
            assertNull("a wrong-shape write-normal envelope must return no operation", rejectedWrite.operation())
            assertTrue(
                "a refused write-normal envelope must zero the caller password",
                writePassword.all { it == 0.toByte() },
            )
            assertFalse("a refused write-normal envelope must create no output", target.exists())

            val password = CALLER_PASSWORD.copyOf()
            val start = Mobile.startPCV3(
                envelope("read-normal", "password", "none", source, target, emptyList()),
                password,
            )
            val operation = start.operation()
            var operationReleased = false
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
                operationReleased = true
            } catch (failure: Throwable) {
                primaryFailure = failure
                throw failure
            } finally {
                if (operation != null) {
                    attachCleanupFailure(primaryFailure) { release(operation, "final read", operationReleased) }
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

    @Test
    fun v11WriteNormalCreationRoundTrip() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val directory = File(context.cacheDir, "pcv3-v11-creation")
        assertFalse("v11 workspace residue from an earlier attempt", directory.exists())
        if (!directory.mkdir()) {
            throw AssertionError("v11 workspace must be newly owned")
        }
        val source = File(directory, "creation-plaintext.bin")
        val target = File(directory, "creation-staging.pcv")
        val saved = File(directory, "creation-volume.pcv")
        val roundTrip = File(directory, "creation-roundtrip.bin")
        var primaryFailure: Throwable? = null
        try {
            source.writeBytes(ROUND_TRIP_PLAINTEXT)

            val password = CALLER_PASSWORD.copyOf()
            val start = Mobile.startPCV3(
                writeEnvelope("write-normal", source, target),
                password,
            )
            val operation = start.operation()
            // The success path releases the operation itself; the flag tells
            // the cleanup helper the release already happened so it verifies
            // the released state instead of re-releasing.
            var operationReleased = false
            try {
                assertEquals("creation start must succeed", "", start.code())
                assertTrue(
                    "bridge must zero the caller password before returning",
                    password.all { it == 0.toByte() },
                )
                val liveOperation = operation
                    ?: throw AssertionError("creation start returned no operation")
                val terminal = awaitTerminalPumping(context, liveOperation)
                skipOnResourceAdmissionDenial(terminal)
                assertEquals("creation must succeed", "success", terminal.outcome())
                assertEquals("creation must leave no failure stage", "none", terminal.stage())
                assertEquals("creation must report success", "PCV3_SUCCESS", terminal.code())
                assertEquals("creation must carry no diagnostic", "none", terminal.diagnostic())
                assertEquals("creation must complete clean", "clean", terminal.completionClass())
                assertTrue("creation must attempt publication", terminal.publicationAttempted())
                assertEquals(
                    "creation must publish durably",
                    "published-durable",
                    terminal.publicationState(),
                )
                assertEquals("creation must leave no publication stage", "none", terminal.publicationStage())
                assertEquals(
                    "creation must report durable publication",
                    "PCV3_PUBLICATION_PUBLISHED_DURABLE",
                    terminal.publicationCode(),
                )
                assertEquals("creation must raise no warnings", 0L, terminal.warningCount())
                assertFalse("creation must not pend an archive", terminal.archivePending())
                val output = liveOperation.output()
                    ?: throw AssertionError("durable creation retained no output authority")
                assertEquals(
                    "release with a live creation output must stay denied",
                    RELEASE_DENIED,
                    liveOperation.release(),
                )

                // SAF-shaped transfer: the created volume moves out of staging
                // through a caller-owned descriptor, exactly like the UI path.
                val destination = ParcelFileDescriptor.open(
                    saved,
                    ParcelFileDescriptor.MODE_READ_WRITE or ParcelFileDescriptor.MODE_CREATE,
                )
                val transferred = output.saveFD(destination.detachFd().toLong())
                assertEquals("creation output transfer must save", "saved", transferred.code())
                assertFalse("creation output transfer must complete cleanup", transferred.cleanupIncomplete())
                assertFalse("a transferred volume must leave staging", target.exists())
                assertEquals("a transferred output must act once", "expired", output.discard().code())
                assertEquals("creation release must succeed", "", liveOperation.release())
                operationReleased = true
            } catch (failure: Throwable) {
                primaryFailure = failure
                throw failure
            } finally {
                if (operation != null) {
                    attachCleanupFailure(primaryFailure) { release(operation, "creation", operationReleased) }
                }
            }

            val readPassword = CALLER_PASSWORD.copyOf()
            val read = Mobile.startPCV3(
                envelope("read-normal", "password", "none", saved, roundTrip, emptyList()),
                readPassword,
            )
            val readOperation = read.operation()
            var readReleased = false
            try {
                assertEquals("round-trip read start must succeed", "", read.code())
                assertTrue(
                    "bridge must zero the read caller password before returning",
                    readPassword.all { it == 0.toByte() },
                )
                val liveRead = readOperation
                    ?: throw AssertionError("round-trip read start returned no operation")
                val readTerminal = awaitTerminalPumping(context, liveRead)
                skipOnResourceAdmissionDenial(readTerminal)
                assertEquals("round-trip read must succeed", "success", readTerminal.outcome())
                assertEquals("round-trip read must complete clean", "clean", readTerminal.completionClass())
                assertEquals("round-trip read must expose the empty comment", "", readTerminal.authenticatedComment())
                assertTrue(
                    "round-trip plaintext must be byte-exact",
                    ROUND_TRIP_PLAINTEXT.contentEquals(roundTrip.readBytes()),
                )
                val readOutput = liveRead.output()
                    ?: throw AssertionError("round-trip read retained no output authority")
                assertEquals("round-trip read output must discard", "discarded", readOutput.discard().code())
                assertEquals("round-trip read release must succeed", "", liveRead.release())
                readReleased = true
            } catch (failure: Throwable) {
                primaryFailure = failure
                throw failure
            } finally {
                if (readOperation != null) {
                    attachCleanupFailure(primaryFailure) { release(readOperation, "round-trip read", readReleased) }
                }
            }
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            attachCleanupFailure(primaryFailure) {
                cleanupFiles(
                    roundTrip to "round-trip plaintext",
                    saved to "transferred volume",
                    target to "creation staging",
                    source to "creation plaintext",
                    directory to "v11 workspace",
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

    /**
     * Awaits the terminal snapshot while answering each KDF resource challenge
     * with fresh, real ActivityManager facts, mirroring the production pump in
     * OperationManager. A challenge the device cannot answer inside its bounded
     * window surfaces as a resource diagnostic, which the caller skips on.
     */
    private fun awaitTerminalPumping(
        context: android.content.Context,
        operation: mobile.PCV3Operation,
    ): mobile.PCV3Snapshot {
        val deadline = SystemClock.elapsedRealtime() + TERMINAL_TIMEOUT_MILLIS
        while (SystemClock.elapsedRealtime() < deadline) {
            val challenge = operation.resourceChallenge()
            if (challenge != null) {
                submitDeviceFacts(context, challenge)
            }
            val snapshot = operation.snapshot()
            if (snapshot.completionClass() != "unknown") {
                return snapshot
            }
            SystemClock.sleep(POLL_MILLIS)
        }
        throw AssertionError("PCV3 operation did not reach a terminal state")
    }

    private fun submitDeviceFacts(context: android.content.Context, challenge: mobile.PCV3ResourceChallenge) {
        val manager = context.getSystemService(ActivityManager::class.java) ?: return
        val system = ActivityManager.MemoryInfo()
        manager.getMemoryInfo(system)
        val process = Debug.MemoryInfo()
        Debug.getMemoryInfo(process)
        val footprint = process.totalPss.toLong() * 1024
        if (system.totalMem <= 0 || system.availMem <= 0 || system.threshold <= 0 || footprint <= 0) {
            return
        }
        challenge.submit(
            system.totalMem,
            system.availMem,
            system.threshold,
            footprint,
            Process.is64Bit(),
            system.lowMemory,
        )
    }

    /**
     * The fixed 1 GiB Argon2id profile is genuinely unaffordable on some
     * devices; an admission denial is environment evidence, not a product
     * regression, so it skips with the exact diagnostic.
     */
    private fun skipOnResourceAdmissionDenial(snapshot: mobile.PCV3Snapshot) {
        Assume.assumeFalse(
            "resource-admission environment skip: the platform admitter refused the fixed 1 GiB " +
                "KDF profile on this device (diagnostic ${snapshot.diagnostic()})",
            RESOURCE_ADMISSION_DIAGNOSTICS.contains(snapshot.diagnostic()),
        )
    }

    /**
     * Cleanup release for an operation. [alreadyReleased] must be true exactly
     * when the test body already released the operation itself.
     *
     * RELEASE_DENIED is ambiguous on the bridge (src/mobile/progress.go
     * Release): it covers both a genuinely live operation (not terminal, or a
     * live consent/archive/output capability retains it) and an operation that
     * is already released and therefore gone from the registry. The registry
     * lookup behind that difference is not observable through the bridge: a
     * released operation's snapshot is the invalid all-"unknown" one, but a
     * just-started live operation presents the same zero snapshot until its
     * first status report. The caller's release fact is the only exact
     * discriminator, so this helper stays strict in both directions: a
     * body-released operation must stay released, and any other operation is
     * cancelled, driven to terminal, and released, failing loudly when it
     * still refuses.
     */
    private fun release(operation: mobile.PCV3Operation, label: String, alreadyReleased: Boolean) {
        if (alreadyReleased) {
            val code = operation.release()
            if (code != RELEASE_DENIED) {
                throw AssertionError("$label operation must stay released after the body release: $code")
            }
            val completion = operation.snapshot().completionClass()
            if (completion != "unknown") {
                throw AssertionError("$label released operation must expose only the unknown snapshot: $completion")
            }
            return
        }
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

    private fun writeEnvelope(mode: String, source: File, target: File): String =
        """{"version":1,"mode":${jsonString(mode)},"factorPolicy":"password","keyfileOrder":"none","source":${jsonString(source.absolutePath)},"target":${jsonString(target.absolutePath)},"keyfiles":[],"comment":"","suite":"standard","payloadRS":false}"""

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
        val ROUND_TRIP_PLAINTEXT = "device creation round-trip payload\u0000\u0001\u0002".toByteArray(Charsets.UTF_8)
        val RESOURCE_ADMISSION_DIAGNOSTICS = setOf("resource-busy", "resource-insufficient", "resource-unknown")
        val FORBIDDEN_RECEIPT_AUTHORITIES = setOf(
            "operation", "consent", "archive", "retry", "resume",
            "extract", "export", "discard", "cleanup", "delete",
        )
    }
}
