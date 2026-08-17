package io.github.picocrypt_ng.picocrypt_ng

import android.app.ActivityManager
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import mobile.Mobile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/**
 * One-shot instrumentation for the default-excluded calibration AAR.
 *
 * This class is source-authored before physical calibration. It is not product
 * support evidence until the exact whole selector passes on every approved
 * physical serial and its separate observations validate.
 */
@RunWith(AndroidJUnit4::class)
class Pcv3CalibrationDeviceTest {
    @Test
    fun calibration() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val invocation = readInvocation(context)
        val physicalDevice = observePhysicalDevice(context)
        val directory = File(context.cacheDir, "pcv3-calibration-${invocation.runNonce}")
        if (!directory.mkdir()) {
            throw AssertionError("calibration workspace must be newly owned")
        }
        val source = File(directory, "ordinary-input.pcv")
        val target = File(directory, "ordinary-output.bin")
        var primaryFailure: Throwable? = null
        try {
            source.writeBytes(ORDINARY_FIXTURE)

            val ordinary = observeOrdinaryRefusal(source, target)
            val tagged = observeSuccessfulTaggedProbe()
            assertTrue(
                "device total RAM must bound tagged VmHWM",
                tagged.window.afterBytes <= physicalDevice.device.totalRamBytes,
            )

            val observation = JSONObject()
                .put("schema_version", 2)
                .put("provenance", invocation.toJson())
                .put("device", physicalDevice.device.toJson())
                .put(
                    "memory",
                    JSONObject()
                        .put("kdf_bytes", KDF_BYTES)
                        .put("ordinary_vmhwm_before_bytes", ordinary.window.beforeBytes)
                        .put("ordinary_vmhwm_after_bytes", ordinary.window.afterBytes)
                        .put("ordinary_vmhwm_delta_bytes", ordinary.window.deltaBytes)
                        .put("tagged_vmhwm_before_bytes", tagged.window.beforeBytes)
                        .put("tagged_vmhwm_after_bytes", tagged.window.afterBytes)
                        .put("tagged_vmhwm_delta_bytes", tagged.window.deltaBytes)
                        .put(
                            "activity_manager_threshold_bytes",
                            physicalDevice.activityManagerThresholdBytes,
                        )
                        .put("reserve_bytes", tagged.reserveBytes),
                )
                .put("ordinary", ordinary.toJson())
                .put("tagged", tagged.toJson())
            InstrumentationRegistry.getInstrumentation().sendStatus(
                0,
                Bundle().apply { putString(OBSERVATION_STATUS_FIELD, observation.toString()) },
            )
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            attachCleanupFailure(primaryFailure) {
                cleanupFiles(
                    target to "ordinary output",
                    source to "ordinary input",
                    directory to "calibration workspace",
                )
            }
        }
    }

    private fun observeOrdinaryRefusal(source: File, target: File): OperationObservation {
        val beforeBytes = currentHighWaterBytes()
        val password = byteArrayOf(0x6d, 0x69, 0x78)
        val request =
            """{"version":1,"mode":"read-normal","factorPolicy":"password","keyfileOrder":"none","source":${jsonString(source.absolutePath)},"target":${jsonString(target.absolutePath)},"keyfiles":[]}"""
        val start = Mobile.startPCV3(request, password)
        val operation = start.operation()
        var primaryFailure: Throwable? = null
        try {
            assertEquals("ordinary PCV3 start must succeed", "", start.code())
            assertTrue("gomobile must zero the caller password", password.all { it == 0.toByte() })
            val liveOperation = operation
                ?: throw AssertionError("ordinary PCV3 call returned no operation")
            val terminal = awaitTerminal(liveOperation)
            val afterBytes = currentHighWaterBytes()
            val observed = TerminalObservation.from(start.code(), liveOperation, terminal)
            assertEquals("ordinary unconfigured snapshot must stay exact", ordinaryTerminal(), observed)
            val window = highWaterWindow(beforeBytes, afterBytes)
            assertTrue(
                "ordinary unconfigured path must stay below the exact 1 GiB KDF allocation",
                window.deltaBytes < KDF_BYTES,
            )
            assertFalse("unconfigured production policy must create no output", target.exists())
            return OperationObservation(observed, window)
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            if (operation != null) {
                attachCleanupFailure(primaryFailure) { release(operation, "ordinary") }
            }
        }
    }

    private fun observeSuccessfulTaggedProbe(): TaggedOperationObservation {
        val beforeBytes = currentHighWaterBytes()
        val calibrationMethod = Mobile::class.java.methods.singleOrNull {
            it.name == "startPCV3Calibration" && it.parameterTypes.isEmpty()
        }
        assertNotNull("tagged calibration AAR must expose the exact no-argument seam", calibrationMethod)
        val start = calibrationMethod!!.invoke(null) as? mobile.PCV3StartResult
            ?: throw AssertionError("tagged calibration seam returned no start result")
        val operation = start.operation()
        var primaryFailure: Throwable? = null
        try {
            assertEquals("tagged calibration start must succeed", "", start.code())
            val liveOperation = operation
                ?: throw AssertionError("tagged calibration seam returned no operation")
            val terminal = awaitTerminal(liveOperation)
            val afterBytes = currentHighWaterBytes()
            val observed = TerminalObservation.from(start.code(), liveOperation, terminal)
            assertEquals("tagged successful snapshot must stay exact", taggedTerminal(), observed)
            val window = highWaterWindow(beforeBytes, afterBytes)
            assertTrue(
                "tagged VmHWM delta must cover the exact 1 GiB KDF allocation",
                window.deltaBytes >= KDF_BYTES,
            )
            return TaggedOperationObservation(observed, window, reserveBytes(afterBytes))
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            if (operation != null) {
                attachCleanupFailure(primaryFailure) { release(operation, "tagged calibration") }
            }
        }
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

    private fun currentHighWaterBytes(): Long {
        val line = File("/proc/self/status").useLines { lines ->
            lines.firstOrNull { it.startsWith("VmHWM:") }
        } ?: throw AssertionError("Android process VmHWM is unavailable")
        val fields = line.trim().split(Regex("\\s+"))
        if (fields.size != 3 || fields[0] != "VmHWM:" || fields[2] != "kB") {
            throw AssertionError("Android process VmHWM has an unsupported representation")
        }
        val bytes = try {
            Math.multiplyExact(fields[1].toLong(), 1024L)
        } catch (error: ArithmeticException) {
            throw AssertionError("Android process VmHWM overflowed", error)
        }
        assertUint53("Android process VmHWM", bytes)
        return bytes
    }

    private fun highWaterWindow(beforeBytes: Long, afterBytes: Long): HighWaterWindow {
        assertUint53("VmHWM before", beforeBytes)
        assertUint53("VmHWM after", afterBytes)
        val deltaBytes = try {
            Math.subtractExact(afterBytes, beforeBytes)
        } catch (error: ArithmeticException) {
            throw AssertionError("VmHWM decreased or overflowed", error)
        }
        if (deltaBytes < 0) {
            throw AssertionError("VmHWM decreased")
        }
        assertUint53("VmHWM delta", deltaBytes)
        return HighWaterWindow(beforeBytes, afterBytes, deltaBytes)
    }

    private fun reserveBytes(afterBytes: Long): Long {
        val raw = if (afterBytes > KDF_BYTES) {
            Math.subtractExact(afterBytes, KDF_BYTES)
        } else {
            0L
        }
        if (raw == 0L) {
            return 0L
        }
        val rounded = Math.multiplyExact(
            Math.floorDiv(Math.addExact(raw, MIB_BYTES - 1), MIB_BYTES),
            MIB_BYTES,
        )
        assertUint53("calibrated reserve", rounded)
        return rounded
    }

    private fun assertUint53(label: String, value: Long) {
        assertTrue("$label must be a nonnegative JSON-safe integer", value >= 0 && value <= MAX_SAFE_INTEGER)
    }

    private fun observePhysicalDevice(context: android.content.Context): PhysicalDeviceObservation {
        val memory = ActivityManager.MemoryInfo().also {
            val manager = context.getSystemService(ActivityManager::class.java)
                ?: throw AssertionError("Android memory service is unavailable")
            manager.getMemoryInfo(it)
        }
        val abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
        val osArch = System.getProperty("os.arch").orEmpty()
        assertEquals("calibration requires an arm64-v8a runtime", "arm64-v8a", abi)
        assertTrue("calibration requires a 64-bit process", Process.is64Bit())
        assertEquals("calibration requires an aarch64 process", "aarch64", osArch)
        assertTrue("emulator traits must fail closed", pcv3EmulatorTraitsClear())
        assertTrue(
            "device manufacturer must use the bounded evidence alphabet",
            DEVICE_TEXT.matches(Build.MANUFACTURER),
        )
        assertTrue(
            "device model must use the bounded evidence alphabet",
            DEVICE_TEXT.matches(Build.MODEL),
        )
        assertTrue("device total RAM must be positive", memory.totalMem > 0)
        assertUint53("device total RAM", memory.totalMem)
        assertTrue("ActivityManager threshold must be positive", memory.threshold > 0)
        assertUint53("ActivityManager threshold", memory.threshold)
        assertTrue(
            "ActivityManager threshold must be below device total RAM",
            memory.threshold < memory.totalMem,
        )
        return PhysicalDeviceObservation(
            device = DeviceObservation(
                manufacturer = Build.MANUFACTURER,
                model = Build.MODEL,
                abi = abi,
                osArch = osArch,
                totalRamBytes = memory.totalMem,
                buildFingerprintSha256 = hashBuildFingerprint(),
            ),
            activityManagerThresholdBytes = memory.threshold,
        )
    }

    private fun hashBuildFingerprint(): String {
        val fingerprint = Build.FINGERPRINT.orEmpty()
        assertTrue("device build fingerprint must be present", fingerprint.isNotBlank())
        assertFalse("device build fingerprint must not be unknown", fingerprint == Build.UNKNOWN)
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(fingerprint.toByteArray(Charsets.UTF_8))
        return buildString(digest.size * 2) {
            digest.forEach { byte ->
                val value = byte.toInt() and 0xff
                append(HEX_DIGITS[value ushr 4])
                append(HEX_DIGITS[value and 0x0f])
            }
        }.also { encoded ->
            assertTrue("device build fingerprint hash must be lowercase SHA-256", SHA256.matches(encoded))
        }
    }

    private fun readInvocation(context: android.content.Context): InvocationBinding {
        val arguments = InstrumentationRegistry.getArguments()
        assertEquals(
            "calibration must be the sole selected method",
            CALIBRATION_SELECTOR,
            arguments.getString("class"),
        )
        val targetPackage = requiredArgument(arguments, "pcv3_target_package", PACKAGE_NAME)
        val expectedProcessName = requiredArgument(arguments, "pcv3_process_name", PACKAGE_NAME)
        assertEquals("calibration target package must be dedicated", CALIBRATION_TARGET, targetPackage)
        assertEquals("calibration process name must be dedicated", CALIBRATION_TARGET, expectedProcessName)
        assertEquals("calibration must run in the dedicated target package", targetPackage, context.packageName)
        val processName = currentProcessName()
        assertEquals("calibration must run in the expected process", expectedProcessName, processName)
        val processID = Process.myPid().toLong()
        assertTrue("calibration process ID must be positive", processID > 0)
        assertUint53("calibration process ID", processID)
        return InvocationBinding(
            runNonce = requiredArgument(arguments, "pcv3_run_nonce", SHA256),
            matrixSerial = requiredArgument(arguments, "pcv3_matrix_serial", SERIAL),
            matrixSha256 = requiredArgument(arguments, "pcv3_matrix_sha256", SHA256),
            candidateCommit = requiredArgument(arguments, "pcv3_candidate_commit", SHA1),
            candidateTree = requiredArgument(arguments, "pcv3_candidate_tree", SHA1),
            aarSha256 = requiredArgument(arguments, "pcv3_aar_sha256", SHA256),
            apkSha256 = requiredArgument(arguments, "pcv3_apk_sha256", SHA256),
            testApkSha256 = requiredArgument(arguments, "pcv3_test_apk_sha256", SHA256),
            targetPackage = targetPackage,
            processName = processName,
            processID = processID,
        )
    }

    private fun currentProcessName(): String {
        val bytes = File("/proc/self/cmdline").readBytes()
        val end = bytes.indexOf(0.toByte()).let { if (it < 0) bytes.size else it }
        val value = bytes.copyOfRange(0, end).toString(Charsets.UTF_8)
        assertTrue("process name must use the exact package alphabet", PACKAGE_NAME.matches(value))
        return value
    }

    private fun requiredArgument(arguments: Bundle, name: String, allowed: Regex): String {
        val value = arguments.getString(name).orEmpty()
        assertTrue("$name must use its exact bounded alphabet", allowed.matches(value))
        return value
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
        fun toJson(): JSONObject = JSONObject()
            .put("start_code", startCode)
            .put("status_code", statusCode)
            .put("status_args", JSONArray(statusArgs))
            .put("outcome", outcome)
            .put("stage", stage)
            .put("code", code)
            .put("force_provenance", forceProvenance)
            .put("d1_bootstrap_provenance", d1BootstrapProvenance)
            .put("detail_stage", detailStage)
            .put("diagnostic", diagnostic)
            .put("completion", completion)
            .put("publication_attempted", publicationAttempted)
            .put("publication_state", publicationState)
            .put("publication_stage", publicationStage)
            .put("publication_code", publicationCode)
            .put("result_args", JSONArray(resultArgs))
            .put("warnings", JSONArray(warnings))
            .put("archive_pending", archivePending)
            .put("consent_present", consentPresent)
            .put("archive_present", archivePresent)
            .put("restored_receipt_present", restoredReceiptPresent)

        companion object {
            fun from(
                startCode: String,
                operation: mobile.PCV3Operation,
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
                consentPresent = operation.consent() != null,
                archivePresent = operation.archive() != null,
                restoredReceiptPresent = snapshot.restoredReceipt().isNotEmpty(),
            )
        }
    }

    private data class HighWaterWindow(
        val beforeBytes: Long,
        val afterBytes: Long,
        val deltaBytes: Long,
    )

    private data class OperationObservation(
        val terminal: TerminalObservation,
        val window: HighWaterWindow,
    ) {
        fun toJson(): JSONObject = terminal.toJson()
    }

    private data class TaggedOperationObservation(
        val terminal: TerminalObservation,
        val window: HighWaterWindow,
        val reserveBytes: Long,
    ) {
        fun toJson(): JSONObject = terminal.toJson()
    }

    private data class InvocationBinding(
        val runNonce: String,
        val matrixSerial: String,
        val matrixSha256: String,
        val candidateCommit: String,
        val candidateTree: String,
        val aarSha256: String,
        val apkSha256: String,
        val testApkSha256: String,
        val targetPackage: String,
        val processName: String,
        val processID: Long,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("run_nonce", runNonce)
            .put("matrix_serial", matrixSerial)
            .put("matrix_sha256", matrixSha256)
            .put("candidate_commit", candidateCommit)
            .put("candidate_tree", candidateTree)
            .put("aar_sha256", aarSha256)
            .put("apk_sha256", apkSha256)
            .put("test_apk_sha256", testApkSha256)
            .put("target_package", targetPackage)
            .put("process_name", processName)
            .put("process_id", processID)
    }

    private data class DeviceObservation(
        val manufacturer: String,
        val model: String,
        val abi: String,
        val osArch: String,
        val totalRamBytes: Long,
        val buildFingerprintSha256: String,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("manufacturer", manufacturer)
            .put("model", model)
            .put("abi", abi)
            .put("os_arch", osArch)
            .put("process_is_64_bit", true)
            .put("emulator_traits_clear", true)
            .put("total_ram_bytes", totalRamBytes)
            .put("build_fingerprint_sha256", buildFingerprintSha256)
    }

    private data class PhysicalDeviceObservation(
        val device: DeviceObservation,
        val activityManagerThresholdBytes: Long,
    )

    private fun ordinaryTerminal() = TerminalObservation(
        startCode = "",
        statusCode = "checking-resources",
        statusArgs = emptyList(),
        outcome = "operation-failed",
        stage = "credential-policy",
        code = "PCV3_OPERATION_FAILED",
        forceProvenance = "none",
        d1BootstrapProvenance = "none",
        detailStage = "none",
        diagnostic = "resource-unknown",
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

    private fun taggedTerminal() = TerminalObservation(
        startCode = "",
        statusCode = "none",
        statusArgs = emptyList(),
        outcome = "success",
        stage = "none",
        code = "success",
        forceProvenance = "none",
        d1BootstrapProvenance = "none",
        detailStage = "none",
        diagnostic = "none",
        completion = "no-output",
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

    private companion object {
        const val OBSERVATION_STATUS_FIELD = "pcv3_calibration_observation"
        const val CALIBRATION_SELECTOR =
            "io.github.picocrypt_ng.picocrypt_ng.Pcv3CalibrationDeviceTest#calibration"
        const val KDF_BYTES = 1L shl 30
        const val MIB_BYTES = 1L shl 20
        const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
        const val POLL_MILLIS = 25L
        const val TERMINAL_TIMEOUT_MILLIS = 5L * 60L * 1000L

        val SHA1 = Regex("^[0-9a-f]{40}$")
        val SHA256 = Regex("^[0-9a-f]{64}$")
        const val HEX_DIGITS = "0123456789abcdef"
        val SERIAL = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
        val PACKAGE_NAME = Regex("^[a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*)+$")
        val DEVICE_TEXT = Regex("^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,127}$")
        const val CALIBRATION_TARGET =
            "io.github.picocrypt_ng.picocrypt_ng.pcv3_calibration"
        val ORDINARY_FIXTURE: ByteArray = android.util.Base64.decode(
            "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",
            android.util.Base64.DEFAULT,
        )
    }
}
