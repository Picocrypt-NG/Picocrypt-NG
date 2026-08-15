package io.github.picocrypt_ng.picocrypt_ng

import android.os.Parcelable
import android.os.ParcelFileDescriptor
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.parcelize.Parcelize
import mobile.Mobile
import mobile.PCV3ArtifactInspection
import mobile.PCV3ArtifactPage
import mobile.PCV3Archive
import mobile.PCV3ArchiveBegin
import mobile.PCV3ArchiveSession
import mobile.PCV3ArchiveStep
import mobile.PCV3Operation
import mobile.PCV3Output
import mobile.PCV3OutputResult
import mobile.PCV3ResourceChallenge
import mobile.PCV3RestoredReceipt
import mobile.PCV3Snapshot
import mobile.PCV3StartResult
import mobile.ProgressResult as GoProgressResult
import org.json.JSONArray
import org.json.JSONObject

/**
 * Options for encryption operations.
 * This is the Kotlin representation of the Go EncryptOptions struct.
 */
data class EncryptOptions(
    val comments: String = "",
    val paranoid: Boolean = false,
    val reedSolomon: Boolean = false,
    val deniability: Boolean = false,
    val compress: Boolean = false,
    val keyfiles: List<String> = emptyList(),
    val keyfileOrdered: Boolean = false
)

/**
 * Options for decryption operations.
 * This is the Kotlin representation of the Go DecryptOptions struct.
 */
data class DecryptOptions(
    val keyfiles: List<String> = emptyList(),
    val forceDecrypt: Boolean = false,
    val verifyFirst: Boolean = false,
    val autoUnzip: Boolean = false,
    val sameLevel: Boolean = false,
    val recombine: Boolean = false,
    val deniability: Boolean = false
)

/**
 * Decryption metadata information.
 * This contains encryption settings and requirements that can be read
 * from an encrypted file without decrypting it.
 */
@Parcelize
data class DecryptionInfo(
    val keyfilesRequired: Boolean,
    val keyfileOrdered: Boolean,
    val reedSolomon: Boolean,
    val deniability: Boolean,
    val paranoid: Boolean,
    val comments: String,
    val readable: Boolean // false if deniable (can't read other fields without password)
) : Parcelable

/**
 * Progress state for an operation.
 * This is the Kotlin representation of the Go ProgressResult struct.
 */
data class ProgressState(
    val status: OperationStatusData,
    val detail: OperationProgressDetail,
    val progress: Float,
    val done: Boolean,
    val technicalError: String = "",
    val errorCode: String = "",
)

/** Strict, authority-free request envelope for one explicit PCV3 read operation. */
data class Pcv3Request(
    val mode: String,
    val factorPolicy: String,
    val keyfileOrder: String,
    val source: String,
    val target: String,
    val keyfiles: List<String>,
)

enum class Pcv3Route {
    LEGACY,
    NORMAL,
    UNSUPPORTED,
    INVALID,
}

/** Static Android presentation configuration; never an operation admission. */
enum class Pcv3AndroidPolicyState {
    CONFIGURED,
    UNCONFIGURED,
}

data class Pcv3SnapshotData(
    val statusCode: String, val statusArgs: List<String>, val outcome: String, val stage: String, val code: String,
    val forceProvenance: String, val d1BootstrapProvenance: String, val detailStage: String,
    val publicationAttempted: Boolean, val publicationState: String, val publicationStage: String, val publicationCode: String,
    val diagnostic: String, val completionClass: String, val args: List<String>, val warnings: List<String>, val archivePending: Boolean,
    val restoredReceipt: String = "",
)
interface Pcv3OperationCapability {
    val id: String
    fun snapshot(): Pcv3SnapshotData
    fun consent(): Pcv3ConsentCapability?
    fun archive(): Pcv3ArchiveCapability?
    fun output(): Pcv3OutputCapability? = null
    fun artifactInspection(): Pcv3ArtifactInspectionCapability? = null
    fun resourceChallenge(): Pcv3ResourceChallengeCapability? = null
    fun cancel(): Pcv3SnapshotData
    fun release(): String
}
interface Pcv3ResourceChallengeCapability {
    fun submit(observation: Pcv3AndroidResourceObservation): Boolean
}
interface Pcv3ConsentCapability { fun mode(): String; fun roles(): List<String>; fun choose(role: String): String; fun refuse(): String }
data class Pcv3ArchiveBeginData(
    val kind: String,
    val code: String,
    val session: Pcv3ArchiveSessionCapability?,
    val snapshot: Pcv3SnapshotData?,
)

interface Pcv3ArchiveCapability {
    fun close(): Pcv3SnapshotData
    fun beginSaf(): Pcv3ArchiveBeginData
}

internal interface Pcv3ArchiveNative {
    fun close(): Pcv3SnapshotData
    fun beginSaf(): Pcv3ArchiveBeginData
}

/**
 * Projects non-owning Begin fields only after the native session authority is retained.
 * A partial ABI projection is deliberately non-actionable so the lifecycle drains the session.
 */
internal fun projectPcv3ArchiveBegin(
    capturedSession: Pcv3ArchiveSessionCapability?,
    kind: () -> String,
    code: () -> String,
    snapshot: () -> Pcv3SnapshotData?,
): Pcv3ArchiveBeginData = try {
    Pcv3ArchiveBeginData(
        kind = kind(),
        code = code(),
        session = capturedSession,
        snapshot = snapshot(),
    )
} catch (_: Exception) {
    Pcv3ArchiveBeginData("malformed", "PCV3_ARCHIVE_UNAVAILABLE", capturedSession, null)
} catch (_: LinkageError) {
    Pcv3ArchiveBeginData("malformed", "PCV3_ARCHIVE_UNAVAILABLE", capturedSession, null)
}

/** Linear Kotlin wrapper; the generated gomobile capability remains the sole authority. */
internal class GoPcv3Archive(
    private val native: Pcv3ArchiveNative,
) : Pcv3ArchiveCapability {
    override fun close(): Pcv3SnapshotData = native.close()
    override fun beginSaf(): Pcv3ArchiveBeginData = native.beginSaf()
}
data class Pcv3OutputResultData(val code: String, val cleanupIncomplete: Boolean)
interface Pcv3OutputCapability {
    fun save(destination: ParcelFileDescriptor): Pcv3OutputResultData
    fun discard(): Pcv3OutputResultData
}

/** Immutable path-free artifact summary exported by the generated gomobile ABI. */
data class Pcv3ArtifactMetadataData(
    val kind: String,
    val role: String,
    val plaintextLength: String,
    val finalStatus: String,
    val rangeCount: String,
    val verifiedCount: String,
    val unverifiedCount: String,
    val missingCount: String,
)

/** One immutable evidence range; every unsigned value remains canonical decimal text. */
data class Pcv3ArtifactRangeData(
    val recordIndex: String,
    val start: String,
    val end: String,
    val status: String,
)

data class Pcv3ArtifactPageData(
    val offsetDecimal: String,
    val ranges: List<Pcv3ArtifactRangeData>,
)

/** Passive inspection only: it grants no save, discard, open, path, or identity action. */
interface Pcv3ArtifactInspectionCapability {
    fun metadata(): Pcv3ArtifactMetadataData?
    fun page(offsetDecimal: String, limit: Int): Pcv3ArtifactPageData?
}
data class Pcv3StartData(val code: String, val operation: Pcv3OperationCapability?)
data class Pcv3RestoredReceiptData(
    val code: String,
    val receiptId: String,
    val operationId: String,
    val snapshot: Pcv3SnapshotData?,
)

/** A bounded PCV3 bridge refusal; raw native diagnostics never cross this boundary. */
internal class Pcv3BridgeFailure(code: String) : IllegalStateException(code)

/** Native-only transport; tests inject a stateful contract fake at this seam. */
internal interface Pcv3Transport {
    fun start(requestJson: String, password: ByteArray): Pcv3StartData
    fun restoreReceipt(receipt: String): Pcv3RestoredReceiptData
}

/**
 * Owns the transient Kotlin password representation around a PCV3 native call.
 * A non-empty core code is data, rather than a reason to discard a returned handle:
 * [Pcv3Lifecycle] retains and drains that handle before surfacing the code.
 */
internal class Pcv3Bridge(private val transport: Pcv3Transport) {
    fun start(request: Pcv3Request, password: CharArray): Result<Pcv3StartData> {
        var passwordBytes: ByteArray? = null
        return try {
            passwordBytes = encodePcv3Password(password)
            Result.success(transport.start(GoBridge.buildPcv3RequestJson(request), passwordBytes))
        } catch (_: CharacterCodingException) {
            Result.failure(Pcv3BridgeFailure("PCV3_BRIDGE_INVALID_REQUEST"))
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            Result.failure(Pcv3BridgeFailure("PCV3_BRIDGE_FAILURE"))
        } finally {
            password.fill('\u0000')
            passwordBytes?.fill(0)
        }
    }

    fun restoreReceipt(receipt: String): Result<Pcv3RestoredReceiptData> = try {
        Result.success(transport.restoreReceipt(receipt))
    } catch (error: CancellationException) {
        throw error
    } catch (_: Exception) {
        Result.failure(Pcv3BridgeFailure("PCV3_RECEIPT_INVALID"))
    }
}

private fun encodePcv3Password(password: CharArray): ByteArray {
    val input = CharBuffer.wrap(password)
    val encoder = Charsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
    val capacity = (input.remaining() * encoder.maxBytesPerChar()).toInt()
    val buffer = ByteBuffer.allocate(capacity)
    try {
        val encoded = encoder.encode(input, buffer, true)
        if (encoded.isError) encoded.throwException()
        val flushed = encoder.flush(buffer)
        if (flushed.isError) flushed.throwException()
        buffer.flip()
        return ByteArray(buffer.remaining()).also(buffer::get)
    } finally {
        buffer.array().fill(0)
    }
}

internal fun pcv3BridgeCode(code: String): String = when (code) {
    "PCV3_BRIDGE_INVALID_REQUEST",
    "PCV3_BRIDGE_INPUT_UNAVAILABLE",
    "PCV3_BRIDGE_KEYFILE_UNAVAILABLE",
    "PCV3_BRIDGE_OPERATION_UNAVAILABLE",
    "PCV3_RECEIPT_INVALID",
    -> code
    else -> "PCV3_BRIDGE_FAILURE"
}

/** Closed, fail-safe projection of the immutable policy state exported by one AAR. */
internal fun readPcv3AndroidPolicyState(
    nativeState: () -> String,
): Pcv3AndroidPolicyState = try {
    when (nativeState()) {
        "configured" -> Pcv3AndroidPolicyState.CONFIGURED
        "unconfigured" -> Pcv3AndroidPolicyState.UNCONFIGURED
        else -> Pcv3AndroidPolicyState.UNCONFIGURED
    }
} catch (_: Exception) {
    Pcv3AndroidPolicyState.UNCONFIGURED
} catch (_: LinkageError) {
    Pcv3AndroidPolicyState.UNCONFIGURED
}

internal fun interface Pcv3JournalCleanupNative {
    fun cleanup(parentPath: String): String
}

/** Closed projection of the Go-owned exact-stage cleanup boundary. */
internal fun cleanupPcv3Journal(
    parentPath: String,
    native: Pcv3JournalCleanupNative,
): Pcv3JournalCleanupState = try {
    when (native.cleanup(parentPath)) {
        "absent" -> Pcv3JournalCleanupState.ABSENT
        "cleaned" -> Pcv3JournalCleanupState.CLEANED
        else -> Pcv3JournalCleanupState.INCOMPLETE
    }
} catch (error: CancellationException) {
    throw error
} catch (_: Exception) {
    Pcv3JournalCleanupState.INCOMPLETE
} catch (_: LinkageError) {
    Pcv3JournalCleanupState.INCOMPLETE
}

private val pcv3SaveResultCodes = setOf(
    "saved",
    "saved-cleanup-incomplete",
    "save-failed",
    "save-failed-cleanup-incomplete",
    "expired",
)
private val pcv3DiscardResultCodes = setOf(
    "discarded",
    "discard-cleanup-incomplete",
    "expired",
)

private fun PCV3OutputResult?.toPcv3OutputData(
    allowedCodes: Set<String>,
    failureCode: String,
): Pcv3OutputResultData {
    if (this == null) return Pcv3OutputResultData(failureCode, cleanupIncomplete = true)
    val code = code()
    val cleanupIsIncomplete = cleanupIncomplete()
    val codeRequiresCleanupWarning = code.endsWith("-cleanup-incomplete")
    if (code !in allowedCodes || codeRequiresCleanupWarning != cleanupIsIncomplete) {
        return Pcv3OutputResultData(failureCode, cleanupIncomplete = true)
    }
    return Pcv3OutputResultData(code, cleanupIsIncomplete)
}

/** Narrow JNI adapter so JVM custody tests do not need to load the device library. */
internal interface Pcv3OutputNative {
    fun saveFD(descriptor: Long): Pcv3OutputResultData
    fun discard(): Pcv3OutputResultData
}

private class GoMobilePcv3Output(private val native: PCV3Output) : Pcv3OutputNative {
    override fun saveFD(descriptor: Long): Pcv3OutputResultData = native.saveFD(descriptor).toPcv3OutputData(
        allowedCodes = pcv3SaveResultCodes,
        failureCode = "save-failed-cleanup-incomplete",
    )

    override fun discard(): Pcv3OutputResultData = native.discard().toPcv3OutputData(
        allowedCodes = pcv3DiscardResultCodes,
        failureCode = "discard-cleanup-incomplete",
    )
}

/** Linear Kotlin owner around the one Go-owned retained-output capability. */
internal class GoPcv3Output(private val native: Pcv3OutputNative) : Pcv3OutputCapability {
    override fun save(destination: ParcelFileDescriptor): Pcv3OutputResultData {
        val descriptor = try {
            destination.detachFd()
        } catch (error: CancellationException) {
            destination.closeAttachedPcv3Destination()
            throw error
        } catch (_: Exception) {
            destination.closeAttachedPcv3Destination()
            return Pcv3OutputResultData("save-failed-cleanup-incomplete", cleanupIncomplete = true)
        } catch (_: LinkageError) {
            destination.closeAttachedPcv3Destination()
            return Pcv3OutputResultData("save-failed-cleanup-incomplete", cleanupIncomplete = true)
        }

        return try {
            native.saveFD(descriptor.toLong())
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            return Pcv3OutputResultData("save-failed-cleanup-incomplete", cleanupIncomplete = true)
        } catch (_: LinkageError) {
            return Pcv3OutputResultData("save-failed-cleanup-incomplete", cleanupIncomplete = true)
        }
    }

    override fun discard(): Pcv3OutputResultData = try {
        native.discard()
    } catch (error: CancellationException) {
        throw error
    } catch (_: Exception) {
        Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true)
    } catch (_: LinkageError) {
        Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true)
    }
}

/** Narrow native seam: the nine raw observations are the entire Android authority. */
internal interface Pcv3ResourceChallengeNative {
    fun submit(
        manufacturer: String,
        model: String,
        abi: String,
        osArch: String,
        totalRamBytes: Long,
        effectiveAvailableBytes: Long,
        processIs64Bit: Boolean,
        emulatorTraitsClear: Boolean,
        lowMemory: Boolean,
    ): Boolean
}

private class GoMobilePcv3ResourceChallenge(
    private val native: PCV3ResourceChallenge,
) : Pcv3ResourceChallengeNative {
    override fun submit(
        manufacturer: String,
        model: String,
        abi: String,
        osArch: String,
        totalRamBytes: Long,
        effectiveAvailableBytes: Long,
        processIs64Bit: Boolean,
        emulatorTraitsClear: Boolean,
        lowMemory: Boolean,
    ): Boolean = native.submit(
        manufacturer,
        model,
        abi,
        osArch,
        totalRamBytes,
        effectiveAvailableBytes,
        processIs64Bit,
        emulatorTraitsClear,
        lowMemory,
    )
}

internal class GoPcv3ResourceChallenge(
    private val native: Pcv3ResourceChallengeNative,
) : Pcv3ResourceChallengeCapability {
    override fun submit(observation: Pcv3AndroidResourceObservation): Boolean = try {
        native.submit(
            observation.manufacturer,
            observation.model,
            observation.abi,
            observation.osArch,
            observation.totalRamBytes,
            observation.effectiveAvailableBytes,
            observation.processIs64Bit,
            observation.emulatorTraitsClear,
            observation.lowMemory,
        )
    } catch (error: CancellationException) {
        throw error
    } catch (_: Exception) {
        false
    } catch (_: LinkageError) {
        false
    }
}

/** Narrow generated-AAR seams keep local JVM tests independent of libgojni. */
internal interface Pcv3ArtifactInspectionNative {
    fun kind(): String
    fun role(): String
    fun plaintextLength(): String
    fun finalStatus(): String
    fun rangeCount(): String
    fun verifiedCount(): String
    fun unverifiedCount(): String
    fun missingCount(): String
    fun page(offsetDecimal: String, limit: Long): Pcv3ArtifactPageNative?
}

internal interface Pcv3ArtifactPageNative {
    fun count(): Long
    fun recordIndexAt(index: Long): String
    fun startAt(index: Long): String
    fun endAt(index: Long): String
    fun statusAt(index: Long): String
}

private class GoMobilePcv3ArtifactInspection(
    private val native: PCV3ArtifactInspection,
) : Pcv3ArtifactInspectionNative {
    override fun kind(): String = native.kind()
    override fun role(): String = native.role()
    override fun plaintextLength(): String = native.plaintextLength()
    override fun finalStatus(): String = native.finalStatus()
    override fun rangeCount(): String = native.rangeCount()
    override fun verifiedCount(): String = native.verifiedCount()
    override fun unverifiedCount(): String = native.unverifiedCount()
    override fun missingCount(): String = native.missingCount()
    override fun page(offsetDecimal: String, limit: Long): Pcv3ArtifactPageNative? =
        native.page(offsetDecimal, limit)?.let(::GoMobilePcv3ArtifactPage)
}

private class GoMobilePcv3ArtifactPage(
    private val native: PCV3ArtifactPage,
) : Pcv3ArtifactPageNative {
    override fun count(): Long = native.count()
    override fun recordIndexAt(index: Long): String = native.recordIndexAt(index)
    override fun startAt(index: Long): String = native.startAt(index)
    override fun endAt(index: Long): String = native.endAt(index)
    override fun statusAt(index: Long): String = native.statusAt(index)
}

private val pcv3ArtifactKinds = setOf("partial", "unverified-forensic")
private val pcv3ArtifactRoles = setOf("none", "primary", "backup", "d1-front", "d1-tail")
private val pcv3ArtifactStatuses = setOf("verified", "unverified", "missing")
private const val PCV3_ARTIFACT_PAGE_MAXIMUM = 128

private fun canonicalPcv3Uint(value: String): ULong? {
    if (value == "0") return 0u
    if (value.isEmpty() || value[0] !in '1'..'9' || value.any { it !in '0'..'9' }) return null
    return value.toULongOrNull()?.takeIf { it.toString() == value }
}

private fun exactPcv3CountSum(first: ULong, second: ULong, third: ULong): ULong? {
    if (first > ULong.MAX_VALUE - second) return null
    val partial = first + second
    if (partial > ULong.MAX_VALUE - third) return null
    return partial + third
}

internal fun Pcv3ArtifactMetadataData.isClosedPcv3ArtifactMetadata(): Boolean {
    if (kind !in pcv3ArtifactKinds || role !in pcv3ArtifactRoles || finalStatus !in pcv3ArtifactStatuses) {
        return false
    }
    canonicalPcv3Uint(plaintextLength) ?: return false
    val ranges = canonicalPcv3Uint(rangeCount) ?: return false
    val verified = canonicalPcv3Uint(verifiedCount) ?: return false
    val unverified = canonicalPcv3Uint(unverifiedCount) ?: return false
    val missing = canonicalPcv3Uint(missingCount) ?: return false
    return exactPcv3CountSum(verified, unverified, missing) == ranges
}

internal fun Pcv3ArtifactPageData.isClosedPcv3ArtifactPage(
    expectedOffset: String,
    limit: Int,
): Boolean {
    if (offsetDecimal != expectedOffset || canonicalPcv3Uint(offsetDecimal) == null ||
        limit !in 1..PCV3_ARTIFACT_PAGE_MAXIMUM || ranges.size !in 1..limit
    ) {
        return false
    }
    return ranges.all { range ->
        canonicalPcv3Uint(range.recordIndex) != null &&
            canonicalPcv3Uint(range.start)?.let { start ->
                canonicalPcv3Uint(range.end)?.let { end -> start <= end }
            } == true && range.status in pcv3ArtifactStatuses
    }
}

/** Validates all native fields as one closed unit before exposing immutable data. */
internal class GoPcv3ArtifactInspection(
    private val native: Pcv3ArtifactInspectionNative,
) : Pcv3ArtifactInspectionCapability {
    override fun metadata(): Pcv3ArtifactMetadataData? = try {
        val data = Pcv3ArtifactMetadataData(
            kind = native.kind(),
            role = native.role(),
            plaintextLength = native.plaintextLength(),
            finalStatus = native.finalStatus(),
            rangeCount = native.rangeCount(),
            verifiedCount = native.verifiedCount(),
            unverifiedCount = native.unverifiedCount(),
            missingCount = native.missingCount(),
        )
        data.takeIf(Pcv3ArtifactMetadataData::isClosedPcv3ArtifactMetadata)
    } catch (error: CancellationException) {
        throw error
    } catch (_: Exception) {
        null
    } catch (_: LinkageError) {
        null
    }

    override fun page(offsetDecimal: String, limit: Int): Pcv3ArtifactPageData? {
        canonicalPcv3Uint(offsetDecimal) ?: return null
        if (limit !in 1..PCV3_ARTIFACT_PAGE_MAXIMUM) return null
        return try {
            val page = native.page(offsetDecimal, limit.toLong()) ?: return null
            val count = page.count()
            if (count !in 1..limit.toLong() || count > PCV3_ARTIFACT_PAGE_MAXIMUM) return null
            val ranges = ArrayList<Pcv3ArtifactRangeData>(count.toInt())
            repeat(count.toInt()) { index ->
                val recordIndex = page.recordIndexAt(index.toLong())
                val start = page.startAt(index.toLong())
                val end = page.endAt(index.toLong())
                val status = page.statusAt(index.toLong())
                canonicalPcv3Uint(recordIndex) ?: return null
                val startValue = canonicalPcv3Uint(start) ?: return null
                val endValue = canonicalPcv3Uint(end) ?: return null
                if (startValue > endValue || status !in pcv3ArtifactStatuses) return null
                ranges += Pcv3ArtifactRangeData(recordIndex, start, end, status)
            }
            Pcv3ArtifactPageData(offsetDecimal, ranges.toList()).takeIf {
                it.isClosedPcv3ArtifactPage(offsetDecimal, limit)
            }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            null
        } catch (_: LinkageError) {
            null
        }
    }
}

internal fun ParcelFileDescriptor.closeAttachedPcv3Destination() {
    try {
        close()
    } catch (_: Exception) {
        // The bounded failure result already records that cleanup is not proven.
    } catch (_: LinkageError) {
        // A stale platform boundary is the same bounded cleanup-uncertain failure.
    }
}

/**
 * Kotlin wrapper for Go mobile bindings.
 * 
 * This bridge connects the Android app to the Go encryption backend
 * through gomobile bindings. The Go mobile package provides all
 * encryption/decryption functionality.
 */
object GoBridge {
    /** Production always uses this immutable gomobile transport. */
    private object NativePcv3Transport : Pcv3Transport {
        override fun start(requestJson: String, password: ByteArray): Pcv3StartData =
            with(GoBridge) { Mobile.startPCV3(requestJson, password).toStartData() }

        override fun restoreReceipt(receipt: String): Pcv3RestoredReceiptData =
            with(GoBridge) { Mobile.restorePCV3Receipt(receipt).toRestoredData() }
    }

    internal val pcv3Bridge = Pcv3Bridge(NativePcv3Transport)

    /** No raw error, URI, or path is returned across this startup boundary. */
    internal fun cleanupPcv3Journal(parentPath: String): Pcv3JournalCleanupState =
        cleanupPcv3Journal(parentPath, Pcv3JournalCleanupNative { Mobile.cleanupPCV3Journal(it) })

    /**
     * One immutable presentation/configuration value for the loaded AAR. Direct
     * StartPCV3 calls still perform their own fresh native admission.
     */
    val pcv3AndroidPolicyState: Pcv3AndroidPolicyState by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        readPcv3AndroidPolicyState { Mobile.pcV3AndroidPolicyState() }
    }

    /**
     * Starts a new operation and returns its ID.
     * This should be called before StartEncrypt or StartDecrypt.
     *
     * @return Result containing the operation ID, or an AppError if the Go binding
     *   fails. A failure is never masked with a fabricated ID: a fake ID would not
     *   exist in the Go operation map, so the next call would fail with a misleading
     *   "operation not found" and hide the real cause.
     */
    fun startOperation(): Result<String> {
        return try {
            Result.success(Mobile.startOperation())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }
    
    /**
     * Detects if a file should be encrypted or decrypted.
     * @param filePath Path to the file to check
     * @return Result containing true for encrypt, false for decrypt, or error if detection fails
     */
    fun detectOperation(filePath: String): Result<Boolean> {
        return try {
            val result = Mobile.detectOperation(filePath)
            Result.success(result)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val technicalMessage = e.message ?: e.toString()
            val mapped = AppError.fromGoError(
                errorString = technicalMessage,
                operationType = OperationType.DECRYPT,
                code = e.message.orEmpty(),
            )
            // Return error instead of fallback - Go binding failure is a critical error
            Result.failure(
                if (mapped is AppError.OperationError.PCVUnavailable) {
                    mapped
                } else {
                    AppError.OperationError.GenericOperation(
                        userMessage = "",
                        technicalMessage = "Go binding error: $technicalMessage",
                        messageResId = R.string.error_detect_operation_type_failed,
                    )
                }
            )
        }
    }

    /**
     * Classifies PCV3 content through the Go-owned detector. This is a route
     * signal only: it grants no operation, credential, or output authority.
     */
    fun detectPcv3Route(filePath: String): Result<Pcv3Route> {
        return try {
            Result.success(parsePcv3Route(Mobile.detectPCV3Route(filePath)))
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            Result.failure(
                AppError.OperationError.GenericOperation(
                    userMessage = "",
                    technicalMessage = "PCV3 route unavailable",
                    messageResId = R.string.error_detect_operation_type_failed,
                )
            )
        }
    }

    internal fun parsePcv3Route(route: String): Pcv3Route = when (route) {
        "legacy" -> Pcv3Route.LEGACY
        "normal" -> Pcv3Route.NORMAL
        "unsupported" -> Pcv3Route.UNSUPPORTED
        "invalid" -> Pcv3Route.INVALID
        else -> error("unknown PCV3 route")
    }
    
    /**
     * Starts an encryption operation in the background.
     * 
     * @param operationID Operation ID from startOperation()
     * @param inputFile Path to input file
     * @param outputFile Path to output file
     * @param password Password for encryption as UTF-8 bytes; zeroed before this returns
     * @param options Encryption options
     * @return Result indicating success or failure
     */
    fun startEncrypt(
        operationID: String,
        inputFile: String,
        outputFile: String,
        password: ByteArray,
        options: EncryptOptions,
        inputFiles: List<String> = emptyList(),
        onlyFolders: List<String> = emptyList(),
        onlyFiles: List<String> = emptyList()
    ): Result<Unit> {
        return try {
            // Build JSON request (password is passed separately as bytes, never in JSON)
            val requestJson = buildEncryptRequestJson(
                operationID, inputFile, outputFile, options, inputFiles, onlyFolders, onlyFiles
            )

            // Note: gomobile copies the array across JNI; that transient bridge copy is not reachable for zeroing (intrinsic to the binding).
            val errorMsg = Mobile.startEncrypt(requestJson, password)

            if (errorMsg.isNotEmpty()) {
                // Convert Go error to AppError (operation type unknown here, use generic)
                val appError = AppError.fromGoError(errorMsg, OperationType.ENCRYPT)
                Result.failure(appError)
            } else {
                Result.success(Unit)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        } finally {
            password.fill(0)
        }
    }
    
    /**
     * Starts a decryption operation in the background.
     * 
     * @param operationID Operation ID from startOperation()
     * @param inputFile Path to input file
     * @param outputFile Path to output file
     * @param password Password for decryption as UTF-8 bytes; zeroed before this returns
     * @param options Decryption options
     * @return Result indicating success or failure
     */
    fun startDecrypt(
        operationID: String,
        inputFile: String,
        outputFile: String,
        password: ByteArray,
        options: DecryptOptions
    ): Result<Unit> {
        return try {
            // Build JSON request (password is passed separately as bytes, never in JSON)
            val requestJson = buildDecryptRequestJson(operationID, inputFile, outputFile, options)

            // Note: gomobile copies the array across JNI; that transient bridge copy is not reachable for zeroing (intrinsic to the binding).
            val errorMsg = Mobile.startDecrypt(requestJson, password)

            if (errorMsg.isNotEmpty()) {
                // Convert Go error to AppError
                val appError = AppError.fromGoError(errorMsg, OperationType.DECRYPT, code = errorMsg)
                Result.failure(appError)
            } else {
                Result.success(Unit)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        } finally {
            password.fill(0)
        }
    }

    /**
     * Gets the current progress state for an operation.
     * 
     * @param operationID Operation ID to get progress for
     * @return Result containing ProgressState or error
     */
    fun getProgress(operationID: String): Result<ProgressState> {
        return try {
            val result: GoProgressResult = Mobile.getProgress(operationID)

            Result.success(result.toProgressState())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }
    
    /**
     * Cancels a running operation.
     * 
     * @param operationID Operation ID to cancel
     * @return Result containing the canonical terminal state, or an error
     */
    fun cancelOperation(operationID: String): Result<ProgressState> {
        return try {
            val result: GoProgressResult = Mobile.cancelOperation(operationID)
            Result.success(result.toProgressState())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }

    internal fun GoProgressResult.toProgressState(): ProgressState = ProgressState(
        status = OperationStatusData(
            code = getStatusCode() ?: "",
            speedMiBPerSecond = getStatusSpeedMiBPerSecond(),
            eta = getStatusETA() ?: "",
        ),
        detail = OperationProgressDetail(
            code = getInfoCode() ?: "",
            current = getInfoCurrent(),
            total = getInfoTotal(),
        ),
        progress = getProgress(),
        done = getDone(),
        technicalError = getError() ?: "",
        errorCode = getCode() ?: "",
    )
    
    /**
     * Gets decryption metadata from an encrypted file without decrypting it.
     * This allows the app to determine what credentials and settings were used
     * during encryption.
     * 
     * @param filePath Path to the encrypted file
     * @return Result containing DecryptionInfo or error
     */
    fun getDecryptionInfo(filePath: String): Result<DecryptionInfo> {
        return try {
            val jsonString = Mobile.getDecryptionInfo(filePath)
            Result.success(parseDecryptionInfo(jsonString))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }

    /**
     * Builds the encryption request JSON sent to Mobile.startEncrypt. The password is
     * intentionally NEVER included here -- it is passed to Mobile as raw bytes and zeroed.
     * Extracted so unit tests verify the REAL serialization instead of re-deriving it.
     */
    internal fun buildEncryptRequestJson(
        operationID: String,
        inputFile: String,
        outputFile: String,
        options: EncryptOptions,
        inputFiles: List<String> = emptyList(),
        onlyFolders: List<String> = emptyList(),
        onlyFiles: List<String> = emptyList()
    ): String = JSONObject().apply {
        put("operationID", operationID)
        put("inputFile", inputFile)
        // Folder/multi-file selection arrays forwarded to the Go core (it zips them).
        // Always present (empty for the single-file path) so the Go side reads a stable shape.
        put("inputFiles", JSONArray().apply { inputFiles.forEach { put(it) } })
        put("onlyFolders", JSONArray().apply { onlyFolders.forEach { put(it) } })
        put("onlyFiles", JSONArray().apply { onlyFiles.forEach { put(it) } })
        put("outputFile", outputFile)
        put("comments", options.comments)
        put("keyfiles", JSONArray().apply { options.keyfiles.forEach { put(it) } })
        put("paranoid", options.paranoid)
        put("reedSolomon", options.reedSolomon)
        put("deniability", options.deniability)
        put("compress", options.compress)
        put("keyfileOrdered", options.keyfileOrdered)
    }.toString()

    /**
     * Builds the decryption request JSON sent to Mobile.startDecrypt. As with encryption,
     * the password is never serialized. Extracted for the same testability reason.
     */
    internal fun buildDecryptRequestJson(
        operationID: String,
        inputFile: String,
        outputFile: String,
        options: DecryptOptions
    ): String = JSONObject().apply {
        put("operationID", operationID)
        put("inputFile", inputFile)
        put("outputFile", outputFile)
        put("keyfiles", JSONArray().apply { options.keyfiles.forEach { put(it) } })
        put("forceDecrypt", options.forceDecrypt)
        put("verifyFirst", options.verifyFirst)
        put("autoUnzip", options.autoUnzip)
        put("sameLevel", options.sameLevel)
        put("recombine", options.recombine)
        put("deniability", options.deniability)
    }.toString()

    /** Builds the exact Go-owned PCV3 envelope; credential bytes never enter JSON. */
    internal fun buildPcv3RequestJson(request: Pcv3Request): String = JSONObject().apply {
        put("version", 1)
        put("mode", request.mode)
        put("factorPolicy", request.factorPolicy)
        put("keyfileOrder", request.keyfileOrder)
        put("source", request.source)
        put("target", request.target)
        put("keyfiles", JSONArray().apply { request.keyfiles.forEach { put(it) } })
    }.toString()

    private fun PCV3StartResult.toStartData(): Pcv3StartData = Pcv3StartData(code(), operation()?.let(::GoPcv3Operation))
    private fun PCV3RestoredReceipt.toRestoredData(): Pcv3RestoredReceiptData = Pcv3RestoredReceiptData(
        code = code(),
        receiptId = receiptID(),
        operationId = operationID(),
        snapshot = snapshot()?.toData(),
    )
    private fun PCV3Snapshot.toData(): Pcv3SnapshotData = Pcv3SnapshotData(
        statusCode = statusCode(),
        statusArgs = bounded(statusArgCount()) { statusArgAt(it) },
        outcome = outcome(),
        stage = stage(),
        code = code(),
        forceProvenance = forceProvenance(),
        d1BootstrapProvenance = d1BootstrapProvenance(),
        detailStage = detailStage(),
        publicationAttempted = publicationAttempted(),
        publicationState = publicationState(),
        publicationStage = publicationStage(),
        publicationCode = publicationCode(),
        diagnostic = diagnostic(),
        completionClass = completionClass(),
        args = bounded(argCount()) { argAt(it) },
        warnings = bounded(warningCount()) { warningAt(it) },
        archivePending = archivePending(),
        restoredReceipt = restoredReceipt(),
    )
    private fun bounded(count: Long, at: (Long) -> String): List<String> = (0 until count.coerceIn(0, 8)).map(at)
    private class GoPcv3Operation(private val native: PCV3Operation) : Pcv3OperationCapability {
        override val id get() = native.id()
        override fun snapshot() = native.snapshot().toData()
        override fun consent() = native.consent()?.let(::GoPcv3Consent)
        override fun archive() = native.archive()?.let {
            GoPcv3Archive(GoMobilePcv3Archive(it))
        }
        override fun output() = native.output()?.let { GoPcv3Output(GoMobilePcv3Output(it)) }
        override fun artifactInspection() = native.artifactInspection()?.let {
            GoPcv3ArtifactInspection(GoMobilePcv3ArtifactInspection(it))
        }
        override fun resourceChallenge() = native.resourceChallenge()?.let {
            GoPcv3ResourceChallenge(GoMobilePcv3ResourceChallenge(it))
        }
        override fun cancel() = native.cancel().toData()
        override fun release() = native.release()
    }
    private class GoPcv3Consent(private val native: mobile.PCV3Consent) : Pcv3ConsentCapability {
        override fun mode() = native.mode(); override fun roles() = bounded(native.roleCount()) { native.roleAt(it) }
        override fun choose(role: String) = native.choose(role); override fun refuse() = native.refuse()
    }
    private class GoMobilePcv3Archive(
        private val native: PCV3Archive,
    ) : Pcv3ArchiveNative {
        override fun close(): Pcv3SnapshotData = native.close().toData()

        override fun beginSaf(): Pcv3ArchiveBeginData {
            val begin = native.beginSAF()
            val session = begin.session()?.let(::GoMobilePcv3ArchiveSession)
            return projectPcv3ArchiveBegin(
                capturedSession = session,
                kind = begin::kind,
                code = begin::code,
                snapshot = { begin.snapshot()?.toData() },
            )
        }
    }

    private class GoMobilePcv3ArchiveSession(
        private val native: PCV3ArchiveSession,
    ) : Pcv3ArchiveSessionCapability {
        override fun entryCount(): Long = native.entryCount()

        override fun entry(index: Long): Pcv3ArchiveEntryData? = native.entry(index)?.let {
            Pcv3ArchiveEntryData(
                name = it.name(),
                parentIndex = it.parentIndex(),
                isDirectory = it.isDirectory(),
                size = it.size(),
            )
        }

        override fun confirmCrashReceiptPersisted(receipt: String): Pcv3ArchiveStepData =
            native.confirmCrashReceiptPersisted(receipt).toData()

        override fun attempt(index: Long): Pcv3ArchiveStepData = native.attempt(index).toData()

        override fun ackDirectory(index: Long): Pcv3ArchiveStepData =
            native.ackDirectory(index).toData()

        override fun writeFd(index: Long, descriptor: Long): Pcv3ArchiveStepData =
            native.writeFD(index, descriptor).toData()

        override fun cancel(): Pcv3ArchiveStepData = native.cancel().toData()

        override fun finish(): Pcv3SnapshotData = native.finish().toData()

        override fun abort(): Pcv3SnapshotData = native.abort().toData()
    }

    private fun PCV3ArchiveStep?.toData(): Pcv3ArchiveStepData = if (this == null) {
        Pcv3ArchiveStepData("rejected", -1)
    } else {
        Pcv3ArchiveStepData(kind(), nextIndex())
    }

    /**
     * Parses the decryption-metadata JSON returned by Mobile.getDecryptionInfo. Uses
     * getBoolean/getString, which THROW on a missing field rather than silently
     * defaulting (a missing keyfilesRequired must never be read as false). Extracted so
     * the parser is unit-tested directly.
     */
    internal fun parseDecryptionInfo(jsonString: String): DecryptionInfo {
        val json = JSONObject(jsonString)
        if (json.has("errorCode")) {
            val errorCode = json.getString("errorCode")
            throw AppError.fromGoError(errorCode, OperationType.DECRYPT, code = errorCode)
        }
        return DecryptionInfo(
            keyfilesRequired = json.getBoolean("keyfilesRequired"),
            keyfileOrdered = json.getBoolean("keyfileOrdered"),
            reedSolomon = json.getBoolean("reedSolomon"),
            deniability = json.getBoolean("deniability"),
            paranoid = json.getBoolean("paranoid"),
            comments = json.getString("comments"),
            readable = json.getBoolean("readable")
        )
    }
}
