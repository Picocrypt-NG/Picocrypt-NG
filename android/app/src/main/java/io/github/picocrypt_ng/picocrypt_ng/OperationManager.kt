package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import io.github.picocrypt_ng.picocrypt_ng.FileCopyService
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.cancellation.CancellationException

/** Narrow persistence seam; production always delegates to the exact AtomicFile store. */
internal interface Pcv3ReceiptPersistence {
    fun save(file: File, receipt: String): Boolean
    fun clear(file: File): Boolean
}

private object AtomicPcv3ReceiptPersistence : Pcv3ReceiptPersistence {
    override fun save(file: File, receipt: String): Boolean = Pcv3ReceiptStore.save(file, receipt)
    override fun clear(file: File): Boolean = Pcv3ReceiptStore.clear(file)
}

/** Exact monotonic receipt custody used by the SAF archive protocol. */
internal interface Pcv3ReceiptCustodyCapability {
    val custody: ReceiptCustody
    fun transition(desiredReceipt: String?): ReceiptCustody
}

internal fun interface Pcv3ReceiptCustodyFactory {
    fun create(file: File, initial: ReceiptCustody): Pcv3ReceiptCustodyCapability
}

private class ExactPcv3ReceiptCustody(
    file: File,
    initial: ReceiptCustody,
) : Pcv3ReceiptCustodyCapability {
    private val custodian = Pcv3ReceiptCustodian(file, initial)

    override val custody: ReceiptCustody
        get() = custodian.custody

    override fun transition(desiredReceipt: String?): ReceiptCustody =
        custodian.transition(desiredReceipt)
}

private val ExactPcv3ReceiptCustodyFactory = Pcv3ReceiptCustodyFactory { file, initial ->
    ExactPcv3ReceiptCustody(file, initial)
}

/**
 * Serializes the one live PCV3 handle. Every operation-visible scalar state is
 * accepted only under its generation/action ticket and reconciled through this owner.
 */
internal class Pcv3Lifecycle(
    private val bridge: Pcv3Bridge,
    private val receiptPersistence: Pcv3ReceiptPersistence = AtomicPcv3ReceiptPersistence,
    private val receiptCustodyFactory: Pcv3ReceiptCustodyFactory = ExactPcv3ReceiptCustodyFactory,
) {
    private val mutex = Mutex()
    private val _presentation = MutableStateFlow<Pcv3Presentation?>(null)
    val presentation: StateFlow<Pcv3Presentation?> = _presentation.asStateFlow()
    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()
    private val _artifactDetails = MutableStateFlow<Pcv3ArtifactDetailsUiState>(Pcv3ArtifactDetailsUiState.Closed)
    val artifactDetails: StateFlow<Pcv3ArtifactDetailsUiState> = _artifactDetails.asStateFlow()

    private var nextGeneration = 0L
    private var nextActionToken = 0L
    private var nextArtifactPageToken = 0L
    private var artifactPageToken: Long? = null
    private var state: State = State.Idle
        set(value) {
            field = value
            _busy.value = value is State.Starting || value is State.Active || value is State.Draining
        }

    private sealed interface State {
        data object Idle : State
        data class Starting(val generation: Long, val receiptFile: File, val creation: Boolean = false) : State
        data class Active(
            val generation: Long,
            val operation: Pcv3OperationCapability,
            val receiptFile: File,
            val creation: Boolean = false,
            val receiptPersisted: Boolean = false,
            val snapshot: Pcv3SnapshotData? = null,
            val consentHandle: Pcv3ConsentCapability? = null,
            val archiveHandle: Pcv3ArchiveCapability? = null,
            val archiveSafAction: SafArchiveAction? = null,
            val outputHandle: Pcv3OutputCapability? = null,
            val consent: Pcv3ConsentView? = null,
            val invalidConsentRefused: Boolean = false,
            val actionToken: Long? = null,
            val outputActionInFlight: Boolean = false,
            val outputActionResult: Pcv3OutputResultView? = null,
            val artifactInspection: Pcv3ArtifactInspectionCapability? = null,
            val artifactMetadata: Pcv3ArtifactMetadataData? = null,
            val artifactInspectionRejected: Boolean = false,
            val resourceObservationReader: Pcv3ResourceObservationReader? = null,
            val resourceReaderInstalled: Boolean = false,
            val resourcePumpEnabled: Boolean = false,
            val receiptCustodian: Pcv3ReceiptCustodyCapability? = null,
        ) : State
        data class Draining(
            val generation: Long,
            val operation: Pcv3OperationCapability,
            val receiptFile: File,
            val creation: Boolean = false,
            val receiptPersisted: Boolean = false,
            val snapshot: Pcv3SnapshotData? = null,
            val cancelRequested: Boolean = false,
            val outputActionResult: Pcv3OutputResultView? = null,
            val artifactInspection: Pcv3ArtifactInspectionCapability? = null,
            val artifactMetadata: Pcv3ArtifactMetadataData? = null,
            val artifactInspectionRejected: Boolean = false,
            val receiptCustodian: Pcv3ReceiptCustodyCapability? = null,
        ) : State
        data class Final(
            val generation: Long,
            val receiptFile: File,
            val receiptPersisted: Boolean,
            val creation: Boolean = false,
            val artifactInspection: Pcv3ArtifactInspectionCapability? = null,
            val artifactMetadata: Pcv3ArtifactMetadataData? = null,
            val receiptCustodian: Pcv3ReceiptCustodyCapability? = null,
            val dismissInFlight: Boolean = false,
        ) : State
    }

    private data class ActionTicket(
        val token: Long,
        val generation: Long,
        val operation: Pcv3OperationCapability,
    )

    private data class ConsentAction(
        val ticket: ActionTicket,
        val handle: Pcv3ConsentCapability,
        val role: String,
    )

    private data class ArchiveAction(
        val ticket: ActionTicket,
        val handle: Pcv3ArchiveCapability,
    )

    private enum class SafTerminalOwner {
        NONE,
        FINISH,
        ABORT,
    }

    /**
     * Race-safe authority for one claimed SAF action. It deliberately carries no URI.
     * Session JNI calls are claimed under [lock] and always executed after releasing it.
     */
    private class SafArchiveAction(
        val ticket: ActionTicket,
        val handle: Pcv3ArchiveCapability,
        val custodian: Pcv3ReceiptCustodyCapability,
        val cancellation: Pcv3SafCancellation,
        val resourceObservationReader: Pcv3ResourceObservationReader?,
    ) {
        val settled = CompletableDeferred<Unit>()
        private val lock = Any()
        private var session: Pcv3ArchiveSessionCapability? = null
        private var cancelRequested = false
        private var cancelDispatched = false
        private var terminalOwner = SafTerminalOwner.NONE

        fun bindSession(value: Pcv3ArchiveSessionCapability): Pcv3ArchiveSessionCapability? = synchronized(lock) {
            if (session == null) session = value
            claimCancellationLocked()
        }

        fun requestCancellation(): Pcv3ArchiveSessionCapability? {
            val claimed = synchronized(lock) {
                cancelRequested = true
                claimCancellationLocked()
            }
            try {
                handle.cancelPreparation()
            } catch (_: Exception) {
                // The session, if already handed off, still has cancellation custody.
            } catch (_: LinkageError) {
                // An incompatible bridge never grants provider effects below.
            }
            try {
                cancellation.cancel()
            } catch (_: Exception) {
                // Native cancellation below remains authoritative.
            } catch (_: LinkageError) {
                // Native cancellation below remains authoritative.
            }
            return claimed
        }

        fun cancellationRequested(): Boolean = synchronized(lock) { cancelRequested }

        fun claimFinish(): Boolean = synchronized(lock) {
            if (cancelRequested || terminalOwner != SafTerminalOwner.NONE) {
                false
            } else {
                terminalOwner = SafTerminalOwner.FINISH
                true
            }
        }

        fun claimAbort(): Boolean = synchronized(lock) {
            if (terminalOwner != SafTerminalOwner.NONE) {
                false
            } else {
                terminalOwner = SafTerminalOwner.ABORT
                true
            }
        }

        private fun claimCancellationLocked(): Pcv3ArchiveSessionCapability? {
            val current = session
            return if (cancelRequested && !cancelDispatched && current != null &&
                terminalOwner == SafTerminalOwner.NONE
            ) {
                cancelDispatched = true
                current
            } else {
                null
            }
        }
    }

    private data class SafArchiveCompletion(
        val snapshot: Pcv3SnapshotData?,
        val receiptSettled: Boolean,
        val failureCode: String?,
        val cancellation: CancellationException? = null,
    )

    private class SafEntrySession(
        private val session: Pcv3ArchiveSessionCapability,
    ) : Pcv3SafEntrySession {
        override fun attempt(index: Long): Pcv3ArchiveStepData = session.attempt(index)
        override fun ackDirectory(index: Long): Pcv3ArchiveStepData = session.ackDirectory(index)
        override fun writeFd(index: Long, descriptor: Long): Pcv3ArchiveStepData =
            session.writeFd(index, descriptor)
    }

    private data class OutputAction(
        val ticket: ActionTicket,
        val handle: Pcv3OutputCapability,
    )

    private data class ArtifactPageTicket(
        val token: Long,
        val generation: Long,
        val operationId: String,
        val inspection: Pcv3ArtifactInspectionCapability,
        val metadata: Pcv3ArtifactMetadataData,
    )

    private sealed interface ArtifactCapture {
        data class Accepted(
            val inspection: Pcv3ArtifactInspectionCapability?,
            val metadata: Pcv3ArtifactMetadataData?,
        ) : ArtifactCapture
        data class Rejected(val cancellation: CancellationException? = null) : ArtifactCapture
    }

    suspend fun start(
        request: Pcv3StartRequest,
        password: CharArray,
        receiptFile: File,
    ): Result<Pcv3Presentation> = try {
        startOwned(request, password, receiptFile)
    } finally {
        password.fill('\u0000')
    }

    private suspend fun startOwned(
        request: Pcv3StartRequest,
        password: CharArray,
        receiptFile: File,
    ): Result<Pcv3Presentation> {
        val creation = request is Pcv3WriteRequest
        val generation = mutex.withLock {
            when (state) {
                State.Idle -> {
                    val next = ++nextGeneration
                    state = State.Starting(next, receiptFile, creation)
                    _presentation.value = null
                    artifactPageToken = null
                    _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
                    next
                }
                is State.Starting, is State.Active, is State.Draining, is State.Final -> null
            }
        }
        if (generation == null) {
            return Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
        }

        val callerContext = currentCoroutineContext()
        val started = try {
            callerContext.ensureActive()
            bridge.start(request, password)
        } catch (error: CancellationException) {
            finishStarting(generation)
            throw error
        }
        try {
            callerContext.ensureActive()
        } catch (error: CancellationException) {
            drainCancelledStart(generation, started, error)
            throw error
        }
        val startData = started.getOrNull()
        if (startData == null) {
            finishStarting(generation)
            return Result.failure(started.exceptionOrNull() ?: Pcv3BridgeFailure("PCV3_BRIDGE_FAILURE"))
        }

        val active = withContext(NonCancellable) {
            mutex.withLock {
                if (state !is State.Starting || (state as State.Starting).generation != generation) {
                    null
                } else if (startData.operation == null) {
                    state = State.Idle
                    _presentation.value = null
                    null
                } else {
                    State.Active(
                        generation = generation,
                        operation = startData.operation,
                        receiptFile = receiptFile,
                        creation = creation,
                    ).also { state = it }
                }
            }
        }
        if (active == null) {
            return Result.failure(Pcv3BridgeFailure(pcv3BridgeCode(startData.code)))
        }

        if (startData.code.isNotEmpty()) {
            withContext(NonCancellable) {
                mutex.withLock {
                    val current = state as? State.Active
                    if (current != null && current.generation == active.generation && current.operation === active.operation) {
                        beginDrainLocked(current, failureCode = pcv3BridgeCode(startData.code))
                    }
                }
            }
            return Result.failure(Pcv3BridgeFailure(pcv3BridgeCode(startData.code)))
        }

        val reconciled = withContext(NonCancellable) { refreshPcv3() }
        return reconciled
    }

    private suspend fun finishStarting(generation: Long) = withContext(NonCancellable) {
        mutex.withLock {
            if (state is State.Starting && (state as State.Starting).generation == generation) {
                state = State.Idle
                _presentation.value = null
                artifactPageToken = null
                _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
            }
        }
    }

    private suspend fun drainCancelledStart(
        generation: Long,
        started: Result<Pcv3StartData>,
        cancellation: CancellationException,
    ) = withContext(NonCancellable) {
        mutex.withLock {
            val starting = state as? State.Starting
            if (starting == null || starting.generation != generation) return@withLock
            val operation = started.getOrNull()?.operation
            if (operation == null) {
                state = State.Idle
                _presentation.value = null
                artifactPageToken = null
                _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
                return@withLock
            }
            val active = State.Active(
                generation = generation,
                operation = operation,
                receiptFile = starting.receiptFile,
                creation = starting.creation,
            )
            state = active
            try {
                beginDrainLocked(active, failureCode = "PCV3_OPERATION_CANCELLED", cancellation = cancellation)
            } catch (drained: CancellationException) {
                if (drained !== cancellation) throw drained
            }
        }
    }

    suspend fun restorePcv3Receipt(
        receipt: String,
        receiptFile: File,
    ): Result<Pcv3Presentation> {
        val generation = mutex.withLock {
            when (state) {
                State.Idle -> {
                    val next = ++nextGeneration
                    state = State.Starting(next, receiptFile)
                    _presentation.value = null
                    artifactPageToken = null
                    _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
                    next
                }
                is State.Starting, is State.Active, is State.Draining, is State.Final -> null
            }
        } ?: return Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))

        val restoredResult = try {
            bridge.restoreReceipt(receipt)
        } catch (error: CancellationException) {
            finishStarting(generation)
            throw error
        }
        return withContext(NonCancellable) {
            mutex.withLock {
                if (state !is State.Starting || (state as State.Starting).generation != generation) {
                    return@withLock Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
                }
                val restored = restoredResult.getOrNull()
                if (restored == null || restored.code.isNotEmpty() || restored.snapshot == null) {
                    state = State.Idle
                    _presentation.value = null
                    artifactPageToken = null
                    _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
                    return@withLock Result.failure(
                        restoredResult.exceptionOrNull() ?: Pcv3BridgeFailure("PCV3_RECEIPT_INVALID"),
                    )
                }
                val snapshot = projectPcv3Snapshot(restored.snapshot)
                if (snapshot.restoredReceipt != receipt || !restored.snapshot.requiresReceipt()) {
                    state = State.Idle
                    _presentation.value = null
                    artifactPageToken = null
                    _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
                    return@withLock Result.failure(Pcv3BridgeFailure("PCV3_RECEIPT_INVALID"))
                }
                val presentation = Pcv3Presentation.Restored(
                    snapshot = snapshot,
                    operationId = restored.operationId,
                    generation = generation,
                    receiptId = restored.receiptId,
                )
                state = State.Final(
                    generation = generation,
                    receiptFile = receiptFile,
                    receiptPersisted = true,
                    artifactInspection = null,
                    artifactMetadata = null,
                )
                _presentation.value = presentation
                artifactPageToken = null
                _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
                Result.success(presentation)
            }
        }
    }

    /** The sole PCV3 state reconciliation path. */
    suspend fun refreshPcv3(): Result<Pcv3Presentation> = mutex.withLock {
        when (val current = state) {
            is State.Active -> {
                if (current.actionToken != null) {
                    Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
                } else {
                    reconcileActiveLocked(pumpResourceChallengeLocked(current))
                }
            }
            is State.Draining -> attemptDrainLocked(current)
            is State.Final -> _presentation.value?.let { Result.success(it) }
                ?: Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
            State.Idle, is State.Starting -> Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
        }
    }

    /** Attaches observations only to the currently active generation. */
    suspend fun installResourceObservationReader(reader: Pcv3ResourceObservationReader): Boolean = mutex.withLock {
        val current = state as? State.Active ?: return@withLock false
        if (current.resourceReaderInstalled) return@withLock false
        state = current.copy(
            resourceObservationReader = reader,
            resourceReaderInstalled = true,
            resourcePumpEnabled = true,
        )
        true
    }

    /**
     * One bounded transport step at the start of refresh. A missing challenge is
     * ordinary and leaves the pump armed for a later KDF. Every other boundary
     * refusal disables only this generation and never invents operation meaning.
     */
    private fun pumpResourceChallengeLocked(initial: State.Active): State.Active {
        val reader = initial.resourceObservationReader
        if (!initial.resourcePumpEnabled || reader == null) return initial

        fun stop(): State.Active = initial.copy(
            resourceObservationReader = null,
            resourcePumpEnabled = false,
        ).also { state = it }

        val challenge = try {
            initial.operation.resourceChallenge()
        } catch (error: CancellationException) {
            stop()
            throw error
        } catch (_: Exception) {
            return stop()
        } catch (_: LinkageError) {
            return stop()
        } ?: return initial

        val observation = try {
            reader.read()
        } catch (error: CancellationException) {
            stop()
            throw error
        } catch (_: Exception) {
            return stop()
        } catch (_: LinkageError) {
            return stop()
        } ?: return stop()

        val consumed = try {
            challenge.submit(observation)
        } catch (error: CancellationException) {
            stop()
            throw error
        } catch (_: Exception) {
            false
        } catch (_: LinkageError) {
            false
        }
        return if (consumed) initial else stop()
    }

    /** Clears only the exact released terminal presentation named by the UI ticket. */
    suspend fun dismissPcv3(expectedOperationId: String, expectedGeneration: Long): Boolean {
        val custody = mutex.withLock {
            val terminal = exactDismissTerminalLocked(expectedOperationId, expectedGeneration)
                ?: return@withLock null
            terminal.receiptCustodian
        }
        if (custody == null) {
            val restored = mutex.withLock {
                val terminal = exactDismissTerminalLocked(expectedOperationId, expectedGeneration)
                    ?: return false
                if (terminal.receiptPersisted && !receiptPersistence.clear(terminal.receiptFile)) {
                    return false
                }
                val presentation = _presentation.value as? Pcv3Presentation.Restored
                if (presentation == null) {
                    clearPcv3PresentationLocked()
                    return true
                }
                // Cleanup may fail or be cancelled after receipt clearing. Keep this
                // exact UI ticket retryable without clearing any later receipt.
                state = terminal.copy(receiptPersisted = false, dismissInFlight = true)
                presentation
            }
            val cleaned = try {
                StartupCleanup.completeRestoredDismissal(restored)
            } catch (error: CancellationException) {
                withContext(NonCancellable) { finishFailedPcv3Dismiss(null, expectedGeneration) }
                throw error
            } catch (_: Exception) {
                false
            } catch (_: LinkageError) {
                false
            }
            return withContext(NonCancellable) {
                mutex.withLock {
                    val terminal = state as? State.Final ?: return@withLock false
                    if (terminal.generation != expectedGeneration || !terminal.dismissInFlight ||
                        _presentation.value !== restored
                    ) {
                        return@withLock false
                    }
                    if (!cleaned) {
                        state = terminal.copy(dismissInFlight = false)
                        return@withLock false
                    }
                    clearPcv3PresentationLocked()
                    true
                }
            }
        }

        val claimed = mutex.withLock {
            val terminal = exactDismissTerminalLocked(expectedOperationId, expectedGeneration)
                ?: return@withLock false
            if (terminal.receiptCustodian !== custody || terminal.dismissInFlight) return@withLock false
            state = terminal.copy(dismissInFlight = true)
            true
        }
        if (!claimed) return false

        val transitioned = try {
            custody.transition(null)
        } catch (error: CancellationException) {
            withContext(NonCancellable) { finishFailedPcv3Dismiss(custody, expectedGeneration) }
            throw error
        } catch (_: Exception) {
            ReceiptCustody.Unknown
        } catch (_: LinkageError) {
            ReceiptCustody.Unknown
        }
        return mutex.withLock {
            val terminal = state as? State.Final ?: return@withLock false
            if (terminal.generation != expectedGeneration || terminal.receiptCustodian !== custody ||
                !terminal.dismissInFlight
            ) {
                return@withLock false
            }
            if (transitioned !== ReceiptCustody.None) {
                state = terminal.copy(dismissInFlight = false)
                return@withLock false
            }
            clearPcv3PresentationLocked()
            true
        }
    }

    private fun exactDismissTerminalLocked(
        expectedOperationId: String,
        expectedGeneration: Long,
    ): State.Final? {
        val terminal = state as? State.Final ?: return null
        val presentation = _presentation.value ?: return null
        if (terminal.generation != expectedGeneration || terminal.dismissInFlight ||
            presentation.generation != expectedGeneration ||
            presentation.operationId != expectedOperationId ||
            (presentation !is Pcv3Presentation.Final && presentation !is Pcv3Presentation.Restored)
        ) {
            return null
        }
        return terminal
    }

    private suspend fun finishFailedPcv3Dismiss(
        custody: Pcv3ReceiptCustodyCapability?,
        expectedGeneration: Long,
    ) = mutex.withLock {
        val terminal = state as? State.Final ?: return@withLock
        if (terminal.generation == expectedGeneration && terminal.receiptCustodian === custody &&
            terminal.dismissInFlight
        ) {
            state = terminal.copy(dismissInFlight = false)
        }
    }

    private fun clearPcv3PresentationLocked() {
        state = State.Idle
        _presentation.value = null
        artifactPageToken = null
        _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
    }

    suspend fun cancelPcv3(): Result<Unit> {
        val safAction = mutex.withLock {
            (state as? State.Active)?.archiveSafAction
        }
        if (safAction != null) {
            cancelSafSession(safAction.requestCancellation())
            withContext(NonCancellable) { safAction.settled.await() }
            return Result.success(Unit)
        }

        val action = mutex.withLock {
            val current = state as? State.Active
                ?: return@withLock null
            if (current.actionToken != null || current.archiveSafAction != null ||
                current.outputHandle != null || current.outputActionInFlight
            ) {
                return@withLock null
            }
            val ticket = ActionTicket(++nextActionToken, current.generation, current.operation)
            val pending = current.copy(
                consentHandle = null,
                archiveHandle = null,
                consent = null,
                actionToken = ticket.token,
            )
            state = pending
            publishActiveLocked(pending)
            ticket
        } ?: return Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))

        var returnedSnapshot: Pcv3SnapshotData? = null
        var actionFailure: String? = null
        var cancellation: CancellationException? = null
        val callerContext = currentCoroutineContext()
        try {
            callerContext.ensureActive()
            returnedSnapshot = action.operation.cancel()
            callerContext.ensureActive()
        } catch (error: CancellationException) {
            cancellation = error
        } catch (_: Exception) {
            actionFailure = "PCV3_OPERATION_FAILURE"
        }
        val reconciled = finishPcv3Action(action, returnedSnapshot, actionFailure, cancellation)
        return actionResult(reconciled, actionFailure)
    }

    suspend fun closePcv3Archive(): Result<Unit> = archiveAction { it.close() }

    /**
     * Claims the exact archive generation before BeginSAF. The selected URI stays
     * on this stack and is never copied into lifecycle state or an error value.
     */
    suspend fun exportPcv3Archive(
        expectedOperationId: String,
        expectedGeneration: Long,
        root: Uri,
        publisher: Pcv3SafPublisher,
    ): Result<Unit> {
        val cancellation = try {
            publisher.newCancellation()
        } catch (_: Exception) {
            return Result.failure(Pcv3BridgeFailure("PCV3_ARCHIVE_UNAVAILABLE"))
        } catch (_: LinkageError) {
            return Result.failure(Pcv3BridgeFailure("PCV3_ARCHIVE_UNAVAILABLE"))
        }
        val action = mutex.withLock {
            val current = state as? State.Active ?: return@withLock null
            val live = _presentation.value as? Pcv3Presentation.Live ?: return@withLock null
            val handle = current.archiveHandle ?: return@withLock null
            if (current.generation != expectedGeneration || live.generation != expectedGeneration ||
                current.operation.id != expectedOperationId || live.operationId != expectedOperationId ||
                current.actionToken != null || current.archiveSafAction != null ||
                current.outputHandle != null || current.outputActionInFlight ||
                current.receiptCustodian != null
            ) {
                return@withLock null
            }
            val ticket = ActionTicket(++nextActionToken, current.generation, current.operation)
            val custodian = receiptCustodyFactory.create(current.receiptFile, ReceiptCustody.None)
            val claimed = SafArchiveAction(
                ticket, handle, custodian, cancellation,
                current.resourceObservationReader?.takeIf { current.resourcePumpEnabled },
            )
            val pending = current.copy(
                archiveHandle = null,
                archiveSafAction = claimed,
                actionToken = ticket.token,
                receiptCustodian = custodian,
            )
            state = pending
            publishActiveLocked(pending)
            claimed
        } ?: return Result.failure(Pcv3BridgeFailure("PCV3_ARCHIVE_UNAVAILABLE"))

        val completion = performSafArchiveAction(action, root, publisher)
        val releaseCode = if (completion.snapshot != null && completion.receiptSettled &&
            completion.cancellation == null
        ) {
            try {
                action.ticket.operation.release()
            } catch (_: Exception) {
                "PCV3_OPERATION_RELEASE_DENIED"
            } catch (_: LinkageError) {
                "PCV3_OPERATION_RELEASE_DENIED"
            }
        } else {
            "PCV3_OPERATION_RELEASE_DENIED"
        }

        val finalized = try {
            withContext(NonCancellable) {
                finishSafArchiveAction(action, completion, releaseCode)
            }
        } finally {
            action.settled.complete(Unit)
        }
        completion.cancellation?.let { throw it }
        return finalized
    }

    /** The claimed follow-up owns its pump because normal refresh excludes actionToken. */
    private suspend fun beginSafWithResourcePump(action: SafArchiveAction): Pcv3ArchiveBeginData {
        val reader = action.resourceObservationReader ?: return action.handle.beginSaf()
        val pump = CoroutineScope(currentCoroutineContext()).launch(Dispatchers.IO) {
            try {
                while (isActive && !action.cancellationRequested()) {
                    val challenge = action.ticket.operation.resourceChallenge()
                    if (challenge != null) {
                        val observation = reader.read() ?: return@launch
                        if (!challenge.submit(observation)) return@launch
                    }
                    delay(25)
                }
            } catch (_: Exception) {
                // The Go-owned challenge expires or cancels; never fabricate facts.
            } catch (_: LinkageError) {
                // An incompatible observation boundary cannot grant admission.
            }
        }
        return try {
            action.handle.beginSaf()
        } finally {
            withContext(NonCancellable) { pump.cancelAndJoin() }
        }
    }

    private suspend fun performSafArchiveAction(
        action: SafArchiveAction,
        root: Uri,
        publisher: Pcv3SafPublisher,
    ): SafArchiveCompletion {
        val callerContext = currentCoroutineContext()
        val callerCancellationArmed = AtomicBoolean(true)
        val callerCancellationWatcher = CoroutineScope(callerContext).launch(
            start = CoroutineStart.UNDISPATCHED,
        ) {
            try {
                awaitCancellation()
            } finally {
                if (callerCancellationArmed.compareAndSet(true, false)) {
                    cancelSafSession(action.requestCancellation())
                }
            }
        }
        return try {
            var session: Pcv3ArchiveSessionCapability? = null
            var failureCode: String? = null
            var cancellation: CancellationException? = null
            var terminal: Pcv3SnapshotData? = null

            try {
                callerContext.ensureActive()
                val begin = beginSafWithResourcePump(action)
                session = begin.session
                session?.let { action.bindSession(it)?.let(::cancelSafSession) }
                callerContext.ensureActive()
                when (begin.kind) {
                    "terminal" -> {
                        if (begin.session != null || begin.snapshot?.isClosedSafTerminal() != true) {
                            failureCode = "PCV3_ARCHIVE_UNAVAILABLE"
                        } else {
                            terminal = begin.snapshot
                        }
                    }
                    "session" -> {
                        val active = begin.snapshot
                        val activeSession = session
                        if (begin.code.isNotEmpty() || activeSession == null || active?.isExactSafActive() != true) {
                            failureCode = "PCV3_ARCHIVE_UNAVAILABLE"
                        } else {
                            if (action.cancellationRequested()) {
                                failureCode = "PCV3_OPERATION_CANCELLED"
                            }
                            val manifest = if (failureCode == null) capturePcv3SafManifest(
                                activeSession,
                                isCancelled = action::cancellationRequested,
                                onResourceLimit = { failureCode = "PCV3_RESOURCE_LIMIT" },
                            ) else null
                            if (failureCode == null && manifest == null) {
                                failureCode = "PCV3_ARCHIVE_UNAVAILABLE"
                            }
                            if (failureCode == null) {
                                val activeReceipt = active.restoredReceipt
                                val custody = action.custodian.transition(activeReceipt)
                                if (custody != ReceiptCustody.Exact(activeReceipt)) {
                                    failureCode = "PCV3_RECEIPT_PERSIST_FAILED"
                                }
                            }
                            if (failureCode == null && action.cancellationRequested()) {
                                failureCode = "PCV3_OPERATION_CANCELLED"
                            }
                            if (failureCode == null) {
                                val activeReceipt = active.restoredReceipt
                                val confirmed = activeSession.confirmCrashReceiptPersisted(activeReceipt)
                                if (confirmed.kind != "ready" || confirmed.nextIndex != 0L) {
                                    failureCode = "PCV3_ARCHIVE_UNAVAILABLE"
                                }
                            }
                            if (failureCode == null && action.cancellationRequested()) {
                                failureCode = "PCV3_OPERATION_CANCELLED"
                            }
                            if (failureCode == null) {
                                val published = publisher.publish(
                                    root,
                                    manifest!!,
                                    SafEntrySession(activeSession),
                                    action.cancellation,
                                )
                                callerContext.ensureActive()
                                if (published != Pcv3SafPublicationResult.READY_TO_FINISH ||
                                    !action.claimFinish()
                                ) {
                                    failureCode = if (action.cancellationRequested()) {
                                        "PCV3_OPERATION_CANCELLED"
                                    } else if (manifest.memory.resourceLimited) {
                                        "PCV3_RESOURCE_LIMIT"
                                    } else {
                                        "PCV3_ARCHIVE_UNAVAILABLE"
                                    }
                                } else {
                                    terminal = activeSession.finish()
                                    if (!terminal.isClosedSafTerminal()) {
                                        failureCode = "PCV3_ARCHIVE_UNAVAILABLE"
                                        terminal = null
                                    } else if (action.cancellationRequested()) {
                                        failureCode = "PCV3_OPERATION_CANCELLED"
                                    }
                                }
                            }
                        }
                    }
                    else -> failureCode = "PCV3_ARCHIVE_UNAVAILABLE"
                }
            } catch (error: CancellationException) {
                cancellation = error
                failureCode = "PCV3_OPERATION_CANCELLED"
            } catch (_: Exception) {
                failureCode = "PCV3_OPERATION_FAILURE"
            } catch (_: LinkageError) {
                failureCode = "PCV3_OPERATION_FAILURE"
            }

            if (failureCode != null && session != null) {
                cancelSafSession(action.requestCancellation())
                if (action.claimAbort()) {
                    terminal = try {
                        session.abort()
                    } catch (_: Exception) {
                        null
                    } catch (_: LinkageError) {
                        null
                    }
                }
            }

            var receiptSettled = try {
                terminal?.takeIf { it.isClosedSafTerminal() }
                    ?.let { settleSafTerminalReceipt(action.custodian, it) }
                    ?: false
            } catch (error: CancellationException) {
                if (cancellation == null) cancellation = error
                failureCode = "PCV3_OPERATION_CANCELLED"
                false
            }
            if (!receiptSettled && session != null) {
                if (failureCode == null) failureCode = "PCV3_RECEIPT_PERSIST_FAILED"
                cancelSafSession(action.requestCancellation())
                if (action.claimAbort()) {
                    terminal = try {
                        session.abort()
                    } catch (_: Exception) {
                        null
                    } catch (_: LinkageError) {
                        null
                    }
                }
                receiptSettled = false
            }
            SafArchiveCompletion(
                snapshot = terminal,
                receiptSettled = receiptSettled,
                failureCode = failureCode,
                cancellation = cancellation,
            )
        } finally {
            callerCancellationArmed.set(false)
            callerCancellationWatcher.cancel()
            withContext(NonCancellable) {
                callerCancellationWatcher.join()
            }
        }
    }

    private fun cancelSafSession(session: Pcv3ArchiveSessionCapability?) {
        if (session == null) return
        try {
            session.cancel()
        } catch (_: Exception) {
            // Abort below remains the canonical terminal authority.
        } catch (_: LinkageError) {
            // Abort below remains the canonical terminal authority.
        }
    }

    private fun settleSafTerminalReceipt(
        custodian: Pcv3ReceiptCustodyCapability,
        snapshot: Pcv3SnapshotData,
    ): Boolean {
        val desired = if (snapshot.requiresReceipt()) snapshot.restoredReceipt else null
        val custody = try {
            custodian.transition(desired)
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            ReceiptCustody.Unknown
        } catch (_: LinkageError) {
            ReceiptCustody.Unknown
        }
        return if (desired == null) {
            custody === ReceiptCustody.None
        } else {
            custody == ReceiptCustody.Exact(desired)
        }
    }

    private suspend fun finishSafArchiveAction(
        action: SafArchiveAction,
        completion: SafArchiveCompletion,
        releaseCode: String,
    ): Result<Unit> = mutex.withLock {
        val current = state as? State.Active
        if (current == null || current.generation != action.ticket.generation ||
            current.operation !== action.ticket.operation || current.actionToken != action.ticket.token ||
            current.archiveSafAction !== action || current.receiptCustodian !== action.custodian
        ) {
            return@withLock Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
        }
        val terminal = completion.snapshot
        if (terminal == null || !completion.receiptSettled || releaseCode.isNotEmpty()) {
            state = State.Draining(
                generation = current.generation,
                operation = current.operation,
                receiptFile = current.receiptFile,
                creation = current.creation,
                receiptPersisted = action.custodian.custody is ReceiptCustody.Exact,
                snapshot = terminal ?: current.snapshot,
                cancelRequested = true,
                outputActionResult = current.outputActionResult,
                artifactInspection = current.artifactInspection,
                artifactMetadata = current.artifactMetadata,
                artifactInspectionRejected = current.artifactInspectionRejected,
                receiptCustodian = action.custodian,
            )
            _presentation.value = null
            artifactPageToken = null
            _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
            return@withLock Result.failure(
                Pcv3BridgeFailure(
                    completion.failureCode ?: if (!completion.receiptSettled) {
                        "PCV3_RECEIPT_PERSIST_FAILED"
                    } else {
                        "PCV3_OPERATION_RELEASE_DENIED"
                    },
                ),
            )
        }

        val presentation = Pcv3Presentation.Final(
            snapshot = projectPcv3Snapshot(terminal),
            operationId = current.operation.id,
            generation = current.generation,
            outputAction = current.outputActionResult,
            artifactMetadata = current.artifactMetadata?.toView(),
            isCreation = current.creation,
        )
        state = State.Final(
            generation = current.generation,
            receiptFile = current.receiptFile,
            receiptPersisted = action.custodian.custody is ReceiptCustody.Exact,
            creation = current.creation,
            artifactInspection = current.artifactInspection,
            artifactMetadata = current.artifactMetadata,
            receiptCustodian = action.custodian,
        )
        _presentation.value = presentation
        artifactPageToken = null
        _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
        completion.failureCode?.let { Result.failure(Pcv3BridgeFailure(it)) } ?: Result.success(Unit)
    }

    private fun Pcv3SnapshotData.isExactSafActive(): Boolean =
        hasExactSafBaseAxes() && hasExactSafSuccessSemantic() &&
            publicationAttempted && publicationState == "publication-indeterminate" &&
            publicationStage == "output-publication" &&
            publicationCode == "PCV3_PUBLICATION_INDETERMINATE" &&
            diagnostic == "none" && completionClass == "publication-indeterminate" &&
            warnings == listOf("publication-indeterminate") &&
            !archivePending && restoredReceipt.isNotEmpty()

    private fun Pcv3SnapshotData.isClosedSafTerminal(): Boolean {
        if (archivePending || !hasExactSafBaseAxes()) return false
        return isExactSafNoOutputWithoutAttempt() || isExactSafNotPublished() ||
            isExactSafResourceRefusal() || isExactSafPreparationCancelled() ||
            isExactSafDurabilityUncertain() || isExactSafPublicationIndeterminate()
    }

    private fun Pcv3SnapshotData.hasExactSafBaseAxes(): Boolean =
        args.isEmpty() && forceProvenance == "none" &&
            d1BootstrapProvenance == "none" && detailStage == "none"

    private fun Pcv3SnapshotData.isExactSafNoOutputWithoutAttempt(): Boolean =
        outcome == "operation-failed" && stage == "output-publication" &&
            code == "PCV3_OPERATION_FAILED" && !publicationAttempted &&
            publicationState == "none" && publicationStage == "none" &&
            publicationCode == "none" && completionClass == "no-output" &&
            diagnostic in setOf("none", "core-failure") &&
            (warnings.isEmpty() || warnings == listOf("cleanup-incomplete")) &&
            restoredReceipt.isEmpty()

    private fun Pcv3SnapshotData.isExactSafNotPublished(): Boolean =
        outcome == "operation-failed" && stage == "output-publication" &&
            code == "PCV3_OPERATION_FAILED" && publicationAttempted &&
            publicationState == "not-published" && publicationStage == "output-publication" &&
            publicationCode == "PCV3_PUBLICATION_NOT_PUBLISHED" && completionClass == "no-output" &&
            diagnostic == "none" && warnings.isEmpty() && restoredReceipt.isEmpty()

    private fun Pcv3SnapshotData.isExactSafResourceRefusal(): Boolean =
        outcome == "operation-failed" && stage == "resource-budget" &&
            code == "PCV3_OPERATION_FAILED" && !publicationAttempted &&
            publicationState == "none" && publicationStage == "none" &&
            publicationCode == "none" && completionClass == "no-output" &&
            diagnostic == "resource-limit" && warnings.isEmpty() && restoredReceipt.isEmpty()

    private fun Pcv3SnapshotData.isExactSafPreparationCancelled(): Boolean =
        outcome == "operation-failed" && stage == "cancellation" &&
            code == "PCV3_OPERATION_FAILED" && publicationAttempted &&
            publicationState == "not-published" && publicationStage == "cancellation" &&
            publicationCode == "PCV3_PUBLICATION_CANCELLED" && completionClass == "refused" &&
            diagnostic == "cancellation" && warnings.isEmpty() && restoredReceipt.isEmpty()

    private fun Pcv3SnapshotData.isExactSafDurabilityUncertain(): Boolean =
        hasExactSafSuccessSemantic() && publicationAttempted &&
            publicationState == "published-durability-uncertain" &&
            publicationStage == "directory-sync" &&
            publicationCode == "PCV3_PUBLICATION_DURABILITY_UNCERTAIN" &&
            completionClass == "durability-uncertain" && diagnostic == "none" &&
            warnings in setOf(
                listOf("durability-uncertain"),
                listOf("durability-uncertain", "cleanup-incomplete"),
            ) && restoredReceipt.isNotEmpty()

    private fun Pcv3SnapshotData.isExactSafPublicationIndeterminate(): Boolean =
        hasExactSafSuccessSemantic() && publicationAttempted &&
            publicationState == "publication-indeterminate" &&
            publicationStage == "output-publication" &&
            publicationCode == "PCV3_PUBLICATION_INDETERMINATE" &&
            completionClass == "publication-indeterminate" &&
            diagnostic in setOf("none", "core-failure") &&
            warnings in setOf(
                listOf("publication-indeterminate"),
                listOf("publication-indeterminate", "cleanup-incomplete"),
            ) && restoredReceipt.isNotEmpty()

    private fun Pcv3SnapshotData.hasExactSafSuccessSemantic(): Boolean =
        outcome == "success" && stage == "none" && code == "PCV3_SUCCESS"

    suspend fun savePcv3Output(
        expectedOperationId: String,
        expectedGeneration: Long,
        destination: ParcelFileDescriptor,
    ): Result<Unit> = outputAction(
        expectedOperationId = expectedOperationId,
        expectedGeneration = expectedGeneration,
        boundaryFailure = Pcv3OutputResultData("save-failed-cleanup-incomplete", cleanupIncomplete = true),
        onUntransferred = { destination.closeAttachedPcv3Destination() },
        actionCall = { it.save(destination) },
    )

    suspend fun discardPcv3Output(
        expectedOperationId: String,
        expectedGeneration: Long,
    ): Result<Unit> = outputAction(
        expectedOperationId = expectedOperationId,
        expectedGeneration = expectedGeneration,
        boundaryFailure = Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true),
        actionCall = { it.discard() },
    )

    /**
     * Loads one passive page outside lifecycle ownership, then publishes it only
     * if the exact generation, captured handle, and newest page ticket still match.
     */
    suspend fun loadPcv3ArtifactPage(
        expectedOperationId: String,
        expectedGeneration: Long,
        offsetDecimal: String,
        limit: Int,
    ): Result<Pcv3ArtifactPageView> {
        val ticket = mutex.withLock {
            acceptArtifactPageLocked(expectedOperationId, expectedGeneration, offsetDecimal, limit)
        } ?: return Result.failure(Pcv3BridgeFailure("PCV3_ARTIFACT_INSPECTION_UNAVAILABLE"))

        val page = try {
            if (ticket.metadata.rangeCount == "0" && offsetDecimal == "0") {
                Pcv3ArtifactPageData(offsetDecimal, emptyList())
            } else {
                ticket.inspection.page(offsetDecimal, limit)
            }
        } catch (error: CancellationException) {
            withContext(NonCancellable) { finishArtifactPage(ticket, null, offsetDecimal, limit) }
            throw error
        } catch (_: Exception) {
            null
        } catch (_: LinkageError) {
            null
        }
        return finishArtifactPage(ticket, page, offsetDecimal, limit)
    }

    private fun acceptArtifactPageLocked(
        expectedOperationId: String,
        expectedGeneration: Long,
        offsetDecimal: String,
        limit: Int,
    ): ArtifactPageTicket? {
        if (!offsetDecimal.isCanonicalPcv3Uint() || limit !in 1..128) return null
        val presentation = _presentation.value ?: return null
        if (presentation.operationId != expectedOperationId || presentation.generation != expectedGeneration) return null
        val pair = when (val current = state) {
            is State.Active -> {
                if (presentation !is Pcv3Presentation.Live || current.generation != expectedGeneration ||
                    current.actionToken != null || current.outputActionInFlight
                ) {
                    return null
                }
                current.artifactInspection to current.artifactMetadata
            }
            is State.Final -> {
                if (presentation !is Pcv3Presentation.Final || current.generation != expectedGeneration) return null
                current.artifactInspection to current.artifactMetadata
            }
            State.Idle, is State.Starting, is State.Draining -> return null
        }
        val inspection = pair.first ?: return null
        val metadata = pair.second ?: return null
        val token = ++nextArtifactPageToken
        artifactPageToken = token
        _artifactDetails.value = Pcv3ArtifactDetailsUiState.Loading
        return ArtifactPageTicket(token, expectedGeneration, expectedOperationId, inspection, metadata)
    }

    private fun invalidateLoadingArtifactPageLocked() {
        if (artifactPageToken == null) return
        artifactPageToken = null
        _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
    }

    private suspend fun finishArtifactPage(
        ticket: ArtifactPageTicket,
        page: Pcv3ArtifactPageData?,
        expectedOffset: String,
        limit: Int,
    ): Result<Pcv3ArtifactPageView> = mutex.withLock {
        val presentation = _presentation.value
        val currentPair = when (val current = state) {
            is State.Active -> current.artifactInspection to current.artifactMetadata
            is State.Final -> current.artifactInspection to current.artifactMetadata
            State.Idle, is State.Starting, is State.Draining -> null
        }
        if (artifactPageToken != ticket.token || presentation == null ||
            presentation.operationId != ticket.operationId || presentation.generation != ticket.generation ||
            currentPair?.first !== ticket.inspection || currentPair.second != ticket.metadata
        ) {
            return@withLock Result.failure(Pcv3BridgeFailure("PCV3_ARTIFACT_INSPECTION_UNAVAILABLE"))
        }

        artifactPageToken = null
        val accepted = page?.takeIf { it.fitsArtifactMetadata(ticket.metadata, expectedOffset, limit) }
        if (accepted == null) {
            _artifactDetails.value = Pcv3ArtifactDetailsUiState.Failed("PCV3_ARTIFACT_INSPECTION_UNAVAILABLE")
            return@withLock Result.failure(Pcv3BridgeFailure("PCV3_ARTIFACT_INSPECTION_UNAVAILABLE"))
        }
        val view = accepted.toView()
        _artifactDetails.value = Pcv3ArtifactDetailsUiState.Ready(ticket.metadata.toView(), view)
        Result.success(view)
    }

    private fun Pcv3ArtifactPageData.fitsArtifactMetadata(
        metadata: Pcv3ArtifactMetadataData,
        expectedOffset: String,
        limit: Int,
    ): Boolean {
        val total = metadata.rangeCount.toCanonicalPcv3ULong() ?: return false
        val offset = expectedOffset.toCanonicalPcv3ULong() ?: return false
        if (ranges.isEmpty()) return total == 0uL && offset == 0uL && offsetDecimal == "0"
        if (!isClosedPcv3ArtifactPage(expectedOffset, limit) || offset > total) return false
        return ranges.size.toULong() <= total - offset
    }

    private fun String.isCanonicalPcv3Uint(): Boolean = toCanonicalPcv3ULong() != null

    private fun String.toCanonicalPcv3ULong(): ULong? =
        toULongOrNull()?.takeIf { it.toString() == this }

    private suspend fun outputAction(
        expectedOperationId: String,
        expectedGeneration: Long,
        boundaryFailure: Pcv3OutputResultData,
        onUntransferred: () -> Unit = {},
        actionCall: (Pcv3OutputCapability) -> Pcv3OutputResultData,
    ): Result<Unit> {
        val callerContext = currentCoroutineContext()
        val action = try {
            mutex.withLock { acceptOutputActionLocked(expectedOperationId, expectedGeneration) }
        } catch (error: CancellationException) {
            onUntransferred()
            throw error
        }
        if (action == null) {
            onUntransferred()
            return Result.failure(Pcv3BridgeFailure("PCV3_OUTPUT_UNAVAILABLE"))
        }

        var actionCallStarted = false
        return try {
            withContext(NonCancellable + Dispatchers.IO) {
                var actionFailure: String? = null
                var cancellation: CancellationException? = null
                val result = try {
                    actionCallStarted = true
                    actionCall(action.handle)
                } catch (error: CancellationException) {
                    cancellation = error
                    boundaryFailure
                } catch (_: Exception) {
                    actionFailure = "PCV3_OPERATION_FAILURE"
                    boundaryFailure
                } catch (_: LinkageError) {
                    actionFailure = "PCV3_OPERATION_FAILURE"
                    boundaryFailure
                }
                try {
                    callerContext.ensureActive()
                } catch (error: CancellationException) {
                    if (cancellation == null) cancellation = error
                }
                val reconciled = finishPcv3OutputAction(action.ticket, result, actionFailure, cancellation)
                actionResult(reconciled, actionFailure)
            }
        } finally {
            if (!actionCallStarted) onUntransferred()
        }
    }

    private fun acceptOutputActionLocked(
        expectedOperationId: String,
        expectedGeneration: Long,
    ): OutputAction? {
        val current = state as? State.Active ?: return null
        val live = _presentation.value as? Pcv3Presentation.Live ?: return null
        val handle = current.outputHandle ?: return null
        if (current.actionToken != null || current.outputActionInFlight ||
            current.generation != expectedGeneration || live.generation != expectedGeneration ||
            live.operationId != expectedOperationId || live.operationHandle !== current.operation ||
            live.outputHandle !== handle || !live.outputPending
        ) {
            return null
        }
        val ticket = ActionTicket(++nextActionToken, current.generation, current.operation)
        invalidateLoadingArtifactPageLocked()
        val pending = current.copy(
            outputHandle = null,
            actionToken = ticket.token,
            outputActionInFlight = true,
        )
        state = pending
        if (publishActiveLocked(pending) == null) {
            state = current
            publishActiveLocked(current)
            return null
        }
        return OutputAction(ticket, handle)
    }

    suspend fun selectPcv3ConsentRole(role: String): Result<Unit> = mutex.withLock {
        val current = state as? State.Active
            ?: return@withLock Result.failure(Pcv3BridgeFailure("PCV3_CONSENT_EXPIRED"))
        val consent = current.consent
        if (current.actionToken != null || current.consentHandle == null || consent == null || role !in consent.allowedRoles) {
            return@withLock Result.failure(Pcv3BridgeFailure("PCV3_CONSENT_EXPIRED"))
        }
        val selected = current.copy(consent = consent.copy(selectedRole = role))
        state = selected
        publishActiveLocked(selected)
        Result.success(Unit)
    }

    suspend fun confirmPcv3Consent(): Result<Unit> = consentAction(requireSelection = true)

    suspend fun refusePcv3Consent(): Result<Unit> = consentAction(requireSelection = false)

    private suspend fun consentAction(requireSelection: Boolean): Result<Unit> {
        val action = mutex.withLock {
            val current = state as? State.Active
                ?: return@withLock null
            val handle = current.consentHandle ?: return@withLock null
            val selected = current.consent?.selectedRole
            if (current.actionToken != null || (requireSelection && selected == null)) return@withLock null
            val ticket = ActionTicket(++nextActionToken, current.generation, current.operation)
            val pending = current.copy(consentHandle = null, consent = null, actionToken = ticket.token)
            state = pending
            publishActiveLocked(pending)
            ConsentAction(ticket, handle, selected.orEmpty())
        } ?: return Result.failure(Pcv3BridgeFailure("PCV3_CONSENT_EXPIRED"))

        var actionFailure: String? = null
        var cancellation: CancellationException? = null
        val callerContext = currentCoroutineContext()
        try {
            callerContext.ensureActive()
            val code = if (requireSelection) action.handle.choose(action.role) else action.handle.refuse()
            callerContext.ensureActive()
            if (code.isNotEmpty()) actionFailure = "PCV3_CONSENT_EXPIRED"
        } catch (error: CancellationException) {
            cancellation = error
        } catch (_: Exception) {
            actionFailure = "PCV3_OPERATION_FAILURE"
        }
        val reconciled = finishPcv3Action(action.ticket, null, actionFailure, cancellation)
        return actionResult(reconciled, actionFailure)
    }

    private suspend fun archiveAction(actionCall: (Pcv3ArchiveCapability) -> Pcv3SnapshotData): Result<Unit> {
        val action = mutex.withLock {
            val current = state as? State.Active
                ?: return@withLock null
            val handle = current.archiveHandle ?: return@withLock null
            if (current.actionToken != null) return@withLock null
            val ticket = ActionTicket(++nextActionToken, current.generation, current.operation)
            val pending = current.copy(archiveHandle = null, actionToken = ticket.token)
            state = pending
            publishActiveLocked(pending)
            ArchiveAction(ticket, handle)
        } ?: return Result.failure(Pcv3BridgeFailure("PCV3_ARCHIVE_UNAVAILABLE"))

        var returnedSnapshot: Pcv3SnapshotData? = null
        var actionFailure: String? = null
        var cancellation: CancellationException? = null
        val callerContext = currentCoroutineContext()
        try {
            callerContext.ensureActive()
            returnedSnapshot = actionCall(action.handle)
            callerContext.ensureActive()
        } catch (error: CancellationException) {
            cancellation = error
        } catch (_: Exception) {
            actionFailure = "PCV3_OPERATION_FAILURE"
        }
        val reconciled = finishPcv3Action(action.ticket, returnedSnapshot, actionFailure, cancellation)
        return actionResult(reconciled, actionFailure)
    }

    /** Action cleanup passes through one exact-ticket path under a narrow cancellation shield. */
    private suspend fun finishPcv3Action(
        ticket: ActionTicket,
        returnedSnapshot: Pcv3SnapshotData?,
        actionFailure: String?,
        cancellation: CancellationException?,
    ): Result<Pcv3Presentation> = withContext(NonCancellable) {
        mutex.withLock {
            val current = state as? State.Active
            if (current == null || current.generation != ticket.generation || current.operation !== ticket.operation || current.actionToken != ticket.token) {
                return@withLock Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
            }
            val active = current.copy(actionToken = null)
            when {
                cancellation != null ->
                    beginDrainLocked(active, returnedSnapshot, "PCV3_OPERATION_CANCELLED", cancellation)
                actionFailure != null ->
                    beginDrainLocked(active, returnedSnapshot, actionFailure)
                else -> reconcileActiveLocked(active, returnedSnapshot = returnedSnapshot)
            }
        }
    }

    private suspend fun finishPcv3OutputAction(
        ticket: ActionTicket,
        actionResult: Pcv3OutputResultData,
        actionFailure: String?,
        cancellation: CancellationException?,
    ): Result<Pcv3Presentation> = withContext(NonCancellable) {
        mutex.withLock {
            val current = state as? State.Active
            if (current == null || current.generation != ticket.generation ||
                current.operation !== ticket.operation || current.actionToken != ticket.token ||
                !current.outputActionInFlight
            ) {
                return@withLock Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
            }
            var active = current.copy(
                actionToken = null,
                outputActionInFlight = false,
                outputActionResult = mergeOutputActionResult(
                    current.outputActionResult.takeUnless {
                        current.creation && it?.code == "save-failed" && !it.cleanupIncomplete
                    },
                    actionResult.toView(),
                ),
            )
            state = active

            val remainingOutput = try {
                active.operation.output()
            } catch (error: CancellationException) {
                return@withLock beginDrainLocked(
                    active.withOutputCleanupUncertain(),
                    failureCode = "PCV3_OPERATION_CANCELLED",
                    cancellation = error,
                )
            } catch (_: Exception) {
                return@withLock beginDrainLocked(
                    active.withOutputCleanupUncertain(),
                    failureCode = "PCV3_OPERATION_FAILURE",
                )
            } catch (_: LinkageError) {
                return@withLock beginDrainLocked(
                    active.withOutputCleanupUncertain(),
                    failureCode = "PCV3_OPERATION_FAILURE",
                )
            }
            if (remainingOutput != null) {
                // Ciphertext remains a reusable result after a confirmed failed save.
                // Plaintext and uncertain bridge outcomes retain the cleanup path.
                if (active.creation && actionResult.code == "save-failed" &&
                    !actionResult.cleanupIncomplete && actionFailure == null && cancellation == null
                ) {
                    active = active.copy(outputHandle = remainingOutput)
                    state = active
                    val reconciled = reconcileActiveLocked(active)
                    return@withLock if (reconciled.isFailure) reconciled else
                        Result.failure(Pcv3BridgeFailure("PCV3_OUTPUT_SAVE_FAILED"))
                }
                active = active.withOutputCleanupUncertain().copy(outputHandle = remainingOutput)
                return@withLock beginDrainLocked(active, failureCode = "PCV3_OPERATION_FAILURE")
            }
            active = active.copy(outputHandle = null)
            when {
                cancellation != null ->
                    beginDrainLocked(active, failureCode = "PCV3_OPERATION_CANCELLED", cancellation = cancellation)
                actionFailure != null ->
                    beginDrainLocked(active, failureCode = actionFailure)
                else -> reconcileActiveLocked(active)
            }
        }
    }

    private fun Pcv3OutputResultData.toView(): Pcv3OutputResultView =
        Pcv3OutputResultView(code = code, cleanupIncomplete = cleanupIncomplete)

    private fun mergeOutputActionResult(
        current: Pcv3OutputResultView?,
        next: Pcv3OutputResultView,
    ): Pcv3OutputResultView = when {
        current == null -> next
        current.cleanupIncomplete || !next.cleanupIncomplete -> current
        else -> current.withCleanupIncompleteCode()
    }

    private fun Pcv3OutputResultView.withCleanupIncompleteCode(): Pcv3OutputResultView = when (code) {
        "saved", "saved-cleanup-incomplete" ->
            Pcv3OutputResultView("saved-cleanup-incomplete", cleanupIncomplete = true)
        "save-failed", "save-failed-cleanup-incomplete" ->
            Pcv3OutputResultView("save-failed-cleanup-incomplete", cleanupIncomplete = true)
        "discarded", "discard-cleanup-incomplete" ->
            Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = true)
        else -> Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = true)
    }

    private fun State.Draining.withOutputCleanupUncertain(): State.Draining = copy(
        outputActionResult = mergeOutputActionResult(
            outputActionResult,
            Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = true),
        ),
    )

    private fun State.Active.withOutputCleanupUncertain(): State.Active = copy(
        outputActionResult = mergeOutputActionResult(
            outputActionResult,
            Pcv3OutputResultView("discard-cleanup-incomplete", cleanupIncomplete = true),
        ),
    )

    private fun captureArtifactInspection(
        operation: Pcv3OperationCapability,
        snapshot: Pcv3SnapshotData,
        existingInspection: Pcv3ArtifactInspectionCapability?,
        existingMetadata: Pcv3ArtifactMetadataData?,
        rejected: Boolean,
    ): ArtifactCapture {
        if (rejected) return ArtifactCapture.Accepted(null, null)
        val expectedKind = snapshot.expectedArtifactKind()
        val inspection = if (existingInspection != null) {
            existingInspection
        } else try {
            operation.artifactInspection()
        } catch (error: CancellationException) {
            return ArtifactCapture.Rejected(error)
        } catch (_: Exception) {
            return ArtifactCapture.Rejected()
        } catch (_: LinkageError) {
            return ArtifactCapture.Rejected()
        }
        if (inspection == null) {
            return if (expectedKind == null) ArtifactCapture.Accepted(null, null) else ArtifactCapture.Rejected()
        }
        if (expectedKind == null) return ArtifactCapture.Rejected()
        val metadata = if (existingMetadata != null) {
            existingMetadata
        } else try {
            inspection.metadata()
        } catch (error: CancellationException) {
            return ArtifactCapture.Rejected(error)
        } catch (_: Exception) {
            return ArtifactCapture.Rejected()
        } catch (_: LinkageError) {
            return ArtifactCapture.Rejected()
        }
        if (metadata == null || !metadata.isClosedPcv3ArtifactMetadata() || metadata.kind != expectedKind) {
            return ArtifactCapture.Rejected()
        }
        return ArtifactCapture.Accepted(inspection, metadata)
    }

    private fun Pcv3SnapshotData.expectedArtifactKind(): String? {
        if (archivePending || completionClass != "warning" || !publicationAttempted ||
            publicationState != "published-durable" || publicationStage != "none" ||
            publicationCode != "PCV3_PUBLICATION_PUBLISHED_DURABLE"
        ) {
            return null
        }
        return when {
            outcome == "force-partial" && code == "PCV3_FORCE_PARTIAL" && forceProvenance == "partial" -> "partial"
            outcome == "force-unverified" && code == "PCV3_FORCE_UNVERIFIED" && forceProvenance == "unverified" ->
                "unverified-forensic"
            else -> null
        }
    }

    private fun reconcileActiveLocked(
        initial: State.Active,
        initialFailure: String? = null,
        returnedSnapshot: Pcv3SnapshotData? = null,
    ): Result<Pcv3Presentation> {
        var active = initial
        var failure = initialFailure
        var suppliedSnapshot = returnedSnapshot
        while (true) {
            val snapshot = if (suppliedSnapshot != null) {
                suppliedSnapshot.also { suppliedSnapshot = null }
            } else try {
                active.operation.snapshot()
            } catch (error: Exception) {
                return beginDrainLocked(
                    active = active,
                    snapshot = active.snapshot,
                    failureCode = "PCV3_OPERATION_FAILURE",
                    cancellation = error as? CancellationException,
                )
            }
            val consentHandle = try {
                active.operation.consent()
            } catch (error: Exception) {
                return beginDrainLocked(active, snapshot, "PCV3_OPERATION_FAILURE", error as? CancellationException)
            }
            val consent = try {
                consentHandle?.toViewOrNull()
            } catch (error: Exception) {
                return beginDrainLocked(active, snapshot, "PCV3_OPERATION_FAILURE", error as? CancellationException)
            }

            if (consentHandle != null && consent == null) {
                if (active.invalidConsentRefused) {
                    return beginDrainLocked(active, snapshot, "PCV3_CONSENT_EXPIRED")
                }
                active = active.copy(
                    snapshot = snapshot,
                    consentHandle = null,
                    consent = null,
                    archiveHandle = null,
                    invalidConsentRefused = true,
                    actionToken = null,
                )
                state = active
                val refusalCode = try {
                    consentHandle.refuse()
                } catch (error: Exception) {
                    return beginDrainLocked(active, snapshot, "PCV3_CONSENT_EXPIRED", error as? CancellationException)
                }
                if (refusalCode.isNotEmpty()) {
                    return beginDrainLocked(active, snapshot, "PCV3_CONSENT_EXPIRED")
                }
                continue
            }

            val archiveHandle = try {
                active.operation.archive()
            } catch (error: Exception) {
                return beginDrainLocked(active, snapshot, "PCV3_OPERATION_FAILURE", error as? CancellationException)
            }
            val priorOutputHandle = active.outputHandle
            val outputHandle = try {
                active.operation.output()
            } catch (error: Exception) {
                return beginDrainLocked(active, snapshot, "PCV3_OPERATION_FAILURE", error as? CancellationException)
            } catch (_: LinkageError) {
                return beginDrainLocked(active, snapshot, "PCV3_OPERATION_FAILURE")
            }
            val selectedRole = active.consent?.selectedRole?.takeIf { it in (consent?.allowedRoles ?: emptyList()) }
            active = active.copy(
                snapshot = snapshot,
                consentHandle = consentHandle?.takeIf { consent != null },
                archiveHandle = archiveHandle,
                outputHandle = outputHandle,
                consent = consent?.copy(selectedRole = selectedRole),
                actionToken = null,
            )

            val artifact = captureArtifactInspection(
                operation = active.operation,
                snapshot = snapshot,
                existingInspection = active.artifactInspection,
                existingMetadata = active.artifactMetadata,
                rejected = active.artifactInspectionRejected,
            )
            if (snapshot.completionClass == "unknown" &&
                (artifact !is ArtifactCapture.Rejected || artifact.cancellation == null)
            ) {
                // JNI accessors are separate observations: the worker may attach a
                // terminal result between them. Terminal (including archive-pending)
                // state stays stable until a Kotlin-owned action. Recollect once from
                // that settled snapshot before judging a mixed observation invalid.
                val settled = try {
                    active.operation.snapshot()
                } catch (error: Exception) {
                    return beginDrainLocked(active, snapshot, "PCV3_OPERATION_FAILURE", error as? CancellationException)
                }
                if (settled.completionClass != "unknown") {
                    suppliedSnapshot = settled
                    continue
                }
            }
            when (artifact) {
                is ArtifactCapture.Accepted -> active = active.copy(
                    artifactInspection = artifact.inspection,
                    artifactMetadata = artifact.metadata,
                )
                is ArtifactCapture.Rejected -> return beginDrainLocked(
                    active.copy(
                        artifactInspection = null,
                        artifactMetadata = null,
                        artifactInspectionRejected = true,
                    ),
                    snapshot,
                    "PCV3_OPERATION_FAILURE",
                    artifact.cancellation,
                )
            }

            if (outputHandle != null && !snapshot.allowsOutputCapability(
                    consentHandle = consentHandle,
                    archiveHandle = archiveHandle,
                    priorAction = active.outputActionResult,
                    creation = active.creation,
                )
            ) {
                return beginDrainLocked(active, snapshot, "PCV3_OPERATION_FAILURE")
            }
            if (priorOutputHandle != null && outputHandle == null && active.outputActionResult == null) {
                return beginDrainLocked(
                    active.withOutputCleanupUncertain(),
                    snapshot,
                    "PCV3_OPERATION_FAILURE",
                )
            }

            if (snapshot.isReleaseCandidate() && consentHandle == null && archiveHandle == null &&
                outputHandle == null && active.actionToken == null && !active.outputActionInFlight
            ) {
                val final = try {
                    Pcv3Presentation.Final(
                        snapshot = projectPcv3Snapshot(snapshot),
                        operationId = active.operation.id,
                        generation = active.generation,
                        outputAction = active.outputActionResult,
                        artifactMetadata = active.artifactMetadata?.toView(),
                        isCreation = active.creation,
                    )
                } catch (error: Exception) {
                    return beginDrainLocked(active, snapshot, "PCV3_OPERATION_FAILURE", error as? CancellationException)
                }
                val receiptPersisted = persistedReceiptState(
                    snapshot = snapshot,
                    receiptFile = active.receiptFile,
                    alreadyPersisted = active.receiptPersisted,
                    receiptCustodian = active.receiptCustodian,
                ) ?: return retainDrainingLocked(
                    active = active,
                    snapshot = snapshot,
                    failureCode = "PCV3_RECEIPT_PERSIST_FAILED",
                )
                active = active.copy(receiptPersisted = receiptPersisted)
                state = active
                val releaseCode = try {
                    active.operation.release()
                } catch (error: Exception) {
                    return retainDrainingLocked(active, snapshot, "PCV3_OPERATION_RELEASE_DENIED", error as? CancellationException)
                }
                if (releaseCode.isEmpty()) {
                    state = State.Final(
                        generation = active.generation,
                        receiptFile = active.receiptFile,
                        receiptPersisted = active.receiptPersisted,
                        creation = active.creation,
                        artifactInspection = active.artifactInspection,
                        artifactMetadata = active.artifactMetadata,
                        receiptCustodian = active.receiptCustodian,
                    )
                    _presentation.value = final
                    return failure?.let { Result.failure(Pcv3BridgeFailure(it)) } ?: Result.success(final)
                }
                return retainDrainingLocked(active, snapshot, "PCV3_OPERATION_RELEASE_DENIED")
            }

            state = active
            val presentation = publishActiveLocked(active)
                ?: return Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
            return failure?.let { Result.failure(Pcv3BridgeFailure(it)) } ?: Result.success(presentation)
        }
    }

    /**
     * Moves a failing live operation behind a private cleanup boundary and performs one
     * bounded drain attempt. Later calls to [refreshPcv3] perform at most one further attempt.
     */
    private fun beginDrainLocked(
        active: State.Active,
        snapshot: Pcv3SnapshotData? = active.snapshot,
        failureCode: String,
        cancellation: CancellationException? = null,
    ): Result<Pcv3Presentation> {
        val draining = State.Draining(
            generation = active.generation,
            operation = active.operation,
            receiptFile = active.receiptFile,
            creation = active.creation,
            receiptPersisted = active.receiptPersisted,
            snapshot = snapshot,
            outputActionResult = active.outputActionResult,
            artifactInspection = active.artifactInspection,
            artifactMetadata = active.artifactMetadata,
            artifactInspectionRejected = active.artifactInspectionRejected,
            receiptCustodian = active.receiptCustodian,
        )
        state = draining
        _presentation.value = null
        artifactPageToken = null
        _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
        return attemptDrainLocked(draining, failureCode, cancellation, reportFailureAfterDrain = true)
    }

    private fun retainDrainingLocked(
        active: State.Active,
        snapshot: Pcv3SnapshotData,
        failureCode: String,
        cancellation: CancellationException? = null,
    ): Result<Pcv3Presentation> {
        state = State.Draining(
            generation = active.generation,
            operation = active.operation,
            receiptFile = active.receiptFile,
            creation = active.creation,
            receiptPersisted = active.receiptPersisted,
            snapshot = snapshot,
            cancelRequested = true,
            outputActionResult = active.outputActionResult,
            artifactInspection = active.artifactInspection,
            artifactMetadata = active.artifactMetadata,
            artifactInspectionRejected = active.artifactInspectionRejected,
            receiptCustodian = active.receiptCustodian,
        )
        _presentation.value = null
        artifactPageToken = null
        _artifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
        cancellation?.let { throw it }
        return Result.failure(Pcv3BridgeFailure(failureCode))
    }

    /** One bounded cleanup pass: cancel, consume capabilities, refresh once, release once. */
    private fun attemptDrainLocked(
        initial: State.Draining,
        failureCode: String = "PCV3_OPERATION_UNAVAILABLE",
        pendingCancellation: CancellationException? = null,
        reportFailureAfterDrain: Boolean = false,
    ): Result<Pcv3Presentation> {
        var draining = initial
        var cancellation = pendingCancellation
        var releaseBlocked = false

        fun record(error: Throwable) {
            if (error is CancellationException && cancellation == null) cancellation = error
        }

        fun retainPrivateDrain(): Result<Pcv3Presentation> {
            state = draining
            _presentation.value = null
            cancellation?.let { throw it }
            return Result.failure(Pcv3BridgeFailure(failureCode))
        }

        state = draining
        _presentation.value = null

        if (draining.receiptCustodian?.custody === ReceiptCustody.Unknown) {
            return retainPrivateDrain()
        }

        if (!draining.cancelRequested) {
            try {
                val cancelled = draining.operation.cancel()
                draining = draining.copy(
                    snapshot = preferTerminalSnapshot(draining.snapshot, cancelled),
                    cancelRequested = true,
                )
            } catch (error: Exception) {
                record(error)
                releaseBlocked = true
            } catch (error: LinkageError) {
                record(error)
                releaseBlocked = true
            }
        }

        try {
            draining.operation.consent()?.let { consent ->
                try {
                    consent.refuse()
                } catch (error: Exception) {
                    record(error)
                    releaseBlocked = true
                } catch (error: LinkageError) {
                    record(error)
                    releaseBlocked = true
                }
            }
        } catch (error: Exception) {
            record(error)
            releaseBlocked = true
        } catch (error: LinkageError) {
            record(error)
            releaseBlocked = true
        }

        val output = try {
            draining.operation.output()
        } catch (error: Exception) {
            record(error)
            draining = draining.withOutputCleanupUncertain()
            releaseBlocked = true
            null
        } catch (error: LinkageError) {
            record(error)
            draining = draining.withOutputCleanupUncertain()
            releaseBlocked = true
            null
        }
        if (output != null) {
            val result = try {
                output.discard()
            } catch (error: CancellationException) {
                record(error)
                Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true)
            } catch (error: Exception) {
                record(error)
                Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true)
            } catch (error: LinkageError) {
                record(error)
                Pcv3OutputResultData("discard-cleanup-incomplete", cleanupIncomplete = true)
            }
            draining = draining.copy(
                outputActionResult = mergeOutputActionResult(
                    draining.outputActionResult,
                    result.toView(),
                ),
            )
            // A one-shot Discard may have changed native state irreversibly; save it
            // before any later accessor, archive, snapshot, or release boundary.
            state = draining
            val remainingOutput = try {
                draining.operation.output()
            } catch (error: Exception) {
                record(error)
                draining = draining.withOutputCleanupUncertain()
                releaseBlocked = true
                null
            } catch (error: LinkageError) {
                record(error)
                draining = draining.withOutputCleanupUncertain()
                releaseBlocked = true
                null
            }
            if (remainingOutput != null) {
                draining = draining.withOutputCleanupUncertain()
                releaseBlocked = true
            }
        }

        try {
            draining.operation.archive()?.let { archive ->
                try {
                    draining = draining.copy(
                        snapshot = preferTerminalSnapshot(draining.snapshot, archive.close()),
                    )
                } catch (error: Exception) {
                    record(error)
                    releaseBlocked = true
                } catch (error: LinkageError) {
                    record(error)
                    releaseBlocked = true
                }
            }
        } catch (error: Exception) {
            record(error)
            releaseBlocked = true
        } catch (error: LinkageError) {
            record(error)
            releaseBlocked = true
        }

        try {
            draining = draining.copy(
                snapshot = preferTerminalSnapshot(draining.snapshot, draining.operation.snapshot()),
            )
        } catch (error: Exception) {
            record(error)
            releaseBlocked = true
        } catch (error: LinkageError) {
            record(error)
            releaseBlocked = true
        }

        state = draining
        if (releaseBlocked) return retainPrivateDrain()
        val snapshot = draining.snapshot
        if (snapshot != null && snapshot.isReleaseCandidate()) {
            when (val artifact = captureArtifactInspection(
                operation = draining.operation,
                snapshot = snapshot,
                existingInspection = draining.artifactInspection,
                existingMetadata = draining.artifactMetadata,
                rejected = draining.artifactInspectionRejected,
            )) {
                is ArtifactCapture.Accepted -> draining = draining.copy(
                    artifactInspection = artifact.inspection,
                    artifactMetadata = artifact.metadata,
                )
                is ArtifactCapture.Rejected -> {
                    artifact.cancellation?.let(::record)
                    draining = draining.copy(
                        artifactInspection = null,
                        artifactMetadata = null,
                        artifactInspectionRejected = true,
                    )
                }
            }
            state = draining
            val final = try {
                Pcv3Presentation.Final(
                    snapshot = projectPcv3Snapshot(snapshot),
                    operationId = draining.operation.id,
                    generation = draining.generation,
                    outputAction = draining.outputActionResult,
                    artifactMetadata = draining.artifactMetadata?.toView(),
                    isCreation = draining.creation,
                )
            } catch (error: Exception) {
                record(error)
                null
            } catch (error: LinkageError) {
                record(error)
                null
            }
            if (final != null) {
                val receiptPersisted = persistedReceiptState(
                    snapshot = snapshot,
                    receiptFile = draining.receiptFile,
                    alreadyPersisted = draining.receiptPersisted,
                    receiptCustodian = draining.receiptCustodian,
                )
                if (receiptPersisted == null) {
                    state = draining
                    cancellation?.let { throw it }
                    return Result.failure(Pcv3BridgeFailure("PCV3_RECEIPT_PERSIST_FAILED"))
                }
                draining = draining.copy(receiptPersisted = receiptPersisted)
                state = draining
                val releaseCode = try {
                    draining.operation.release()
                } catch (error: Exception) {
                    record(error)
                    "PCV3_OPERATION_RELEASE_DENIED"
                } catch (error: LinkageError) {
                    record(error)
                    "PCV3_OPERATION_RELEASE_DENIED"
                }
                if (releaseCode.isEmpty()) {
                    state = State.Final(
                        generation = draining.generation,
                        receiptFile = draining.receiptFile,
                        receiptPersisted = draining.receiptPersisted,
                        creation = draining.creation,
                        artifactInspection = draining.artifactInspection,
                        artifactMetadata = draining.artifactMetadata,
                        receiptCustodian = draining.receiptCustodian,
                    )
                    _presentation.value = final
                    cancellation?.let { throw it }
                    return if (reportFailureAfterDrain) {
                        Result.failure(Pcv3BridgeFailure(failureCode))
                    } else {
                        Result.success(final)
                    }
                }
            }
        }

        return retainPrivateDrain()
    }

    private fun preferTerminalSnapshot(
        current: Pcv3SnapshotData?,
        candidate: Pcv3SnapshotData,
    ): Pcv3SnapshotData = if (current?.isReleaseCandidate() == true && !candidate.isReleaseCandidate()) {
        current
    } else {
        candidate
    }

    private fun publishActiveLocked(active: State.Active): Pcv3Presentation.Live? {
        val snapshot = active.snapshot ?: return null
        return Pcv3Presentation.Live(
            snapshot = projectPcv3Snapshot(snapshot),
            operationId = active.operation.id,
            generation = active.generation,
            operationHandle = active.operation,
            consentHandle = active.consentHandle,
            archiveHandle = active.archiveHandle,
            consent = active.consent,
            outputHandle = active.outputHandle,
            outputPending = active.outputHandle != null,
            outputActionInFlight = active.outputActionInFlight,
            artifactMetadata = active.artifactMetadata?.toView(),
            isCreation = active.creation,
        ).also { _presentation.value = it }
    }

    private fun Pcv3SnapshotData.isReleaseCandidate(): Boolean =
        !archivePending && completionClass != "unknown" && completionClass != "archive-pending"

    private fun Pcv3SnapshotData.allowsOutputCapability(
        consentHandle: Pcv3ConsentCapability?,
        archiveHandle: Pcv3ArchiveCapability?,
        priorAction: Pcv3OutputResultView?,
        creation: Boolean,
    ): Boolean =
        consentHandle == null && archiveHandle == null &&
            (priorAction == null || creation && priorAction.code == "save-failed" && !priorAction.cleanupIncomplete) &&
            !archivePending && (
                restoredReceipt.isEmpty() && !requiresReceipt() &&
                    (completionClass == "clean" || completionClass == "warning") &&
                    publicationAttempted && publicationState == "published-durable" &&
                    publicationStage == "none" && publicationCode == "PCV3_PUBLICATION_PUBLISHED_DURABLE" ||
                    creation && pcv3OutputActionTarget(projectPcv3Snapshot(this), null, isCreation = true) ==
                        Pcv3OutputActionTarget.CREATED_VOLUME
                )

    private fun Pcv3SnapshotData.requiresReceipt(): Boolean =
        completionClass == "durability-uncertain" || completionClass == "publication-indeterminate"

    /**
     * Returns the updated persisted bit, or null when release must remain blocked.
     * A non-restorable terminal must not carry a receipt, and a restorable one must
     * durably commit its exact Go-issued receipt before the native handle is released.
     */
    private fun persistedReceiptState(
        snapshot: Pcv3SnapshotData,
        receiptFile: File,
        alreadyPersisted: Boolean,
        receiptCustodian: Pcv3ReceiptCustodyCapability? = null,
    ): Boolean? {
        if (receiptCustodian != null) {
            return if (snapshot.requiresReceipt()) {
                val receipt = snapshot.restoredReceipt
                true.takeIf { receipt.isNotEmpty() && receiptCustodian.custody == ReceiptCustody.Exact(receipt) }
            } else {
                false.takeIf { snapshot.restoredReceipt.isEmpty() && receiptCustodian.custody === ReceiptCustody.None }
            }
        }
        if (alreadyPersisted) return true
        if (!snapshot.requiresReceipt()) {
            return false.takeIf { snapshot.restoredReceipt.isEmpty() }
        }
        val receipt = snapshot.restoredReceipt
        if (receipt.isEmpty() || !receiptPersistence.save(receiptFile, receipt)) return null
        return true
    }

    private fun actionResult(
        reconciled: Result<Pcv3Presentation>,
        actionFailure: String?,
    ): Result<Unit> = when {
        actionFailure != null -> Result.failure(Pcv3BridgeFailure(actionFailure))
        reconciled.isFailure -> Result.failure(reconciled.exceptionOrNull() ?: Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
        else -> Result.success(Unit)
    }

}

/** Exact host authority over one transferred request's input paths. */
internal class Pcv3InputCustody internal constructor(internal val request: Pcv3StartRequest)

/**
 * Manages encryption/decryption operations and their progress.
 */
object OperationManager {
    private val legacyOperationMutex = Mutex()
    private val pcv3InputCustodyLock = Any()
    private var pcv3InputCustody: Pcv3InputCustody? = null
    private val _pcv3InputCleanupPending = MutableStateFlow(false)
    internal val currentPcv3InputCleanupPending: StateFlow<Boolean> = _pcv3InputCleanupPending.asStateFlow()
    private val _currentOperation = MutableStateFlow<OperationState?>(null)
    val currentOperation: StateFlow<OperationState?> = _currentOperation.asStateFlow()
    private val pcv3Lifecycle = Pcv3Lifecycle(GoBridge.pcv3Bridge)
    val currentPcv3Presentation: StateFlow<Pcv3Presentation?> = pcv3Lifecycle.presentation
    val currentPcv3ArtifactDetails: StateFlow<Pcv3ArtifactDetailsUiState> = pcv3Lifecycle.artifactDetails
    /** Authority-free lifecycle occupancy; true while native ownership may still be live. */
    val currentPcv3Busy: StateFlow<Boolean> = pcv3Lifecycle.busy

    /** Host-owned input paths stay occupied across native Final and ViewModel destruction. */
    internal fun claimPcv3InputCustody(request: Pcv3StartRequest): Pcv3InputCustody? = synchronized(pcv3InputCustodyLock) {
        if (pcv3InputCustody != null || currentPcv3Busy.value || _currentOperation.value != null) return@synchronized null
        Pcv3InputCustody(request).also {
            pcv3InputCustody = it
            _pcv3InputCleanupPending.value = true
        }
    }

    internal fun releasePcv3InputCustody(owner: Pcv3InputCustody) = synchronized(pcv3InputCustodyLock) {
        if (pcv3InputCustody === owner) {
            pcv3InputCustody = null
            _pcv3InputCleanupPending.value = false
        }
    }

    private fun ownsPcv3Inputs(owner: Pcv3InputCustody?, request: Pcv3StartRequest): Boolean =
        synchronized(pcv3InputCustodyLock) {
            owner != null && pcv3InputCustody === owner && owner.request === request
        }

    private fun FormData.passwordBytesForGo(): ByteArray =
        if (hasPassword) passwordInput.toUtf8BytesSecure() else ByteArray(0)

    private fun progressError(progressState: ProgressState, type: OperationType): AppError? =
        if (progressState.done && progressState.status.code == OperationStatus.ERROR) {
            AppError.fromGoError(
                progressState.technicalError,
                type,
                progressState.errorCode,
            )
        } else {
            null
        }

    /**
     * Starts an explicit PCV3 operation without joining the legacy operation state.
     * Resource admission is performed from a fresh operation-scoped observation.
     * Read and creation envelopes share this exact lifecycle; the request subtype
     * decides which strict JSON shape crosses the bridge.
     */
    internal suspend fun startPcv3(
        request: Pcv3StartRequest,
        password: CharArray,
        receiptFile: File,
        inputCustody: Pcv3InputCustody? = null,
    ): Result<Pcv3Presentation> = try {
        if (!ownsPcv3Inputs(inputCustody, request) || !StartupCleanup.allowsPcv3Dispatch()) {
            Result.failure(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
        } else {
            withContext(Dispatchers.IO) { pcv3Lifecycle.start(request, password, receiptFile) }
        }
    } finally {
        password.fill('\u0000')
    }

    /** Explicit polling is the only path that reconciles Go scalar state and capabilities. */
    suspend fun refreshPcv3(): Result<Pcv3Presentation> =
        withContext(Dispatchers.IO) { pcv3Lifecycle.refreshPcv3() }

    /** Binds the process-local Android observer to only the active native generation. */
    internal suspend fun installPcv3ResourceObservationReader(reader: Pcv3ResourceObservationReader): Boolean =
        withContext(Dispatchers.IO) { pcv3Lifecycle.installResourceObservationReader(reader) }

    /** Dismisses only the exact released terminal generation currently presented. */
    suspend fun dismissPcv3(expectedOperationId: String, expectedGeneration: Long): Boolean =
        withContext(Dispatchers.IO) { pcv3Lifecycle.dismissPcv3(expectedOperationId, expectedGeneration) }

    /** Cancellation is only a request; the later Go snapshot supplies terminal meaning. */
    suspend fun cancelPcv3(): Result<Unit> = withContext(Dispatchers.IO) { pcv3Lifecycle.cancelPcv3() }

    /** Atomically consumes the current archive capability before delegating to Go. */
    suspend fun closePcv3Archive(): Result<Unit> =
        withContext(Dispatchers.IO) { pcv3Lifecycle.closePcv3Archive() }

    /** Publishes only the exact claimed archive generation into the selected SAF tree. */
    suspend fun exportPcv3Archive(
        context: Context,
        expectedOperationId: String,
        expectedGeneration: Long,
        root: Uri,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        pcv3Lifecycle.exportPcv3Archive(
            expectedOperationId = expectedOperationId,
            expectedGeneration = expectedGeneration,
            root = root,
            publisher = Pcv3SafArchiveProvider(AndroidPcv3SafPlatform(context.contentResolver)),
        )
    }

    /** Transfers an attached SAF descriptor only for the exact live output ticket. */
    suspend fun savePcv3Output(
        expectedOperationId: String,
        expectedGeneration: Long,
        destination: ParcelFileDescriptor,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        pcv3Lifecycle.savePcv3Output(expectedOperationId, expectedGeneration, destination)
    }

    /** Consumes only the exact live retained-output capability. */
    suspend fun discardPcv3Output(
        expectedOperationId: String,
        expectedGeneration: Long,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        pcv3Lifecycle.discardPcv3Output(expectedOperationId, expectedGeneration)
    }

    /** Loads only an exact generation-bound passive artifact page. */
    suspend fun loadPcv3ArtifactPage(
        expectedOperationId: String,
        expectedGeneration: Long,
        offsetDecimal: String,
        limit: Int,
    ): Result<Pcv3ArtifactPageView> = withContext(Dispatchers.IO) {
        pcv3Lifecycle.loadPcv3ArtifactPage(
            expectedOperationId,
            expectedGeneration,
            offsetDecimal,
            limit,
        )
    }

    /** Selects an exact Go-granted role but does not invoke consent yet. */
    suspend fun selectPcv3ConsentRole(role: String): Result<Unit> =
        withContext(Dispatchers.IO) { pcv3Lifecycle.selectPcv3ConsentRole(role) }

    /** Invokes only Choose(exact selected role); a consumed handle is never reused. */
    suspend fun confirmPcv3Consent(): Result<Unit> =
        withContext(Dispatchers.IO) { pcv3Lifecycle.confirmPcv3Consent() }

    /** Invokes only Refuse; no local fallback decision is made. */
    suspend fun refusePcv3Consent(): Result<Unit> =
        withContext(Dispatchers.IO) { pcv3Lifecycle.refusePcv3Consent() }

    /** Restores only an authority-free receipt projection, never a live operation. */
    suspend fun restorePcv3Receipt(
        receipt: String,
        receiptFile: File,
    ): Result<Pcv3Presentation> = withContext(Dispatchers.IO) {
        pcv3Lifecycle.restorePcv3Receipt(receipt, receiptFile)
    }
    
    /**
     * Starts a decryption operation.
     */
    suspend fun startDecrypt(
        context: Context,
        formData: FormData
    ): Result<String> = legacyOperationMutex.withLock {
        startDecryptLocked(context, formData)
    }

    private suspend fun startDecryptLocked(
        context: Context,
        formData: FormData,
    ): Result<String> = withContext(Dispatchers.IO) {
        if (formData.copiedFilePath.isEmpty()) {
            return@withContext Result.failure(AppError.ValidationError.NoFileSelected)
        }

        // A desktop split volume (secret.pcv.0) cannot be decrypted on Android without
        // recombining its sibling chunks, which the single-file picker cannot supply.
        // Fail loud instead of running the Go op on one chunk (a confusing corrupt error).
        if (formData.isSplitVolumeChunk) {
            return@withContext Result.failure(AppError.ValidationError.SplitVolumeNotSupported)
        }

        if (!formData.isPasswordValid) {
            return@withContext Result.failure(AppError.ValidationError.InvalidPassword)
        }

        // Clean up old files before starting new operation to prevent contamination
        if (!FileCopyService.cleanupOperationFilesBeforeStart(context)) {
            return@withContext Result.failure(AppError.FileError.DeleteFailed())
        }

        // Generate output file path using FileCopyService
        val outputFilePath = FileCopyService.getOutputFilePath(context, formData.copiedFilePath, isEncrypt = false)

        // Start operation
        val operationID = GoBridge.startOperation().getOrElse { return@withContext Result.failure(it) }

        val options = DecryptOptions(
            keyfiles = formData.keyfileFilenames.map { it.internalPath },
            forceDecrypt = false,
            verifyFirst = formData.verifyFirst,
            // INTEROP: Go auto-unzip extracts to a subdirectory and DELETES the zip
            // (decrypt.go:816,847). Android exports a single fixed output path, so an
            // unzipped output orphans the export -> SaveFailed. Keep OFF until a SAF
            // tree-export exists; the intact .zip stays exportable. Matches the CLI
            // --auto-unzip default (decrypt.go:94).
            autoUnzip = false,
            sameLevel = false,
            recombine = false, // Split volumes are not supported in the Android app
            deniability = formData.decryptionInfo?.deniability ?: false
        )
        
        // Encode the password to UTF-8 bytes without a String; GoBridge zeroes them.
        val result = GoBridge.startDecrypt(
            operationID,
            formData.copiedFilePath,
            outputFilePath,
            formData.passwordBytesForGo(),
            options
        )
        
        result.onSuccess {
            _currentOperation.value = OperationState(
                id = operationID,
                type = OperationType.DECRYPT,
                inputFile = formData.copiedFilePath,
                outputFile = outputFilePath,
                status = OperationStatusData(OperationStatus.STARTING),
                detail = OperationProgressDetail(OperationProgress.NONE),
                progress = 0f,
                formData = formData
            )
        }
        
        result.map { operationID }
    }
    
    /**
     * Surfaces a start failure as a terminal error OperationState so the UI can show it
     * (e.g. via OperationUiState.Failed) instead of silently swallowing the Result.failure.
     * Only writes if _currentOperation is null (i.e. the start truly failed before
     * establishing a state); does not clobber an already-running operation.
     */
    fun surfaceStartFailure(type: OperationType, error: Throwable) {
        val appError = if (error is AppError) error
                       else AppError.OperationError.GenericOperation(
                           error.message ?: "Operation failed to start",
                           error.message,
                           R.string.error_operation_start_failed,
                       )
        _currentOperation.update { current ->
            if (current != null) current  // Don't clobber an already-running op.
            else OperationState(
                id = "",
                type = type,
                inputFile = "",
                outputFile = "",
                status = OperationStatusData(OperationStatus.ERROR),
                detail = OperationProgressDetail(OperationProgress.NONE),
                progress = 0f,
                done = true,
                error = appError
            )
        }
    }

    /**
     * Polls progress for the current operation.
     */
    suspend fun pollProgress(): OperationState? = withContext(Dispatchers.IO) {
        val operation = _currentOperation.value ?: return@withContext null
        // Once terminal, do not let a slow/concurrent poll (UI 500ms + FGS 1000ms run
        // simultaneously) overwrite the freshly-final state with stale progress.
        if (operation.done) return@withContext operation

        val result = GoBridge.getProgress(operation.id)
        result.getOrNull()?.let { progressState ->
            // Classify by the stable Go error code (not fragile substring matching).
            val error = progressError(progressState, operation.type)
            
            // Atomic read-modify-write: between capturing `operation` above and the
            // suspending getProgress I/O, a concurrent coroutine (the FGS 1000ms poll
            // vs. the UI 500ms poll, or a clear/replace) may have changed the flow. An
            // unconditional write would resurrect a cleared op as a phantom non-done
            // state or clobber a newer op. Update conditionally on the latest value.
            _currentOperation.update { current ->
                if (current == null || current.id != operation.id || current.done) {
                    // cleared, replaced, or already finished concurrently -- do not
                    // resurrect/clobber.
                    current
                } else {
                    // Copy onto `current` (not the captured `operation`): same id,
                    // latest base.
                    current.copy(
                        status = progressState.status,
                        detail = progressState.detail,
                        progress = progressState.progress,
                        done = progressState.done,
                        error = error
                    )
                }
            }
        }
        
        _currentOperation.value
    }
    
    /**
     * Cancels the current operation.
     */
    suspend fun cancelOperation(): Result<Unit> = withContext(Dispatchers.IO) {
        val operation = _currentOperation.value ?: return@withContext Result.failure(
            AppError.OperationError.GenericOperation(
                userMessage = "",
                messageResId = R.string.error_no_active_operation,
            )
        )
        
        val result = GoBridge.cancelOperation(operation.id)
        result.onSuccess { progressState ->
            val error = progressError(progressState, operation.type)
            _currentOperation.update { current ->
                if (current == null || current.id != operation.id || current.done) {
                    current
                } else {
                    current.copy(
                        status = progressState.status,
                        detail = progressState.detail,
                        progress = progressState.progress,
                        done = progressState.done,
                        error = error,
                    )
                }
            }
        }
        result.map { Unit }
    }
    
    /**
     * Clears the current operation.
     * @param shouldCleanupFiles If true, deletes input, output, and keyfiles from internal storage.
     */
    suspend fun clearOperation(
        context: Context? = null,
        shouldCleanupFiles: Boolean = true,
        expectedOperation: OperationState? = _currentOperation.value,
    ): Result<Unit> = legacyOperationMutex.withLock {
        clearOperationLocked(context, shouldCleanupFiles, expectedOperation)
    }

    private suspend fun clearOperationLocked(
        context: Context?,
        shouldCleanupFiles: Boolean,
        expectedOperation: OperationState?,
    ): Result<Unit> {
        // A delayed or duplicate clear owns only the operation captured by its caller.
        // Keep replacement starts and other dismissals out until all deletion ends.
        val operation = _currentOperation.value?.takeIf { it.hasSameOwnerAs(expectedOperation) }
            ?: return Result.success(Unit)
        
        // Clear passwords from form data before clearing operation
        operation.formData?.clearPasswords()

        if (!shouldCleanupFiles) {
            _currentOperation.compareAndSet(operation, null)
            return Result.success(Unit)
        }

        if (context == null) {
            val error = AppError.FileError.DeleteFailed(
                technicalMessage = "Android context is required to clean operation files",
            )
            retainCleanupFailure(operation, error)
            return Result.failure(error)
        }

        val formData = operation.formData
        val keyfilePaths = formData?.keyfileFilenames?.map { it.internalPath } ?: emptyList()

        val filesCleaned = FileCopyService.cleanupOperationFiles(
                context = context,
                inputFilePath = operation.inputFile,
                outputFilePath = operation.outputFile,
                keyfilePaths = keyfilePaths,
            )

        // A folder/multi selection stages plaintext copies under STAGING_DIR that the
        // per-file cleanup above does not cover (it only knows the single input path).
        // Always attempt this cleanup even if one of the paths above could not be removed.
        val stagingCleaned = withContext(Dispatchers.IO) {
            StagingService.wipeStaging(context)
        }

        if (!filesCleaned || !stagingCleaned) {
            val error = AppError.FileError.DeleteFailed(
                technicalMessage = buildString {
                    append("Operation cleanup incomplete:")
                    if (!filesCleaned) append(" operation files")
                    if (!stagingCleaned) append(" staging")
                },
            )
            retainCleanupFailure(operation, error)
            return Result.failure(error)
        }

        _currentOperation.compareAndSet(operation, null)
        return Result.success(Unit)
    }

    private fun retainCleanupFailure(
        operation: OperationState,
        error: AppError.FileError.DeleteFailed,
    ) {
        _currentOperation.update { current ->
            if (current == null || current.id != operation.id) {
                current
            } else {
                current.copy(
                    status = OperationStatusData(OperationStatus.ERROR),
                    detail = OperationProgressDetail(OperationProgress.NONE),
                    done = true,
                    error = error,
                )
            }
        }
    }
    
    /**
     * Retries decryption with force decrypt enabled.
     * This should only be called when a decryption operation has failed due to data corruption.
     */
    suspend fun retryDecryptWithForce(
        context: Context,
        expectedOperation: OperationState? = _currentOperation.value,
    ): Result<String> = legacyOperationMutex.withLock {
        retryDecryptWithForceLocked(context, expectedOperation)
    }

    private suspend fun retryDecryptWithForceLocked(
        context: Context,
        expectedOperation: OperationState?,
    ): Result<String> = withContext(Dispatchers.IO) {
        val operation = _currentOperation.value?.takeIf { it.hasSameOwnerAs(expectedOperation) }
            ?: return@withContext Result.failure(
                AppError.OperationError.GenericOperation(
                    userMessage = "",
                    messageResId = R.string.error_no_active_operation,
                )
            )
        
        if (operation.type != OperationType.DECRYPT) {
            return@withContext Result.failure(
                AppError.OperationError.GenericOperation(
                    userMessage = "",
                    messageResId = R.string.error_decrypt_retry_only,
                )
            )
        }
        
        val formData = operation.formData ?: return@withContext Result.failure(
            AppError.OperationError.GenericOperation(
                userMessage = "",
                messageResId = R.string.error_operation_data_unavailable,
            )
        )

        // Force-decrypt BYPASSES integrity/RS checks. Mirror startDecrypt's credential
        // guard so a cleared password cannot run unless keyfiles still provide a
        // credential.
        if (!formData.isPasswordValid) {
            return@withContext Result.failure(AppError.ValidationError.InvalidPassword)
        }

        if (!FileCopyService.cleanupOperationFilesBeforeStart(context)) {
            return@withContext Result.failure(AppError.FileError.DeleteFailed())
        }

        // Clear the current operation state
        _currentOperation.value = null

        // Start new operation with force decrypt enabled
        val operationID = GoBridge.startOperation().getOrElse { return@withContext Result.failure(it) }
        
        val options = DecryptOptions(
            keyfiles = formData.keyfileFilenames.map { it.internalPath },
            forceDecrypt = true, // Enable force decrypt
            verifyFirst = formData.verifyFirst,
            autoUnzip = false, // See startDecrypt: off until SAF tree-export exists.
            sameLevel = false,
            recombine = false,
            deniability = formData.decryptionInfo?.deniability ?: false
        )
        
        // Encode the password to UTF-8 bytes without a String; GoBridge zeroes them.
        val result = GoBridge.startDecrypt(
            operationID,
            operation.inputFile,
            operation.outputFile,
            formData.passwordBytesForGo(),
            options
        )
        
        result.onSuccess {
            _currentOperation.value = OperationState(
                id = operationID,
                type = OperationType.DECRYPT,
                inputFile = operation.inputFile,
                outputFile = operation.outputFile,
                status = OperationStatusData(OperationStatus.STARTING),
                detail = OperationProgressDetail(OperationProgress.NONE),
                progress = 0f,
                formData = formData
            )
        }
        
        result.map { operationID }
    }
}

/**
 * State of an encryption/decryption operation.
 */
data class OperationState(
    val id: String,
    val type: OperationType,
    val inputFile: String,
    val outputFile: String,
    val status: OperationStatusData,
    val detail: OperationProgressDetail,
    val progress: Float,
    val done: Boolean = false,
    val error: AppError? = null,
    val formData: FormData? = null
)

/** Native IDs survive progress snapshots; failed starts without an ID own only their exact state. */
internal fun OperationState.hasSameOwnerAs(expected: OperationState?): Boolean =
    this === expected || (id.isNotBlank() && id == expected?.id)

enum class OperationType {
    ENCRYPT,
    DECRYPT
}
