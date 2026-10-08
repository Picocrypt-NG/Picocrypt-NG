package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.coroutines.cancellation.CancellationException

/** Narrow seam around the one native PCV3 lifecycle owner. */
internal interface Pcv3Operations {
    val presentation: StateFlow<Pcv3Presentation?>
    val busy: StateFlow<Boolean>
    suspend fun start(
        request: Pcv3StartRequest,
        password: CharArray,
        receiptFile: File,
        inputCustody: Pcv3InputCustody,
    ): Result<Pcv3Presentation>
    suspend fun refresh(): Result<Pcv3Presentation>
    suspend fun installResourceObservationReader(reader: Pcv3ResourceObservationReader): Boolean
    suspend fun dismiss(operationId: String, generation: Long): Boolean
    suspend fun cancel(operationId: String, generation: Long): Result<Unit>
    suspend fun selectConsentRole(operationId: String, generation: Long, role: String): Result<Unit>
    suspend fun confirmConsent(operationId: String, generation: Long): Result<Unit>
    suspend fun refuseConsent(operationId: String, generation: Long): Result<Unit>
    suspend fun closeArchive(operationId: String, generation: Long): Result<Unit>
    suspend fun exportArchive(
        context: Context,
        operationId: String,
        generation: Long,
        root: Uri,
    ): Result<Unit>
    /** Invocation transfers descriptor custody even when the native action later fails. */
    suspend fun saveOutput(
        operationId: String,
        generation: Long,
        destination: ParcelFileDescriptor,
    ): Result<Unit>
    suspend fun discardOutput(operationId: String, generation: Long): Result<Unit>
    suspend fun loadArtifactPage(
        operationId: String,
        generation: Long,
        offsetDecimal: String,
        limit: Int,
    ): Result<Pcv3ArtifactPageView>
}

internal fun interface Pcv3TransferredResourceCleaner {
    suspend fun delete(context: Context, paths: List<String>): Boolean
}

private object FilePcv3TransferredResourceCleaner : Pcv3TransferredResourceCleaner {
    override suspend fun delete(context: Context, paths: List<String>): Boolean {
        var complete = true
        paths.forEach { path ->
            if (!FileCopyService.deleteFile(context, path)) complete = false
        }
        return complete
    }
}

private object ManagerPcv3Operations : Pcv3Operations {
    override val presentation = OperationManager.currentPcv3Presentation
    override val busy = OperationManager.currentPcv3Busy
    override suspend fun start(
        request: Pcv3StartRequest,
        password: CharArray,
        receiptFile: File,
        inputCustody: Pcv3InputCustody,
    ) = OperationManager.startPcv3(request, password, receiptFile, inputCustody)
    override suspend fun refresh() = OperationManager.refreshPcv3()
    override suspend fun installResourceObservationReader(reader: Pcv3ResourceObservationReader) =
        OperationManager.installPcv3ResourceObservationReader(reader)
    override suspend fun dismiss(operationId: String, generation: Long) =
        OperationManager.dismissPcv3(operationId, generation)
    override suspend fun cancel(operationId: String, generation: Long) = OperationManager.cancelPcv3(operationId, generation)
    override suspend fun selectConsentRole(operationId: String, generation: Long, role: String) = OperationManager.selectPcv3ConsentRole(operationId, generation, role)
    override suspend fun confirmConsent(operationId: String, generation: Long) = OperationManager.confirmPcv3Consent(operationId, generation)
    override suspend fun refuseConsent(operationId: String, generation: Long) = OperationManager.refusePcv3Consent(operationId, generation)
    override suspend fun closeArchive(operationId: String, generation: Long) = OperationManager.closePcv3Archive(operationId, generation)
    override suspend fun exportArchive(
        context: Context,
        operationId: String,
        generation: Long,
        root: Uri,
    ) = OperationManager.exportPcv3Archive(context, operationId, generation, root)
    override suspend fun saveOutput(
        operationId: String,
        generation: Long,
        destination: ParcelFileDescriptor,
    ) = OperationManager.savePcv3Output(operationId, generation, destination)
    override suspend fun discardOutput(operationId: String, generation: Long) =
        OperationManager.discardPcv3Output(operationId, generation)
    override suspend fun loadArtifactPage(
        operationId: String,
        generation: Long,
        offsetDecimal: String,
        limit: Int,
    ) = OperationManager.loadPcv3ArtifactPage(operationId, generation, offsetDecimal, limit)
}

internal fun interface Pcv3ForegroundHost {
    fun start(context: Context)
}

private object ServicePcv3ForegroundHost : Pcv3ForegroundHost {
    override fun start(context: Context) = OperationForegroundService.start(context)
}

private object NoopPcv3ForegroundHost : Pcv3ForegroundHost {
    override fun start(context: Context) = Unit
}

/**
 * ViewModel for managing encryption/decryption operations and centralized progress polling.
 */
class OperationViewModel internal constructor(
    private val pcv3Operations: Pcv3Operations,
    private val pcv3ResourceCleaner: Pcv3TransferredResourceCleaner,
    private val pcv3ForegroundHost: Pcv3ForegroundHost,
) : ViewModel() {
    constructor() : this(
        ManagerPcv3Operations,
        FilePcv3TransferredResourceCleaner,
        ServicePcv3ForegroundHost,
    )

    internal constructor(pcv3Operations: Pcv3Operations) : this(
        pcv3Operations,
        FilePcv3TransferredResourceCleaner,
        NoopPcv3ForegroundHost,
    )

    internal constructor(
        pcv3Operations: Pcv3Operations,
        pcv3ResourceCleaner: Pcv3TransferredResourceCleaner,
    ) : this(
        pcv3Operations,
        pcv3ResourceCleaner,
        NoopPcv3ForegroundHost,
    )

    // Expose OperationManager's state as our own
    val operationState: StateFlow<OperationState?> = OperationManager.currentOperation

    // The lifecycle owner remains the sole store of live capabilities. The ViewModel
    // exposes that immutable flow directly and retains only authority-free UI intent.
    val pcv3Presentation: StateFlow<Pcv3Presentation?> = pcv3Operations.presentation

    private val _pcv3Intent = MutableStateFlow<Pcv3OperationIntent?>(null)
    val pcv3Intent: StateFlow<Pcv3OperationIntent?> = _pcv3Intent.asStateFlow()

    private val _pcv3Busy = MutableStateFlow(
        pcv3Operations.busy.value || OperationManager.currentPcv3InputCleanupPending.value ||
            pcv3Operations.presentation.value is Pcv3Presentation.Live,
    )
    val pcv3Busy: StateFlow<Boolean> = _pcv3Busy.asStateFlow()

    private val _pcv3Error = MutableStateFlow<AppError?>(null)
    val pcv3Error: StateFlow<AppError?> = _pcv3Error.asStateFlow()
    private var pcv3CleanupFailure: Pcv3InputCleanupFailure? = null
    private var pendingPcv3CleanupError: AppError.FileError.DeleteFailed? = null

    /** Bounded save failure for the host-copied D1 creation staging file. */

    private val _pcv3ArtifactDetails =
        MutableStateFlow<Pcv3ArtifactDetailsUiState>(Pcv3ArtifactDetailsUiState.Closed)
    val pcv3ArtifactDetails: StateFlow<Pcv3ArtifactDetailsUiState> =
        _pcv3ArtifactDetails.asStateFlow()

    private var pcv3StartPending = false
    private var currentPcv3Ticket: Pcv3Ticket? = pcv3Operations.presentation.value?.toTicket()
    private var pendingPcv3Save: Pcv3SaveTicket? = null
    private var pcv3SaveCompletion: Pcv3SaveTicket? = null
    private var pcv3CreateName: String? = null
    private var pendingPcv3Archive: Pcv3Ticket? = null
    private var pcv3ArchiveCompletion: Pcv3Ticket? = null
    private var pcv3OutputActionTicket: Pcv3Ticket? = null
    private var pcv3ArtifactTicket: Pcv3Ticket? = null
    private var pcv3ArtifactRequestToken = 0L
    
    private var pollingJob: Job? = null
    private var backgroundPollingJob: Job? = null
    private var pcv3PollingJob: Job? = null
    private var isForeground = true

    init {
        viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
            OperationManager.currentPcv3InputCleanupFailure.collect { failure ->
                pcv3CleanupFailure = failure
                if (failure != null) {
                    if (_pcv3Error.value == null) _pcv3Error.value = failure.error
                    else pendingPcv3CleanupError = failure.error
                }
            }
        }
        viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
            OperationManager.currentPcv3InputCleanupPending.collect { publishPcv3Busy() }
        }
        viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
            pcv3Operations.busy.collect { nativeBusy ->
                publishPcv3Busy(nativeBusy)
                if (nativeBusy && !pcv3StartPending && isForeground) {
                    startPcv3Polling()
                } else if (!shouldPollPcv3()) {
                    stopPcv3Polling()
                }
            }
        }
        viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
            pcv3Operations.presentation.collect { presentation ->
                if (presentation != null) {
                    currentPcv3Ticket = presentation.toTicket()
                    if (presentation is Pcv3Presentation.Final || presentation is Pcv3Presentation.Restored) {
                        stopPcv3Polling()
                    }
                } else if (!pcv3StartPending && !pcv3Operations.busy.value) {
                    currentPcv3Ticket = null
                    _pcv3Intent.value = null
                    pcv3CreateName = null
                }
                if (!presentation.supportsArtifactTicket(pcv3ArtifactTicket)) {
                    invalidatePcv3ArtifactDetails()
                }
                publishPcv3Busy()
            }
        }
        if (shouldPollPcv3()) {
            startPcv3Polling()
        }
    }

    /**
     * Consumes the opaque request exactly once. Nothing suspends between source take in
    * MainViewModel and dispatch to the native owner; every pre-dispatch path zeros the password.
     */
    fun startPcv3(context: Context, transfer: Pcv3OperationTransfer) {
        val password = transfer.password
        val request = transfer.request
        val intent = transfer.intent
        val applicationContext = context.applicationContext
        val receiptFile = Pcv3ReceiptStore.receiptFile(applicationContext)
        val inputCustody = OperationManager.claimPcv3InputCustody(request)
        if (inputCustody == null) {
            password.fill('\u0000')
            _pcv3Error.value = AppError.fromException(Pcv3BridgeFailure("PCV3_OPERATION_UNAVAILABLE"))
            publishPcv3Busy()
            return
        }

        pcv3StartPending = true
        _pcv3Busy.value = true
        _pcv3Intent.value = intent
        pcv3CreateName = transfer.createName
        _pcv3Error.value = null
        pendingPcv3CleanupError = null

        inputCustody.start(applicationContext, password, receiptFile, pcv3Operations, pcv3ResourceCleaner, pcv3ForegroundHost)
        viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                val result = inputCustody.started.await()
                acceptPcv3OwnerState(result.getOrNull())
                pcv3StartPending = false
                publishPcv3Busy()
                if (shouldPollPcv3() && isForeground) startPcv3Polling()
                val primaryFailure = result.exceptionOrNull() as? Exception
                if (primaryFailure != null && pcv3Operations.presentation.value == null && !pcv3Operations.busy.value) {
                    _pcv3Error.value = AppError.fromException(primaryFailure)
                }
                inputCustody.cleanupAttempt.await()
            } catch (error: CancellationException) {
                inputCustody.cancel()
                throw error
            } finally {
                pcv3StartPending = false
                publishPcv3Busy()
            }
        }
    }

    fun cancelPcv3(operationId: String, generation: Long) = runPcv3Action(operationId, generation) {
        pcv3Operations.cancel(operationId, generation)
    }

    fun selectPcv3ConsentRole(operationId: String, generation: Long, role: String) =
        runPcv3Action(operationId, generation) { pcv3Operations.selectConsentRole(operationId, generation, role) }

    fun confirmPcv3Consent(operationId: String, generation: Long) = runPcv3Action(operationId, generation) {
        pcv3Operations.confirmConsent(operationId, generation)
    }

    fun refusePcv3Consent(operationId: String, generation: Long) = runPcv3Action(operationId, generation) {
        pcv3Operations.refuseConsent(operationId, generation)
    }

    fun closePcv3Archive(operationId: String, generation: Long) = runPcv3Action(operationId, generation) {
        pcv3Operations.closeArchive(operationId, generation)
    }

    /** Opens one tree picker for the exact live archive generation without retaining its URI. */
    fun beginPcv3Archive(operationId: String, generation: Long): Boolean {
        if (pendingPcv3Archive != null || pcv3ArchiveCompletion != null ||
            pendingPcv3Save != null || pcv3SaveCompletion != null || pcv3OutputActionTicket != null
        ) {
            return false
        }
        val live = currentLivePcv3Archive(operationId, generation) ?: return false
        pendingPcv3Archive = live.toTicket()
        return true
    }

    /** Consumes one picker callback; null and stale callbacks have zero native effects. */
    fun completePcv3Archive(context: Context, root: Uri?) {
        val ticket = pendingPcv3Archive ?: return
        pendingPcv3Archive = null
        if (root == null) return
        pcv3ArchiveCompletion = ticket

        viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                if (!ticket.isCurrentPcv3Archive()) return@launch
                pcv3Operations.exportArchive(
                    context = context,
                    operationId = ticket.operationId,
                    generation = ticket.generation,
                    root = root,
                )
            } finally {
                if (pcv3ArchiveCompletion == ticket) pcv3ArchiveCompletion = null
            }
        }
    }

    /**
     * Creates one in-memory SAF picker ticket for the exact live output generation.
     * No URI or provider metadata is retained in ViewModel state.
     */
    fun beginPcv3Save(operationId: String, generation: Long): String? {
        if (pendingPcv3Save != null || pcv3SaveCompletion != null ||
            pcv3OutputActionTicket != null || pendingPcv3Archive != null ||
            pcv3ArchiveCompletion != null
        ) {
            return null
        }
        val live = currentLivePcv3Output(operationId, generation) ?: return null
        val destination = live.pcv3SaveDestination() ?: return null
        pendingPcv3Save = Pcv3SaveTicket(live.toTicket(), destination)
        return if (destination == Pcv3SaveDestination.CREATED_VOLUME) {
            pcv3CreateName?.takeIf(String::isNotBlank) ?: destination.suggestedName
        } else {
            destination.suggestedName
        }
    }

    /** Consumes the outstanding picker ticket once; a null picker result has no native effect. */
    fun completePcv3Save(context: Context, destinationUri: Uri?) {
        val saveTicket = pendingPcv3Save ?: return
        pendingPcv3Save = null
        if (destinationUri == null) return
        pcv3SaveCompletion = saveTicket

        viewModelScope.launch {
            try {
                if (!saveTicket.isCurrentPcv3Save()) return@launch
                if (saveTicket.destination.requiresRecoverySuffix) {
                    val validation = FileCopyService.validatePcv3RecoveryDestination(context, destinationUri)
                    if (validation.isFailure) {
                        publishPcv3SaveFailure(saveTicket, validation.exceptionOrNull())
                        return@launch
                    }
                    if (!saveTicket.isCurrentPcv3Save()) return@launch
                }

                val descriptorResult = FileCopyService.openPcv3OutputDescriptor(context, destinationUri)
                val descriptor = descriptorResult.getOrElse { error ->
                    publishPcv3SaveFailure(saveTicket, error)
                    return@launch
                }
                if (!claimPcv3OutputAction(
                        saveTicket.ticket,
                        saveTicket.destination.outputTarget,
                    )
                ) {
                    closeUntransferredPcv3Descriptor(descriptor)
                    return@launch
                }

                val actionResult = try {
                    // Once invoked, Pcv3Operations owns the attached descriptor. Never
                    // re-adopt or close its integer after native Save may have detached it.
                    withContext(NonCancellable) {
                        pcv3Operations.saveOutput(
                            saveTicket.ticket.operationId,
                            saveTicket.ticket.generation,
                            descriptor,
                        )
                    }
                } catch (error: CancellationException) {
                    throw error
                } catch (_: Exception) {
                    Result.failure(Pcv3BridgeFailure(PCV3_OUTPUT_SAVE_FAILED))
                } catch (_: LinkageError) {
                    Result.failure(Pcv3BridgeFailure(PCV3_OUTPUT_SAVE_FAILED))
                } finally {
                    finishPcv3OutputAction(saveTicket.ticket)
                }
                if (actionResult.isFailure) {
                    publishPcv3SaveFailure(saveTicket, actionResult.exceptionOrNull())
                }
            } finally {
                if (pcv3SaveCompletion == saveTicket) pcv3SaveCompletion = null
            }
        }
    }

    fun discardPcv3Output(operationId: String, generation: Long) {
        val ticket = Pcv3Ticket(operationId, generation)
        val live = currentLivePcv3Output(operationId, generation) ?: return
        val target = pcv3OutputActionTarget(live.snapshot, live.artifactMetadata, live.isCreation) ?: return
        if (!claimPcv3OutputAction(ticket, target)) return
        if (_pcv3Error.value is AppError.FileError.SaveFailed) clearPcv3Error()
        viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                withContext(NonCancellable) {
                    pcv3Operations.discardOutput(operationId, generation)
                }
            } finally {
                finishPcv3OutputAction(ticket)
            }
        }
    }

    fun inspectPcv3Artifact(operationId: String, generation: Long) {
        loadPcv3ArtifactPage(operationId, generation, "0")
    }

    fun loadPcv3ArtifactPage(
        operationId: String,
        generation: Long,
        offsetDecimal: String,
    ) {
        val ticket = Pcv3Ticket(operationId, generation)
        val metadata = currentPcv3ArtifactMetadata(ticket) ?: return
        val requestToken = ++pcv3ArtifactRequestToken
        pcv3ArtifactTicket = ticket
        _pcv3ArtifactDetails.value = Pcv3ArtifactDetailsUiState.Loading

        viewModelScope.launch {
            val result = try {
                pcv3Operations.loadArtifactPage(
                    operationId,
                    generation,
                    offsetDecimal,
                    PCV3_ARTIFACT_PAGE_LIMIT,
                )
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                Result.failure(Pcv3BridgeFailure(PCV3_ARTIFACT_INSPECTION_UNAVAILABLE))
            } catch (_: LinkageError) {
                Result.failure(Pcv3BridgeFailure(PCV3_ARTIFACT_INSPECTION_UNAVAILABLE))
            }
            if (!isCurrentPcv3ArtifactRequest(ticket, metadata, requestToken)) return@launch
            _pcv3ArtifactDetails.value = result.fold(
                onSuccess = { page -> Pcv3ArtifactDetailsUiState.Ready(metadata, page) },
                onFailure = {
                    Pcv3ArtifactDetailsUiState.Failed(PCV3_ARTIFACT_INSPECTION_UNAVAILABLE)
                },
            )
        }
    }

    fun closePcv3ArtifactInspection(operationId: String, generation: Long) {
        val ticket = Pcv3Ticket(operationId, generation)
        if (pcv3ArtifactTicket != ticket || currentPcv3Ticket != ticket) return
        invalidatePcv3ArtifactDetails()
    }

    fun dismissPcv3(operationId: String, generation: Long) {
        if (!isCurrentTerminalPcv3(operationId, generation)) return
        viewModelScope.launch {
            if (pcv3Operations.dismiss(operationId, generation)) {
                _pcv3Intent.value = null
                pcv3CreateName = null
                currentPcv3Ticket = null
                stopPcv3Polling()
                publishPcv3Busy()
            }
        }
    }

    fun clearPcv3Error() {
        pcv3CleanupFailure?.takeIf { _pcv3Error.value === it.error }
            ?.let(OperationManager::retryPcv3InputCleanup)
        _pcv3Error.value = pendingPcv3CleanupError
        pendingPcv3CleanupError = null
    }

    private fun currentLivePcv3Output(
        operationId: String,
        generation: Long,
    ): Pcv3Presentation.Live? {
        val live = pcv3Operations.presentation.value as? Pcv3Presentation.Live ?: return null
        val ticket = Pcv3Ticket(operationId, generation)
        return live.takeIf {
            it.toTicket() == ticket && currentPcv3Ticket == ticket &&
                it.outputPending && !it.outputActionInFlight && pcv3OutputActionTicket == null
        }
    }

    private fun currentLivePcv3Archive(
        operationId: String,
        generation: Long,
    ): Pcv3Presentation.Live? {
        val live = pcv3Operations.presentation.value as? Pcv3Presentation.Live ?: return null
        val ticket = Pcv3Ticket(operationId, generation)
        return live.takeIf {
            it.toTicket() == ticket && currentPcv3Ticket == ticket &&
                it.snapshot.archivePending && it.archiveHandle != null &&
                it.outputHandle == null && !it.outputPending && !it.outputActionInFlight
        }
    }

    private fun Pcv3Ticket.isCurrentPcv3Archive(): Boolean =
        pendingPcv3Archive == null && pcv3ArchiveCompletion == this &&
            currentLivePcv3Archive(operationId, generation) != null

    private fun Pcv3Presentation.Live.pcv3SaveDestination(): Pcv3SaveDestination? =
        when (pcv3OutputActionTarget(snapshot, artifactMetadata, isCreation)) {
            Pcv3OutputActionTarget.DECRYPTED_OUTPUT -> Pcv3SaveDestination.DECRYPTED_OUTPUT
            Pcv3OutputActionTarget.CREATED_VOLUME -> Pcv3SaveDestination.CREATED_VOLUME
            Pcv3OutputActionTarget.RECOVERY_ARTIFACT -> Pcv3SaveDestination.RECOVERY_ARTIFACT
            null -> null
        }

    private fun Pcv3SaveTicket.isCurrentPcv3Save(): Boolean =
        pendingPcv3Save == null && pcv3SaveCompletion == this &&
            currentLivePcv3Output(ticket.operationId, ticket.generation)
                ?.pcv3SaveDestination() == destination

    private fun claimPcv3OutputAction(
        ticket: Pcv3Ticket,
        expectedTarget: Pcv3OutputActionTarget,
    ): Boolean {
        val live = currentLivePcv3Output(ticket.operationId, ticket.generation) ?: return false
        if (pcv3OutputActionTarget(live.snapshot, live.artifactMetadata, live.isCreation) != expectedTarget) {
            return false
        }
        pcv3OutputActionTicket = ticket
        invalidatePcv3ArtifactDetails()
        return true
    }

    private fun finishPcv3OutputAction(ticket: Pcv3Ticket) {
        if (pcv3OutputActionTicket == ticket) pcv3OutputActionTicket = null
    }

    private suspend fun closeUntransferredPcv3Descriptor(descriptor: ParcelFileDescriptor) {
        withContext(NonCancellable + Dispatchers.IO) {
            try {
                descriptor.close()
            } catch (_: Exception) {
                // Stale authority remains rejected; no provider detail crosses the boundary.
            }
        }
    }

    private fun publishPcv3SaveFailure(saveTicket: Pcv3SaveTicket, failure: Throwable?) {
        if (!saveTicket.isCurrentPcv3Save()) return
        (_pcv3Error.value as? AppError.FileError.DeleteFailed)?.let {
            pendingPcv3CleanupError = it
        }
        _pcv3Error.value = failure as? AppError ?: AppError.FileError.SaveFailed(
            userMessage = "",
            technicalMessage = PCV3_OUTPUT_SAVE_FAILED,
            messageResId = R.string.error_save_failed,
        )
    }

    private fun currentPcv3ArtifactMetadata(ticket: Pcv3Ticket): Pcv3ArtifactMetadataView? {
        val presentation = pcv3Operations.presentation.value
        if (!presentation.supportsArtifactTicket(ticket)) return null
        return presentation?.artifactMetadata
    }

    private fun Pcv3Presentation?.supportsArtifactTicket(ticket: Pcv3Ticket?): Boolean {
        if (ticket == null) return true
        if (this == null || toTicket() != ticket || currentPcv3Ticket != ticket ||
            pcv3OutputActionTicket != null
        ) {
            return false
        }
        if (this is Pcv3Presentation.Live && outputActionInFlight) return false
        if (this !is Pcv3Presentation.Live && this !is Pcv3Presentation.Final) return false
        val metadata = artifactMetadata ?: return false
        return pcv3OutputActionTarget(snapshot, metadata, isCreation) ==
            Pcv3OutputActionTarget.RECOVERY_ARTIFACT
    }

    private fun isCurrentPcv3ArtifactRequest(
        ticket: Pcv3Ticket,
        metadata: Pcv3ArtifactMetadataView,
        requestToken: Long,
    ): Boolean =
        pcv3ArtifactRequestToken == requestToken && pcv3ArtifactTicket == ticket &&
            pcv3Operations.presentation.value.supportsArtifactTicket(ticket) &&
            pcv3Operations.presentation.value?.artifactMetadata == metadata

    private fun invalidatePcv3ArtifactDetails() {
        if (pcv3ArtifactTicket == null &&
            _pcv3ArtifactDetails.value == Pcv3ArtifactDetailsUiState.Closed
        ) {
            return
        }
        pcv3ArtifactRequestToken += 1
        pcv3ArtifactTicket = null
        _pcv3ArtifactDetails.value = Pcv3ArtifactDetailsUiState.Closed
    }

    private fun runPcv3Action(
        operationId: String,
        generation: Long,
        action: suspend () -> Result<Unit>,
    ) {
        if (!isCurrentLivePcv3(operationId, generation)) return
        viewModelScope.launch {
            if (!isCurrentLivePcv3(operationId, generation)) return@launch
            action()
        }
    }

    private fun acceptPcv3OwnerState(returned: Pcv3Presentation?) {
        val authoritative = pcv3Operations.presentation.value
        if (returned != null && authoritative?.toTicket() != returned.toTicket()) return
        if (authoritative != null) {
            val ticket = authoritative.toTicket()
            val current = currentPcv3Ticket
            if (current == null || current == ticket) {
                currentPcv3Ticket = ticket
            } else {
                return
            }
        }
        if (authoritative is Pcv3Presentation.Final || authoritative is Pcv3Presentation.Restored) {
            stopPcv3Polling()
        }
        publishPcv3Busy()
    }

    private fun isCurrentLivePcv3(operationId: String, generation: Long): Boolean =
        (pcv3Operations.presentation.value as? Pcv3Presentation.Live)?.let {
            it.operationId == operationId && it.generation == generation &&
                currentPcv3Ticket == it.toTicket()
        } == true

    private fun isCurrentTerminalPcv3(operationId: String, generation: Long): Boolean =
        pcv3Operations.presentation.value?.let {
            (it is Pcv3Presentation.Final || it is Pcv3Presentation.Restored) &&
                it.operationId == operationId && it.generation == generation &&
                currentPcv3Ticket == it.toTicket()
        } == true

    private fun shouldPollPcv3(): Boolean =
        !pcv3StartPending && (
            pcv3Operations.busy.value || pcv3Operations.presentation.value is Pcv3Presentation.Live
        )

    private fun publishPcv3Busy(nativeBusy: Boolean = pcv3Operations.busy.value) {
        _pcv3Busy.value = pcv3StartPending || OperationManager.currentPcv3InputCleanupPending.value || nativeBusy ||
            pcv3Operations.presentation.value is Pcv3Presentation.Live
    }

    /** One cadence for foreground and background PCV3 reconciliation. */
    private fun startPcv3Polling() {
        if (pcv3PollingJob?.isActive == true) return
        pcv3PollingJob = viewModelScope.launch {
            while (true) {
                delay(PCV3_POLL_INTERVAL_MS)
                if (!shouldPollPcv3()) break
                val returned = pcv3Operations.refresh().getOrNull()
                acceptPcv3OwnerState(returned)
            }
        }
    }

    private fun stopPcv3Polling() {
        pcv3PollingJob?.cancel()
        pcv3PollingJob = null
    }

    /**
     * Starts the foreground service, swallowing a background-start failure. On Android
     * 12+ ForegroundServiceStartNotAllowedException (an IllegalStateException subclass)
     * is thrown if the app left the foreground during the suspending op-start. The Go
     * operation is already running; callers still poll so progress and completion
     * surface — just without the ongoing notification.
     */
    internal fun startForegroundServiceSafely(context: Context) {
        try {
            pcv3ForegroundHost.start(context.applicationContext)
        } catch (e: IllegalStateException) {
            // Background-start not allowed; intentionally ignored (see KDoc).
        }
    }

    /**
     * Starts a decryption operation and begins polling progress.
     */
    fun startDecrypt(context: Context, formData: FormData) {
        viewModelScope.launch {
            val result = OperationManager.startDecrypt(context, formData)
            result.onSuccess {
                startForegroundServiceSafely(context)
                startPolling()
            }
            result.onFailure { e ->
                OperationManager.surfaceStartFailure(OperationType.DECRYPT, e)
            }
        }
    }
    
    /**
     * Cancels the current operation and stops polling.
     */
    fun cancelOperation() {
        viewModelScope.launch {
            stopPolling()
            OperationManager.cancelOperation()
        }
    }
    
    /**
     * Clears the current operation and stops polling.
     * @param context Android context for file cleanup
     * @param shouldCleanupFiles If true, deletes input, output, and keyfiles from internal storage.
     * @return Whether this callback still owns the operation and may clear its form.
     */
    fun clearOperation(
        context: Context? = null,
        shouldCleanupFiles: Boolean = true,
        expectedOperation: OperationState? = operationState.value,
    ): Boolean {
        if (operationState.value?.hasSameOwnerAs(expectedOperation) != true) return false
        viewModelScope.launch {
            if (operationState.value?.hasSameOwnerAs(expectedOperation) != true) return@launch
            stopPolling()
            OperationManager.clearOperation(context, shouldCleanupFiles, expectedOperation)
        }
        return true
    }
    
    /**
     * Retries decryption with force decrypt enabled.
     */
    fun retryDecryptWithForce(context: Context) {
        val expectedOperation = operationState.value ?: return
        viewModelScope.launch {
            if (operationState.value?.hasSameOwnerAs(expectedOperation) != true) return@launch
            stopPolling()
            val result = OperationManager.retryDecryptWithForce(context, expectedOperation)
            result.onSuccess {
                startForegroundServiceSafely(context)
                startPolling()
            }
            result.onFailure { e ->
                OperationManager.surfaceStartFailure(OperationType.DECRYPT, e)
            }
        }
    }
    
    /**
     * Pauses polling when app goes to background.
     * Switches to background polling mode (slower frequency) to keep state updated for notifications.
     */
    fun pausePolling() {
        isForeground = false
        stopPolling() // Stop foreground polling
        startBackgroundPolling() // Start background polling for notifications
        if (shouldPollPcv3()) {
            stopPcv3Polling()
        }
    }
    
    /**
     * Resumes polling when app returns to foreground.
     * Immediately polls once to catch up on state, then resumes interval polling if operation is still active.
     */
    fun resumePolling() {
        isForeground = true
        stopBackgroundPolling() // Stop background polling
        if (shouldPollPcv3()) {
            stopPcv3Polling()
            viewModelScope.launch {
                val returned = pcv3Operations.refresh().getOrNull()
                acceptPcv3OwnerState(returned)
                if (shouldPollPcv3()) startPcv3Polling()
            }
        }
        
        // Immediate poll and wait for it to complete before checking state
        viewModelScope.launch {
            OperationManager.pollProgress()
            
            // Check state after poll completes
            val currentOp = operationState.value
            if (currentOp != null && !currentOp.done) {
                startPolling() // Resume foreground polling
            }
            // If done, don't start polling - UI will show final state via StateFlow
        }
    }
    
    /**
     * Starts polling progress for the current operation.
     * Polls every 500ms until the operation completes or is cancelled.
     * Only polls when app is in foreground.
     */
    private fun startPolling() {
        stopPolling() // Stop any existing polling
        
        if (!isForeground) {
            // Don't start polling if app is in background
            return
        }
        
        pollingJob = viewModelScope.launch {
            while (true) {
                delay(500) // Poll every 500ms
                
                // Check if still in foreground before polling
                if (!isForeground) {
                    break
                }
                
                val operation = OperationManager.currentOperation.value
                if (operation == null || operation.done) {
                    // Operation completed or was cleared, stop polling
                    break
                }
                
                // Poll progress
                OperationManager.pollProgress()
            }
        }
    }
    
    /**
     * Stops the current polling job.
     */
    private fun stopPolling() {
        pollingJob?.cancel()
        pollingJob = null
    }
    
    /**
     * Starts background polling at reduced frequency (2 seconds) to keep state updated for notifications.
     * This runs when the app is in the background.
     */
    private fun startBackgroundPolling() {
        stopBackgroundPolling()
        
        backgroundPollingJob = viewModelScope.launch {
            while (true) {
                delay(2000) // Poll every 2 seconds in background
                
                val operation = OperationManager.currentOperation.value
                if (operation == null || operation.done) {
                    // Operation completed or was cleared, stop polling
                    break
                }
                
                // Poll progress to advance state; the foreground service renders the notification from OperationManager.currentOperation.
                OperationManager.pollProgress()
            }
        }
    }
    
    /**
     * Stops the background polling job.
     */
    private fun stopBackgroundPolling() {
        backgroundPollingJob?.cancel()
        backgroundPollingJob = null
    }
    
    override fun onCleared() {
        super.onCleared()
        stopPolling()
        stopBackgroundPolling()
        stopPcv3Polling()
    }

    private data class Pcv3Ticket(val operationId: String, val generation: Long)

    private data class Pcv3SaveTicket(
        val ticket: Pcv3Ticket,
        val destination: Pcv3SaveDestination,
    )

    private enum class Pcv3SaveDestination(
        val suggestedName: String,
        val requiresRecoverySuffix: Boolean,
        val outputTarget: Pcv3OutputActionTarget,
    ) {
        DECRYPTED_OUTPUT(
            "decrypted-output",
            requiresRecoverySuffix = false,
            outputTarget = Pcv3OutputActionTarget.DECRYPTED_OUTPUT,
        ),
        CREATED_VOLUME(
            "created-volume.pcv",
            requiresRecoverySuffix = false,
            outputTarget = Pcv3OutputActionTarget.CREATED_VOLUME,
        ),
        RECOVERY_ARTIFACT(
            "decrypted-output.pcv3-recovery",
            requiresRecoverySuffix = true,
            outputTarget = Pcv3OutputActionTarget.RECOVERY_ARTIFACT,
        ),
    }

    private fun Pcv3Presentation.toTicket() = Pcv3Ticket(operationId, generation)

    private companion object {
        const val PCV3_POLL_INTERVAL_MS = 500L
        const val PCV3_ARTIFACT_PAGE_LIMIT = 128
        const val PCV3_ARTIFACT_INSPECTION_UNAVAILABLE =
            "PCV3_ARTIFACT_INSPECTION_UNAVAILABLE"
        const val PCV3_OUTPUT_SAVE_FAILED = "PCV3_OUTPUT_SAVE_FAILED"
    }
}
