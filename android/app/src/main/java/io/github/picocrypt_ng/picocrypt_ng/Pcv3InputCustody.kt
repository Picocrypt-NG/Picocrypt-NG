package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import kotlin.coroutines.cancellation.CancellationException

internal data class Pcv3InputCleanupFailure(
    val owner: Pcv3InputCustody,
    val error: AppError.FileError.DeleteFailed,
)

/** Process-owned authority over the exact transferred paths, independent of a UI coroutine. */
internal class Pcv3InputCustody internal constructor(internal val request: Pcv3StartRequest) {
    companion object {
        private val scope = CoroutineScope(SupervisorJob())
    }

    private val lock = Any()
    private var identity: Pair<String, Long>? = null
    private val nativeStopped = CompletableDeferred<Unit>()
    private var job: Job? = null
    private var cancelDispatched = false
    private lateinit var operations: Pcv3Operations
    private var cleanupRunning = false
    private var inputsReleased = false
    private lateinit var context: Context
    private lateinit var cleaner: Pcv3TransferredResourceCleaner
    private val write = request as? Pcv3WriteRequest
    private val deferredInputs = write != null && (write.inputFiles.isNotEmpty() || write.compress)
    private val paths = (request.keyfiles + request.source + (write?.inputFiles ?: emptyList()) +
        (write?.onlyFiles ?: emptyList()) + (write?.onlyFolders ?: emptyList())).distinct()
    val started = CompletableDeferred<Result<Pcv3Presentation>>()
    val cleanupAttempt = CompletableDeferred<Boolean>()

    /** Called at native acceptance, before IO dispatch can lose the return value to cancellation. */
    internal fun bind(operationId: String, generation: Long) = synchronized(lock) {
        check(identity == null || identity == operationId to generation)
        identity = operationId to generation
    }

    internal fun observeNativeStop(generation: Long) = synchronized(lock) {
        if (identity?.second == generation) nativeStopped.complete(Unit)
    }

    internal fun start(
        applicationContext: Context,
        password: CharArray,
        receiptFile: File,
        operations: Pcv3Operations,
        resourceCleaner: Pcv3TransferredResourceCleaner,
        foregroundHost: Pcv3ForegroundHost,
    ) {
        context = applicationContext
        cleaner = resourceCleaner
        this.operations = operations
        job = scope.launch(Dispatchers.Main.immediate, start = CoroutineStart.UNDISPATCHED) {
            var cancelled = false
            try {
                val result = operations.start(request, password, receiptFile, this@Pcv3InputCustody)
                result.getOrNull()?.let { bind(it.operationId, it.generation) }
                password.fill('\u0000')
                if (operations.busy.value) {
                    if (operations.presentation.value is Pcv3Presentation.Live) {
                        operations.installResourceObservationReader(Pcv3AndroidResourceObservationReader(context))
                    }
                    try {
                        foregroundHost.start(context)
                    } catch (_: IllegalStateException) {
                        // Background-start refusal does not revoke native ownership.
                    }
                }
                started.complete(result)
            } catch (error: CancellationException) {
                cancelled = true
                started.complete(Result.failure(error))
            } catch (error: Exception) {
                started.complete(Result.failure(error))
            } finally {
                password.fill('\u0000')
                withContext(NonCancellable) {
                    val target = synchronized(lock) { identity }
                    if (cancelled) cancelNative()
                    // Simple/read paths are opened synchronously by Start; unlinking their names
                    // preserves the native-owned descriptors. ZIP preparation still opens paths
                    // asynchronously, so those names must survive until native reader completion.
                    inputsReleased = !deferredInputs || (target == null && !operations.busy.value)
                    while (!inputsReleased) {
                        val terminal = operations.presentation.value
                        inputsReleased = nativeStopped.isCompleted || (target != null && terminal?.operationId == target.first &&
                            terminal.generation == target.second && terminal.snapshot.completionClass !in listOf("", "unknown"))
                        if (inputsReleased) break
                        // UI and service polling can both stop. Observe their updates when available,
                        // and reconcile native state ourselves at the existing polling cadence.
                        withTimeoutOrNull(500) {
                            operations.presentation.first { state ->
                                target != null && state?.operationId == target.first && state.generation == target.second &&
                                    state.snapshot.completionClass !in listOf("", "unknown")
                            }
                        } ?: try {
                            operations.refresh()
                        } catch (_: Exception) {
                            // Unobservable completion retains exact input custody.
                        }
                    }
                    cleanupAttempt.complete(cleanup())
                }
            }
        }
    }

    internal fun cancel() {
        job?.cancel()
        scope.launch(Dispatchers.Main.immediate, start = CoroutineStart.UNDISPATCHED) { cancelNative() }
    }

    private suspend fun cancelNative() {
        val target = synchronized(lock) {
            identity?.takeIf { !cancelDispatched }?.also { cancelDispatched = true }
        } ?: return
        try {
            operations.cancel(target.first, target.second)
        } catch (_: Exception) {
            // Cancellation requests never prove reader completion.
        }
    }

    private suspend fun cleanup(): Boolean {
        if (!synchronized(lock) {
                if (!inputsReleased || cleanupRunning) false else { cleanupRunning = true; true }
            }) return false
        val complete = try {
            cleaner.delete(context, paths)
        } catch (_: Exception) {
            false
        } catch (_: LinkageError) {
            false
        }
        synchronized(lock) {
            cleanupRunning = false
            if (complete) inputsReleased = false
        }
        OperationManager.finishPcv3InputCleanup(this, complete)
        return complete
    }

    /** One explicit retry after failure, only after native no longer needs these pathnames. */
    internal fun retryCleanup() {
        scope.launch(Dispatchers.Main.immediate, start = CoroutineStart.UNDISPATCHED) { cleanup() }
    }
}
