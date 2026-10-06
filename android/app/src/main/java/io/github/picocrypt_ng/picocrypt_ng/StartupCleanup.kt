package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import java.io.File
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal enum class Pcv3JournalCleanupState {
    ABSENT,
    CLEANED,
    INCOMPLETE,
}

internal object StartupCleanup {
    private sealed interface Evaluation {
        data object Blocked : Evaluation
        data class Restored(val presentation: Pcv3Presentation.Restored) : Evaluation
        data object Cleanable : Evaluation
    }

    private val lock = Mutex()
    private var evaluationInThisProcess: Evaluation? = null
    private var retainedCleanupDoneInThisProcess = false
    private var deferredCleanup: (suspend () -> Boolean)? = null
    @Volatile
    private var startupDoneInThisProcess = false
    @Volatile
    private var dispatchAllowedInThisProcess = false

    /** True only after the None-custody startup matrix completed every cleanup. */
    internal fun allowsPcv3Dispatch(): Boolean = dispatchAllowedInThisProcess

    suspend fun runBeforeUi(
        context: Context,
        restoreReceipt: suspend (Context) -> Pcv3ReceiptRestore = { applicationContext ->
            Pcv3ReceiptStore.restore(Pcv3ReceiptStore.receiptFile(applicationContext)) { receipt ->
                OperationManager.restorePcv3Receipt(
                    receipt,
                    Pcv3ReceiptStore.receiptFile(applicationContext),
                )
            }
        },
        ensurePrivateParent: suspend (Context) -> File? = FileCopyService::ensurePcv3PrivateParent,
        cleanupJournal: suspend (String) -> Pcv3JournalCleanupState = GoBridge::cleanupPcv3Journal,
        cleanupRetainedOutput: suspend (Context) -> Boolean =
            FileCopyService::cleanupPcv3RetainedOutputAtStartup,
        cleanupTransient: suspend (Context) -> Boolean = FileCopyService::cleanupStartupTransientFiles,
    ): Boolean = lock.withLock {
        if (startupDoneInThisProcess) return@withLock true

        val evaluation = evaluationInThisProcess ?: try {
            evaluate(
                context = context,
                restoreReceipt = restoreReceipt,
                ensurePrivateParent = ensurePrivateParent,
                cleanupJournal = cleanupJournal,
            ).also { evaluationInThisProcess = it }
        } catch (error: CancellationException) {
            evaluationInThisProcess = Evaluation.Blocked
            throw error
        }

        when (evaluation) {
            Evaluation.Blocked -> false
            is Evaluation.Restored -> {
                // The restore callback already installed the authority-free Final UI.
                // Preserve every private object until its explicit dismissal owner runs.
                val applicationContext = context.applicationContext
                deferredCleanup = {
                    cleanupPrivateFiles(applicationContext, cleanupRetainedOutput, cleanupTransient)
                }
                dispatchAllowedInThisProcess = false
                startupDoneInThisProcess = true
                true
            }
            Evaluation.Cleanable -> {
                if (!cleanupPrivateFiles(context, cleanupRetainedOutput, cleanupTransient)) return@withLock false
                dispatchAllowedInThisProcess = true
                startupDoneInThisProcess = true
                true
            }
        }
    }

    /** Called after exact receipt clearing, without holding the lifecycle mutex. */
    suspend fun completeRestoredDismissal(presentation: Pcv3Presentation.Restored): Boolean = lock.withLock {
        val evaluation = evaluationInThisProcess as? Evaluation.Restored
            ?: return@withLock evaluationInThisProcess != Evaluation.Blocked
        if (evaluation.presentation != presentation) return@withLock false
        val cleanup = deferredCleanup ?: return@withLock false
        if (!cleanup()) return@withLock false
        currentCoroutineContext().ensureActive()
        deferredCleanup = null
        evaluationInThisProcess = Evaluation.Cleanable
        dispatchAllowedInThisProcess = true
        true
    }

    private suspend fun cleanupPrivateFiles(
        context: Context,
        cleanupRetainedOutput: suspend (Context) -> Boolean,
        cleanupTransient: suspend (Context) -> Boolean,
    ): Boolean {
        if (!retainedCleanupDoneInThisProcess) {
            if (!boundedCleanup(context, cleanupRetainedOutput)) return false
            retainedCleanupDoneInThisProcess = true
        }
        return boundedCleanup(context, cleanupTransient)
    }

    private suspend fun evaluate(
        context: Context,
        restoreReceipt: suspend (Context) -> Pcv3ReceiptRestore,
        ensurePrivateParent: suspend (Context) -> File?,
        cleanupJournal: suspend (String) -> Pcv3JournalCleanupState,
    ): Evaluation {
        val restored = try {
            restoreReceipt(context)
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            Pcv3ReceiptRestore.Unknown
        } catch (_: LinkageError) {
            Pcv3ReceiptRestore.Unknown
        }

        val parent = try {
            ensurePrivateParent(context)
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            null
        } catch (_: LinkageError) {
            null
        } ?: return Evaluation.Blocked

        val journal = try {
            cleanupJournal(parent.absolutePath)
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            Pcv3JournalCleanupState.INCOMPLETE
        } catch (_: LinkageError) {
            Pcv3JournalCleanupState.INCOMPLETE
        }
        if (journal == Pcv3JournalCleanupState.INCOMPLETE) return Evaluation.Blocked

        return when (restored) {
            Pcv3ReceiptRestore.None -> Evaluation.Cleanable
            is Pcv3ReceiptRestore.Exact -> if (
                restored.presentation.snapshot.restoredReceipt == restored.custody.receipt
            ) {
                Evaluation.Restored(restored.presentation)
            } else {
                Evaluation.Blocked
            }
            Pcv3ReceiptRestore.Unknown -> Evaluation.Blocked
        }
    }

    private suspend fun boundedCleanup(
        context: Context,
        cleanup: suspend (Context) -> Boolean,
    ): Boolean = try {
        cleanup(context)
    } catch (error: CancellationException) {
        throw error
    } catch (_: Exception) {
        false
    } catch (_: LinkageError) {
        false
    }

    internal fun resetForTests() {
        evaluationInThisProcess = null
        retainedCleanupDoneInThisProcess = false
        deferredCleanup = null
        startupDoneInThisProcess = false
        dispatchAllowedInThisProcess = false
    }
}
