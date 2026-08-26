package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import java.io.File
import kotlin.coroutines.cancellation.CancellationException
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
        data object Restored : Evaluation
        data object Cleanable : Evaluation
    }

    private val lock = Mutex()
    private var evaluationInThisProcess: Evaluation? = null
    private var retainedCleanupDoneInThisProcess = false
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
            Evaluation.Restored -> {
                // The restore callback already installed the authority-free Final UI.
                // Preserve every private object until its explicit dismissal owner runs.
                dispatchAllowedInThisProcess = false
                startupDoneInThisProcess = true
                true
            }
            Evaluation.Cleanable -> {
                if (!retainedCleanupDoneInThisProcess) {
                    if (!boundedCleanup(context, cleanupRetainedOutput)) return@withLock false
                    retainedCleanupDoneInThisProcess = true
                }
                if (!boundedCleanup(context, cleanupTransient)) return@withLock false
                dispatchAllowedInThisProcess = true
                startupDoneInThisProcess = true
                true
            }
        }
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
                Evaluation.Restored
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
        startupDoneInThisProcess = false
        dispatchAllowedInThisProcess = false
    }
}
