package io.github.picocrypt_ng.picocrypt_ng

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val OPERATION_NOTIFICATION_CHANNEL_ID = "operation_progress"

internal fun shouldStopOperationForegroundHost(
    operation: OperationState?,
    pcv3Busy: Boolean,
): Boolean = (operation == null || operation.done) && !pcv3Busy

/** One immediate service-owned cadence step; neither UI polling nor resource data is involved. */
internal suspend fun pollOperationForegroundOwners(
    operation: OperationState?,
    pcv3Busy: Boolean,
    pollLegacy: suspend () -> Unit,
    refreshPcv3: suspend () -> Unit,
) {
    if (pcv3Busy) refreshPcv3()
    if (operation != null && !operation.done) pollLegacy()
}

/** Timeout requests cancellation from every owner that can still hold native work. */
internal suspend fun cancelOperationForegroundOwners(
    operation: OperationState?,
    pcv3Busy: Boolean,
    cancelLegacy: suspend () -> Unit,
    cancelPcv3: suspend () -> Unit,
) {
    var firstCancellation: CancellationException? = null
    var firstFailure: Throwable? = null

    withContext(NonCancellable) {
        suspend fun attempt(cancel: suspend () -> Unit) {
            try {
                cancel()
            } catch (error: CancellationException) {
                if (firstCancellation == null) firstCancellation = error
            } catch (error: Exception) {
                if (firstFailure == null) firstFailure = error
            } catch (error: LinkageError) {
                if (firstFailure == null) firstFailure = error
            }
        }

        if (operation != null && !operation.done) {
            attempt(cancelLegacy)
        }
        if (pcv3Busy) {
            attempt(cancelPcv3)
        }
    }

    // Throw outside withContext so coroutine stack-trace recovery cannot replace the exact cause.
    firstCancellation?.let { throw it }
    firstFailure?.let { throw it }
}

/** Timeout orchestration, kept separate from Android callbacks for cancellation tests. */
internal fun stopTimedOutOperationForegroundHost(
    cleanupScope: CoroutineScope,
    operation: OperationState?,
    pcv3Busy: Boolean,
    stopHost: () -> Unit,
    cancelLegacy: suspend () -> Unit,
    cancelPcv3: suspend () -> Unit,
) {
    // Android's grace period cannot wait for native or provider calls. The process
    // owner keeps exact receipt/cleanup custody after the Service is destroyed.
    stopHost()
    cleanupScope.launch {
        try {
            cancelOperationForegroundOwners(operation, pcv3Busy, cancelLegacy, cancelPcv3)
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            // Native ownership and its failure presentation remain in OperationManager.
        } catch (_: LinkageError) {
            // A stale bridge must not prevent prompt service shutdown.
        }
    }
}

internal fun buildOperationNotification(
    context: Context,
    type: OperationType?,
    status: OperationStatusData,
    detail: OperationProgressDetail,
    progress: Float,
): Notification {
    val displayText = renderOperationStatus(context, status, detail, progress)
    val title = when (type) {
        OperationType.ENCRYPT -> context.getString(R.string.fgs_encrypting)
        OperationType.DECRYPT -> context.getString(R.string.fgs_decrypting)
        null -> context.getString(R.string.fgs_working)
    }
    val pendingIntent = PendingIntent.getActivity(
        context,
        0,
        Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        },
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
    return NotificationCompat.Builder(context, OPERATION_NOTIFICATION_CHANNEL_ID)
        .setSmallIcon(android.R.drawable.ic_dialog_info)
        .setContentTitle(title)
        .setContentText(displayText.status)
        .setProgress(100, (progress * 100).toInt(), false)
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .setOngoing(true)
        .setContentIntent(pendingIntent)
        .build()
}

/**
 * Foreground service (type dataSync) that hosts active legacy or PCV3 native ownership so it
 * survives UI pause and ViewModel teardown.
 *
 * Normal completion stops after both owners are inactive. A system timeout stops the service
 * promptly and leaves cancellation with a process-scoped owner. PCV3 resource observations
 * remain private to the lifecycle refresh and never enter notifications.
 */
class OperationForegroundService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel()

        // Register exactly once for the service's lifetime (onCreate runs once;
        // onStartCommand runs on every start() and would otherwise stack collectors).
        combine(
            OperationManager.currentOperation,
            OperationManager.currentPcv3Busy,
        ) { state, pcv3Busy -> state to pcv3Busy }
            .onEach { (state, pcv3Busy) ->
                if (shouldStopOperationForegroundHost(state, pcv3Busy)) {
                    stopSelfAndForeground()
                } else {
                    val activeLegacy = state?.takeUnless { it.done }
                    notificationManager().notify(
                        NOTIFICATION_ID,
                        buildOperationNotification(
                            this,
                            activeLegacy?.type,
                            activeLegacy?.status ?: OperationStatusData(OperationStatus.WORKING),
                            activeLegacy?.detail ?: OperationProgressDetail(OperationProgress.NONE),
                            activeLegacy?.progress ?: 0f,
                        )
                    )
                }
            }
            .launchIn(scope)

        // Immediate first step is required because a Go KDF challenge is time-bounded.
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            while (isActive) {
                val operation = OperationManager.currentOperation.value
                val pcv3Busy = OperationManager.currentPcv3Busy.value
                if (shouldStopOperationForegroundHost(operation, pcv3Busy)) {
                    stopSelfAndForeground()
                    break
                }
                pollOperationForegroundOwners(
                    operation = operation,
                    pcv3Busy = pcv3Busy,
                    pollLegacy = { OperationManager.pollProgress() },
                    refreshPcv3 = { OperationManager.refreshPcv3() },
                )
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val op = OperationManager.currentOperation.value?.takeUnless { it.done }
        startForegroundCompat(
            buildOperationNotification(
                this,
                op?.type,
                op?.status ?: OperationStatusData(OperationStatus.WORKING),
                op?.detail ?: OperationProgressDetail(OperationProgress.NONE),
                op?.progress ?: 0f
            )
        )
        return START_NOT_STICKY
    }

    /**
     * Called by the system when a dataSync foreground service exceeds its time limit
     * (6h / 24h on Android 15+). Cancel the operation and stop promptly to avoid a crash.
     */
    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    override fun onTimeout(startId: Int, fgsType: Int) {
        stopTimedOutOperationForegroundHost(
            cleanupScope = timeoutCleanupScope,
            operation = OperationManager.currentOperation.value,
            pcv3Busy = OperationManager.currentPcv3Busy.value,
            stopHost = ::stopSelfAndForeground,
            cancelLegacy = { OperationManager.cancelOperation() },
            cancelPcv3 = { OperationManager.cancelPcv3() },
        )
    }

    private fun stopSelfAndForeground() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun startForegroundCompat(n: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
    }

    private fun notificationManager() =
        getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            notificationManager().createNotificationChannel(
                NotificationChannel(
                    OPERATION_NOTIFICATION_CHANNEL_ID,
                    getString(R.string.fgs_channel_name),
                    NotificationManager.IMPORTANCE_LOW
                ).apply { setShowBadge(false) }
            )
        }
    }

    companion object {
        // Independent of onDestroy; it holds no Service or Activity reference.
        private val timeoutCleanupScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private const val NOTIFICATION_ID = 1
        private const val POLL_INTERVAL_MS = 500L

        /**
         * Starts the service in the foreground. Must be called while the app is in the
         * foreground (e.g. from a user-initiated tap) — apps targeting Android 12+ cannot
         * start a foreground service from the background.
         */
        fun start(context: Context) =
            ContextCompat.startForegroundService(
                context,
                Intent(context, OperationForegroundService::class.java)
            )
    }
}
