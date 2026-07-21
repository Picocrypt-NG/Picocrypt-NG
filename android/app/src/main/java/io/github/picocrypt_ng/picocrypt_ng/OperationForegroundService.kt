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
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Foreground service (type dataSync) that hosts an active encrypt/decrypt operation so it
 * survives the app being backgrounded.
 *
 * The service owns its own stop lifecycle: it observes [OperationManager.currentOperation] and,
 * when that becomes null OR the operation is done, demotes itself and stops. Callers only need to
 * START it (from a user-initiated tap while the app is foreground) when an operation begins.
 */
class OperationForegroundService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel()

        // Register exactly once for the service's lifetime (onCreate runs once;
        // onStartCommand runs on every start() and would otherwise stack collectors).
        OperationManager.currentOperation
            .onEach { state ->
                if (state == null || state.done) {
                    stopSelfAndForeground()
                } else {
                    notificationManager().notify(
                        NOTIFICATION_ID,
                        buildNotification(state.type, state.status, state.detail, state.progress)
                    )
                }
            }
            .launchIn(scope)

        // Self-driving poll loop: advances OperationManager state even when no UI
        // ViewModel is alive (e.g. the app was swiped from recents mid-operation),
        // so the collector above eventually observes `done` and self-stops.
        scope.launch {
            while (isActive) {
                OperationManager.pollProgress()
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val op = OperationManager.currentOperation.value
        startForegroundCompat(
            buildNotification(
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
    @OptIn(DelicateCoroutinesApi::class)
    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    override fun onTimeout(startId: Int, fgsType: Int) {
        // Cancel on a process-lifetime scope: stopSelf() below cancels `scope`, so a cancel
        // launched on `scope` could be cancelled before it signals the native Go operation.
        GlobalScope.launch { OperationManager.cancelOperation() }
        stopSelfAndForeground()
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
                    CHANNEL_ID,
                    getString(R.string.fgs_channel_name),
                    NotificationManager.IMPORTANCE_LOW
                ).apply { setShowBadge(false) }
            )
        }
    }

    private fun buildNotification(
        type: OperationType?,
        status: OperationStatusData,
        detail: OperationProgressDetail,
        progress: Float
    ): Notification {
        val displayText = renderOperationStatus(this, status, detail, progress)
        val title = when (type) {
            OperationType.ENCRYPT -> getString(R.string.fgs_encrypting)
            OperationType.DECRYPT -> getString(R.string.fgs_decrypting)
            null -> getString(R.string.fgs_working)
        }
        val pi = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(title)
            .setContentText(displayText.status)
            .setProgress(100, (progress * 100).toInt(), false)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setContentIntent(pi)
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "operation_progress"
        private const val NOTIFICATION_ID = 1
        private const val POLL_INTERVAL_MS = 1000L

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
