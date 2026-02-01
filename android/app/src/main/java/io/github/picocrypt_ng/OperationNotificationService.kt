package io.github.picocrypt_ng

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Service for managing operation progress notifications.
 * Shows persistent notifications when operations are running in the background.
 */
object OperationNotificationService {
    private const val CHANNEL_ID = "operation_progress"
    private const val CHANNEL_NAME = "Operation Progress"
    private const val NOTIFICATION_ID = 1
    
    // Track if notification was dismissed by user
    @Volatile
    private var notificationDismissed = false
    
    /**
     * Shows a notification for an active operation.
     * @param context Android context
     * @param operationType Type of operation (ENCRYPT or DECRYPT)
     * @param status Current status message
     */
    fun showNotification(context: Context, operationType: OperationType, status: String) {
        // Check notification permission (Android 13+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    context,
                    android.Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                // Permission not granted, skip showing notification
                return
            }
        }
        
        // Reset dismissal state when showing new notification
        notificationDismissed = false
        
        createNotificationChannel(context)
        
        val operationName = if (operationType == OperationType.ENCRYPT) {
            "Encrypting"
        } else {
            "Decrypting"
        }
        
        // Create intent to open app when notification is tapped
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(operationName)
            .setContentText(status)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true) // Persistent notification
            .setAutoCancel(false) // Don't auto-cancel
            .setContentIntent(pendingIntent)
            .build()
        
        NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification)
    }
    
    /**
     * Updates an existing notification with new progress and status.
     * @param context Android context
     * @param progress Progress value (0.0 to 1.0)
     * @param status Current status message
     */
    fun updateNotification(context: Context, progress: Float, status: String) {
        // Don't update if notification was dismissed by user
        if (notificationDismissed) {
            return
        }
        
        // Check notification permission (Android 13+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    context,
                    android.Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                // Permission not granted, skip updating notification
                return
            }
        }
        
        // Check if notification still exists before updating
        // If it doesn't exist, user dismissed it - track this and stop updating
        if (!isNotificationActive(context)) {
            notificationDismissed = true
            return
        }
        
        // Create intent to open app when notification is tapped
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("Operation in progress")
            .setContentText(status)
            .setProgress(100, (progress * 100).toInt(), false)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setAutoCancel(false)
            .setContentIntent(pendingIntent)
            .build()
        
        NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification)
    }
    
    /**
     * Hides the operation notification.
     * @param context Android context
     */
    fun hideNotification(context: Context) {
        NotificationManagerCompat.from(context).cancel(NOTIFICATION_ID)
        // Reset dismissal state when we explicitly hide notification
        notificationDismissed = false
    }
    
    /**
     * Checks if notification was dismissed by user.
     * @return true if notification was dismissed
     */
    fun isNotificationDismissed(): Boolean {
        return notificationDismissed
    }
    
    /**
     * Resets the dismissal state. Call this when starting a new operation or when app resumes.
     */
    fun resetDismissalState() {
        notificationDismissed = false
    }
    
    /**
     * Checks if the notification is currently active (exists in notification manager).
     * @param context Android context
     * @return true if notification exists
     */
    private fun isNotificationActive(context: Context): Boolean {
        val notificationManager = NotificationManagerCompat.from(context)
        val activeNotifications = notificationManager.activeNotifications
        return activeNotifications.any { it.id == NOTIFICATION_ID }
    }
    
    /**
     * Creates the notification channel (required for Android 8.0+).
     * @param context Android context
     */
    private fun createNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows progress for encryption and decryption operations"
                setShowBadge(false)
            }
            
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }
}

