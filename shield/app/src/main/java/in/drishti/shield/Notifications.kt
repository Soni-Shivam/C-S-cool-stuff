package `in`.drishti.shield

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import `in`.drishti.shield.ui.VerdictActivity

/** Notification plumbing. Two channels: a quiet one for "watching", a loud one for alerts. */
object Notifications {
    const val CHANNEL_WATCH = "drishti_watch"
    const val CHANNEL_ALERT = "drishti_alert"
    const val ID_WATCH = 1
    const val ID_ALERT = 2

    fun ensureChannels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_WATCH, "Shield active", NotificationManager.IMPORTANCE_LOW
            ).apply { description = "The persistent watcher on the Download folder" }
        )
        nm.createNotificationChannel(
            // HIGH, because a full-screen intent is only honoured on a high-importance
            // channel — and the whole point is that the verdict interrupts.
            NotificationChannel(
                CHANNEL_ALERT, "Threat verdicts", NotificationManager.IMPORTANCE_HIGH
            ).apply { description = "APK verdicts from the DRISHTI backend" }
        )
    }

    fun watching(context: Context, text: String): Notification =
        Notification.Builder(context, CHANNEL_WATCH)
            .setContentTitle("DRISHTI Shield")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .setContentIntent(open(context, null))
            .build()

    /**
     * The verdict alert. A full-screen intent is attached so the verdict screen comes
     * up without a tap; if the OS declines the full-screen route, the same intent is
     * still the notification's content intent, so one tap gets there.
     */
    fun alert(context: Context, scan: Scan): Notification {
        val blocked = scan.blocked
        val title = when {
            scan.state == ScanState.SCANNING -> "Scanning ${scan.filename}…"
            blocked -> "BLOCKED: ${scan.filename}"
            scan.state == ScanState.ERROR -> "Scan incomplete: ${scan.filename}"
            else -> "Cleared: ${scan.filename}"
        }
        val body = when {
            scan.state == ScanState.SCANNING -> "DRISHTI is analysing this file before you open it"
            scan.decision != null -> "${scan.decision.headline} · ${scan.elapsedMs} ms"
            else -> scan.error ?: "No verdict"
        }
        val intent = open(context, scan.id)
        return Notification.Builder(context, CHANNEL_ALERT)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(Notification.BigTextStyle().bigText(body))
            .setSmallIcon(R.drawable.ic_shield)
            .setCategory(Notification.CATEGORY_ALARM)
            .setColor(if (blocked) 0xFFD62828.toInt() else 0xFF3FA7FF.toInt())
            .setColorized(true)
            .setAutoCancel(false)
            .setOngoing(blocked)
            .setContentIntent(intent)
            .setFullScreenIntent(intent, true)
            .build()
    }

    fun post(context: Context, id: Int, notification: Notification) {
        context.getSystemService(NotificationManager::class.java).notify(id, notification)
    }

    private fun open(context: Context, scanId: String?): PendingIntent {
        val intent = Intent(context, VerdictActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            scanId?.let { putExtra(VerdictActivity.EXTRA_SCAN_ID, it) }
        }
        return PendingIntent.getActivity(
            context,
            scanId?.hashCode() ?: 0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }
}
