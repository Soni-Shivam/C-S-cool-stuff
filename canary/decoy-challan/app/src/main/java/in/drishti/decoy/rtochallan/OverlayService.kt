package `in`.drishti.decoy.rtochallan

import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * The service half of `OVERLAY_CREDENTIAL_THEFT` (T1056): SYSTEM_ALERT_WINDOW is
 * declared in the manifest and a service component exists, which is what the rule
 * matches on.
 *
 * The implementation never obtains a `WindowManager`, never inflates a view, and
 * never calls `addView`. It stops itself on the first command.
 */
class OverlayService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        InertMarker.noop("OverlayService.onStartCommand — stopping immediately, no overlay")
        stopSelf()
        return START_NOT_STICKY
    }
}
