package `in`.drishti.decoy.rtochallan

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Declared for BOOT_COMPLETED. Starts nothing; logs one line. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        InertMarker.noop("BootReceiver.onReceive — no service is started")
    }
}
