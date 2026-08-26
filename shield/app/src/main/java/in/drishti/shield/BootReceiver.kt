package `in`.drishti.shield

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Restart the watcher after a reboot. Layer 1 is worthless if it only runs once. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) WatchService.start(context)
    }
}
