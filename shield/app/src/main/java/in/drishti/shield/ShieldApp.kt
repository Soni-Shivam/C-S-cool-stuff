package `in`.drishti.shield

import android.app.Application

/** Creates the notification channels once and starts the watcher. */
class ShieldApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Notifications.ensureChannels(this)
        WatchService.start(this)
    }
}
