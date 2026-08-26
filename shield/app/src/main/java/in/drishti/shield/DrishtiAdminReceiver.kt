package `in`.drishti.shield

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * LAYER 3 — the device-admin component `dpm set-device-owner` points at.
 *
 * It holds no policy of its own; [PolicyEngine] owns every decision. Keeping the
 * receiver empty means the admin's behaviour can be audited by reading one file.
 */
class DrishtiAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        Log.i("DrishtiShield", "device admin enabled; device_owner=${PolicyEngine.isDeviceOwner(context)}")
        WatchService.start(context)
    }

    override fun onDisabled(context: Context, intent: Intent) {
        Log.i("DrishtiShield", "device admin disabled — the Layer 3 veto is no longer available")
    }

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        "Disabling DRISHTI Shield removes the install veto. Malicious APKs will install."
}
