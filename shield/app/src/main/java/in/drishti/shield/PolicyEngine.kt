package `in`.drishti.shield

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.UserManager
import android.util.Log

/**
 * LAYER 3 — the veto.
 *
 * Everything an attacker-facing product would call "blocking" is usually a dialog the
 * user can dismiss. This is not that: as device owner, DRISHTI Shield sets a user
 * restriction that makes the package installer itself refuse. The install does not
 * get discouraged, it fails.
 *
 * The app never elevates itself. Device owner is granted out of band by
 *   `adb shell dpm set-device-owner in.drishti.shield/.DrishtiAdminReceiver`
 * on a device with no accounts, exactly as `scripts/demo_up.sh` does it. If that has
 * not happened, every call here reports `false` and the UI says the veto is
 * unavailable rather than pretending it engaged.
 */
object PolicyEngine {
    private const val TAG = "DrishtiShield"

    /** `DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY` is API 29+ and is what stops a
     *  secondary user or a work profile routing around the per-user restriction. */
    private const val DISALLOW_GLOBAL = "no_install_unknown_sources_globally"

    fun admin(context: Context): ComponentName =
        ComponentName(context.applicationContext, DrishtiAdminReceiver::class.java)

    fun dpm(context: Context): DevicePolicyManager =
        context.applicationContext.getSystemService(DevicePolicyManager::class.java)

    fun isDeviceOwner(context: Context): Boolean = runCatching {
        dpm(context).isDeviceOwnerApp(context.packageName)
    }.getOrDefault(false)

    fun isAdminActive(context: Context): Boolean = runCatching {
        dpm(context).isAdminActive(admin(context))
    }.getOrDefault(false)

    /** True when installs from unknown sources are currently vetoed. */
    fun vetoEngaged(context: Context): Boolean = runCatching {
        val um = context.getSystemService(UserManager::class.java)
        um.hasUserRestriction(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
    }.getOrDefault(false)

    /**
     * Engage the veto. Returns false — and logs why — if this app is not device owner,
     * so a caller can degrade to "advisory only" instead of claiming a block it did
     * not perform.
     */
    fun engageVeto(context: Context): Boolean {
        if (!isDeviceOwner(context)) {
            Log.w(TAG, "veto requested but Shield is not device owner; advisory only")
            return false
        }
        return runCatching {
            val dpm = dpm(context)
            val admin = admin(context)
            dpm.addUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                dpm.addUserRestriction(admin, DISALLOW_GLOBAL)
            }
            Log.i(TAG, "veto ENGAGED: unknown-source installs are now refused by the OS")
            true
        }.onFailure { Log.w(TAG, "engageVeto failed", it) }.getOrDefault(false)
    }

    /**
     * Release the veto. This is an analyst action, never automatic: the UI routes it
     * through an explicit "override" button and says what it is doing.
     */
    fun releaseVeto(context: Context): Boolean {
        if (!isDeviceOwner(context)) return false
        return runCatching {
            val dpm = dpm(context)
            val admin = admin(context)
            dpm.clearUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                dpm.clearUserRestriction(admin, DISALLOW_GLOBAL)
            }
            Log.i(TAG, "veto released by analyst override")
            true
        }.onFailure { Log.w(TAG, "releaseVeto failed", it) }.getOrDefault(false)
    }

    /**
     * Quarantine an already-installed package: suspend it so it cannot be launched or
     * receive broadcasts, and block its uninstall so the sample cannot remove the
     * evidence before an analyst has looked at it.
     */
    fun quarantine(context: Context, packageName: String): Boolean {
        if (!isDeviceOwner(context)) return false
        return runCatching {
            val dpm = dpm(context)
            val admin = admin(context)
            val failed = dpm.setPackagesSuspended(admin, arrayOf(packageName), true)
            dpm.setUninstallBlocked(admin, packageName, true)
            val ok = failed.isEmpty()
            Log.i(TAG, "quarantine $packageName suspended=$ok uninstall_blocked=true")
            ok
        }.onFailure { Log.w(TAG, "quarantine failed", it) }.getOrDefault(false)
    }

    /**
     * Lift every quarantine this app is currently holding, and report what was freed.
     *
     * Needed because a quarantine is deliberately hard to undo: Layer 4 calls
     * [setUninstallBlocked][DevicePolicyManager.setUninstallBlocked], and from that
     * moment `adb uninstall` returns `DELETE_FAILED_OWNER_BLOCKED`. That is correct
     * behaviour against a real sample and wrong behaviour for a demo that has to be
     * rerunnable — after one rehearsal in which the decoy actually installed, every
     * later run's reset failed to remove it and the beat started from a dirty device.
     *
     * There is no "list what I have blocked" API, so this asks per package. Bounded by
     * the installed-package count and only ever reached from the debug-gated reset.
     */
    fun releaseAllQuarantines(context: Context): List<String> {
        if (!isDeviceOwner(context)) return emptyList()
        val dpm = dpm(context)
        val admin = admin(context)
        val freed = mutableListOf<String>()
        val installed = runCatching {
            context.packageManager.getInstalledPackages(0).map { it.packageName }
        }.getOrDefault(emptyList())
        for (name in installed) {
            if (name == context.packageName) continue
            runCatching {
                if (dpm.isUninstallBlocked(admin, name)) {
                    release(context, name)
                    freed += name
                }
            }
        }
        return freed
    }

    /** Lift a quarantine so the package can be removed by the user. */
    fun release(context: Context, packageName: String): Boolean {
        if (!isDeviceOwner(context)) return false
        return runCatching {
            val dpm = dpm(context)
            val admin = admin(context)
            dpm.setUninstallBlocked(admin, packageName, false)
            dpm.setPackagesSuspended(admin, arrayOf(packageName), false)
            true
        }.onFailure { Log.w(TAG, "release failed", it) }.getOrDefault(false)
    }

    /** One line for the status card, honest about what is actually in force. */
    fun statusLine(context: Context): String = when {
        !isDeviceOwner(context) -> "Layer 3 unavailable — Shield is not device owner"
        vetoEngaged(context) -> "Layer 3 ARMED — unknown-source installs are vetoed"
        else -> "Layer 3 ready — device owner held, veto not currently engaged"
    }
}
