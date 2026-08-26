/*
 * MORPH install_packages — put the target apps on the device.
 *
 * An overlay trojan carries a roster of banking packages and asks the PackageManager
 * which of them are installed. On a bare AVD the answer is "none", so there is nothing
 * to overlay and the sample idles. The behaviour that makes it malware — choosing a
 * target, building the overlay, requesting accessibility — is never reached, and the
 * trace looks like a clean app.
 *
 * This morph makes the roster's packages answer "present". It installs nothing: no APK
 * is added to the device, no code is loaded, and the synthetic PackageInfo carries a
 * name and nothing else. The sample learns that a package exists; it gains no access
 * to it, because it does not exist.
 *
 * Params (MorphKind.INSTALL_PACKAGES, validated by _validate_packages before this runs):
 *   packages  non-empty list of valid package names, each matched by _PACKAGE_RE.
 * Defaults below are high-share Indian banking/UPI apps, matching the demo narrative.
 */

'use strict';

(function () {
    var M = (typeof DRISHTI_MORPH !== 'undefined') ? DRISHTI_MORPH : {
        config: function () { return {}; },
        fail: function (n, e) {
            try { send({ type: 'hook_error', hook: 'morph:' + n, error: String(e).substring(0, 200) }); }
            catch (ignored) { /* no channel left */ }
        },
        install: function (n, f) { try { f(); } catch (e) { this.fail(n, e); } }
    };

    var DEFAULTS = [
        'com.google.android.apps.nbu.paisa.user',  /* Google Pay India */
        'net.one97.paytm',
        'com.phonepe.app',
        'com.csam.icici.bank.imobile',
        'com.sbi.lotusintouch',
        'com.snapwork.hdfc',
        'com.axis.mobile',
        'com.msf.kbank.mobile'
    ];

    M.install('install_packages', function () {
        var params = M.config('install_packages');
        var wanted = (params.packages && params.packages.length) ? params.packages : DEFAULTS;

        /* Membership set — the hooks below run on every PackageManager call the sample
         * makes, so this must be a lookup, not a scan. */
        var present = {};
        wanted.forEach(function (pkg) { present[pkg] = true; });

        var PackageInfo = Java.use('android.content.pm.PackageInfo');
        var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
        var PM = Java.use('android.app.ApplicationPackageManager');

        /* A deliberately hollow record: package name, nothing else. The sample can
         * learn that the name resolves. There is no APK, no signature, no code. */
        function synth(pkg) {
            var info = PackageInfo.$new();
            info.packageName.value = pkg;
            info.versionName.value = '1.0';
            try {
                var app = ApplicationInfo.$new();
                app.packageName.value = pkg;
                app.enabled.value = true;
                info.applicationInfo.value = app;
            } catch (err) { /* applicationInfo is optional for a presence check */ }
            return info;
        }

        /* getPackageInfo: the direct "is the bank installed?" probe. Answer for a name
         * on the roster; leave every other package to the real PackageManager, so the
         * sample's view of the rest of the device stays truthful. */
        try {
            PM.getPackageInfo.overload('java.lang.String', 'int').implementation =
                function (pkg, flags) {
                    try {
                        return this.getPackageInfo(pkg, flags);
                    } catch (notFound) {
                        if (present[pkg]) { return synth(pkg); }
                        throw notFound;
                    }
                };
        } catch (err) {
            M.fail('install_packages.getPackageInfo', err);
        }

        /* getInstalledPackages: the roster-enumeration probe. Append the synthetic
         * entries to the real list rather than replacing it — a sample that finds the
         * device implausibly empty stalls for a different reason. */
        try {
            PM.getInstalledPackages.overload('int').implementation = function (flags) {
                var real = this.getInstalledPackages(flags);
                try {
                    var seen = {};
                    var size = real.size();
                    for (var i = 0; i < size; i++) {
                        var entry = Java.cast(real.get(i), PackageInfo);
                        seen[String(entry.packageName.value)] = true;
                    }
                    wanted.forEach(function (pkg) {
                        if (!seen[pkg]) { real.add(synth(pkg)); }
                    });
                } catch (err) {
                    M.fail('install_packages.enumerate', err);
                }
                return real;
            };
        } catch (err) {
            M.fail('install_packages.getInstalledPackages', err);
        }
    });
}());
