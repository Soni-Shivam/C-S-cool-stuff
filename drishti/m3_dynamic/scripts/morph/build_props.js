/*
 * MORPH build_props — make the device stop looking like an emulator.
 *
 * The single most common stall in Android banking trojans: read android.os.Build,
 * see "generic_x86" / "sdk_gphone" / "Android-Build", conclude "analysis sandbox",
 * and do nothing. A sample that stalls here is indistinguishable from a clean app,
 * which is exactly why `inconclusive` is never reported as benign.
 *
 * This morph answers the Build query with a real handset's values. It changes what
 * the sample observes; it grants the sample nothing. Every field written here is one
 * the sample could already read.
 *
 * Params (MorphKind.BUILD_PROPS, validated by _validate_build_props before this runs):
 *   MODEL, FINGERPRINT, PRODUCT, HARDWARE, MANUFACTURER, BRAND, DEVICE — all strings.
 * Defaults below describe a Xiaomi Redmi Note 10, a high-volume handset in the Indian
 * market the demo narrative is about.
 */

'use strict';

(function () {
    /* Fallback if _prelude.js was not prepended — a morph must not fail open. */
    var M = (typeof DRISHTI_MORPH !== 'undefined') ? DRISHTI_MORPH : {
        config: function () { return {}; },
        fail: function (n, e) {
            try { send({ type: 'hook_error', hook: 'morph:' + n, error: String(e).substring(0, 200) }); }
            catch (ignored) { /* no channel left */ }
        },
        install: function (n, f) { try { f(); } catch (e) { this.fail(n, e); } }
    };

    var DEFAULTS = {
        MODEL: 'M2101K7AG',
        MANUFACTURER: 'Xiaomi',
        BRAND: 'Redmi',
        DEVICE: 'mojito',
        PRODUCT: 'mojito',
        HARDWARE: 'qcom',
        FINGERPRINT: 'Redmi/mojito/mojito:11/RKQ1.201004.002/V12.5.2.0.RKGINXM:user/release-keys'
    };

    M.install('build_props', function () {
        var params = M.config('build_props');
        var Build = Java.use('android.os.Build');

        Object.keys(DEFAULTS).forEach(function (field) {
            var value = Object.prototype.hasOwnProperty.call(params, field)
                ? params[field]
                : DEFAULTS[field];
            if (typeof value !== 'string') { return; }
            try {
                /* Build's fields are `static final String`. Frida writes them through
                 * the field wrapper; a field missing on this API level costs us that
                 * one field, not the whole morph. */
                Build[field].value = value;
            } catch (err) {
                M.fail('build_props.' + field, err);
            }
        });

        /* Build.VERSION is a separate class and some checks read its CODENAME to spot
         * a preview/emulator image. Only normalise it if it is not already 'REL'. */
        try {
            var Version = Java.use('android.os.Build$VERSION');
            if (String(Version.CODENAME.value) !== 'REL') { Version.CODENAME.value = 'REL'; }
        } catch (err) {
            M.fail('build_props.VERSION', err);
        }
    });
}());
