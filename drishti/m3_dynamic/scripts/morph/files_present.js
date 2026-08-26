/*
 * MORPH files_present — hide the sandbox's fingerprint files, or show a target's.
 *
 * Two stall shapes share one mechanism. (1) Anti-analysis samples probe for files that
 * only exist on an emulator or a rooted/instrumented device — /dev/qemu_pipe, the su
 * binary, frida's own artifacts — and abort if they find them. (2) Some samples wake
 * only when a companion file is present (a config the dropper wrote, a marker from an
 * earlier stage). Both are `File.exists()` checks with a hardcoded path.
 *
 * This morph answers those existence probes: paths on the emulator-fingerprint list
 * report absent, and any path the caller names in `names` reports present. It creates
 * no file and reads no file — it changes only the boolean the sample observes.
 *
 * Params (MorphKind.FILES_PRESENT, validated by _validate_files before this runs):
 *   names  list of file names to report as PRESENT (no path separators; the validator
 *          rejects a name that tries to smuggle a path).
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

    /* Emulator / instrumentation fingerprints that should report ABSENT. A substring
     * match: samples probe many spellings of the same path. */
    var HIDE = [
        'qemu', 'goldfish', 'ranchu', 'genymotion', 'vbox', 'nox', 'ttVM',
        '/su', 'magisk', 'supersu', 'frida', 're.frida', 'gum-js-loop',
        'gdbus', '/dev/socket/qemud', 'android_x86'
    ];

    M.install('files_present', function () {
        var params = M.config('files_present');
        var show = {};
        (params.names || []).forEach(function (name) { show['' + name] = true; });

        var File = Java.use('java.io.File');

        function decide(path, realResult) {
            var p = ('' + path);
            var lower = p.toLowerCase();
            /* Explicit "show" wins: the caller asked for this name specifically. */
            for (var name in show) {
                if (Object.prototype.hasOwnProperty.call(show, name) && p.indexOf(name) !== -1) {
                    return true;
                }
            }
            /* Anything on the fingerprint list is forced absent. */
            for (var i = 0; i < HIDE.length; i++) {
                if (lower.indexOf(HIDE[i].toLowerCase()) !== -1) { return false; }
            }
            /* Everything else keeps the real answer — the sample's view of the rest of
             * the filesystem stays truthful. */
            return realResult;
        }

        try {
            File.exists.implementation = function () {
                return decide(this.getAbsolutePath(), this.exists());
            };
        } catch (err) {
            M.fail('files_present.exists', err);
        }
    });
}());
