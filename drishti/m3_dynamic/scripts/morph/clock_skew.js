/*
 * MORPH clock_skew — move the wall clock forward.
 *
 * Time-bomb samples compare the current date against a hardcoded activation date and
 * do nothing until it passes: a sandbox runs for two minutes, the activation is a week
 * out, and the sample looks inert. Advancing the clock the sample observes lets the
 * activation branch be reached inside the detonation window.
 *
 * This morph moves only what the SAMPLE reads. The VM clock, the trace timestamps, and
 * the containment manifest's validity window are untouched — they come from the host,
 * not from these hooks — so the artifact's own timeline stays truthful.
 *
 * Params (MorphKind.CLOCK_SKEW, validated by _validate_clock before this runs):
 *   offset_days  integer, |offset| <= MAX_OFFSET_DAYS. Positive moves into the future.
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

    M.install('clock_skew', function () {
        var params = M.config('clock_skew');
        var offsetDays = (typeof params.offset_days === 'number') ? params.offset_days : 30;
        var offsetMs = offsetDays * 24 * 60 * 60 * 1000;

        /* System.currentTimeMillis is the common path. Add the offset to the real
         * value rather than returning a fixed constant, so time still advances during
         * the run and a sample that samples the clock twice sees it move.
         *
         * The real millis value exceeds 2^53, so JS number arithmetic on it would lose
         * precision; go through java.lang.Long to keep it exact. */
        try {
            var Long = Java.use('java.lang.Long');
            var System = Java.use('java.lang.System');
            System.currentTimeMillis.implementation = function () {
                var realMs = this.currentTimeMillis();
                return Long.parseLong('' + (parseInt('' + realMs, 10) + offsetMs));
            };
        } catch (err) {
            M.fail('clock_skew.currentTimeMillis', err);
        }

        /* Date() with no args and Calendar.getInstance() both funnel through
         * currentTimeMillis on Android, so the two hooks above cover the usual date
         * reads without hooking Date/Calendar directly. */
    });
}());
