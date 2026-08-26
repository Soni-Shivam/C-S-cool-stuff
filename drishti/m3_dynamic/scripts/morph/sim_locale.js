/*
 * MORPH sim_locale — give the device a SIM from a real carrier.
 *
 * A bare AVD reports network operator "Android", MCC/MNC 310260, and an empty SIM
 * country. Region-targeted banking trojans check exactly this before deciding whether
 * the victim is worth attacking: the wrong country means the overlay set they carry is
 * useless, so they stall. The stall reads as "clean app" unless the environment is
 * corrected and the run repeated.
 *
 * Answers the SIM/operator queries with an Indian carrier, matching the demo's
 * financial-fraud narrative. It adds no telephony capability: SmsManager.sendTextMessage
 * remains observed-and-contained by the base hooks, and the VM has no radio.
 *
 * Params (MorphKind.SIM_LOCALE, validated by _validate_sim before this runs):
 *   sim_country_iso        two lowercase letters, e.g. "in"
 *   network_operator_name  up to 20 alphanumerics/spaces, e.g. "Jio"
 *   sim_operator           5-6 digits, MCC+MNC, e.g. "40570"
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

    M.install('sim_locale', function () {
        var params = M.config('sim_locale');
        var countryIso = params.sim_country_iso || 'in';
        var operatorName = params.network_operator_name || 'Jio';
        var operator = params.sim_operator || '40570';

        var TM = Java.use('android.telephony.TelephonyManager');

        /* Map each getter to the value it should now return. Every one of these is a
         * read the sample was already making — the base hooks record that it asked. */
        var answers = {
            getSimCountryIso: countryIso,
            getNetworkCountryIso: countryIso,
            getSimOperatorName: operatorName,
            getNetworkOperatorName: operatorName,
            getSimOperator: operator,
            getNetworkOperator: operator
        };

        Object.keys(answers).forEach(function (name) {
            try {
                if (!TM[name]) { return; }
                /* Replace every overload: a sample calling the subscription-id variant
                 * would otherwise still see the emulator's answer and stall anyway. */
                TM[name].overloads.forEach(function (overload) {
                    overload.implementation = function () { return answers[name]; };
                });
            } catch (err) {
                M.fail('sim_locale.' + name, err);
            }
        });

        /* SIM_STATE_READY = 5. An absent SIM is its own stall condition, separate from
         * the wrong country, so correcting the country without this changes nothing. */
        try {
            TM.getSimState.overloads.forEach(function (overload) {
                overload.implementation = function () { return 5; };
            });
        } catch (err) {
            M.fail('sim_locale.getSimState', err);
        }
    });
}());
