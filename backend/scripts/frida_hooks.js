/*
 * DRISHTI dynamic-analysis instrumentation.
 *
 * Passive OBSERVER only: every hook logs the call and then invokes the original method.
 * Nothing is blocked, faked, or injected — the goal is to record what a sample does
 * inside a sealed sandbox so its behaviour can be mapped to MITRE ATT&CK Mobile.
 *
 * Each emitted event carries a `mitre` tag so observations land in the evidence ledger
 * already attributed (paper Table 6).
 */
'use strict';

function emit(technique, mitre, detail) {
    send({ type: 'observation', technique: technique, mitre: mitre, detail: String(detail) });
}

function safe(name, fn) {
    try { fn(); } catch (e) { send({ type: 'hook_error', hook: name, error: String(e) }); }
}

Java.perform(function () {

    // ---- T1582 SMS Control: outbound SMS (premium fraud / spreading) ----
    safe('SmsManager.sendTextMessage', function () {
        var SmsManager = Java.use('android.telephony.SmsManager');
        SmsManager.sendTextMessage.overload(
            'java.lang.String', 'java.lang.String', 'java.lang.String',
            'android.app.PendingIntent', 'android.app.PendingIntent'
        ).implementation = function (dest, sc, text, a, b) {
            emit('SMS sent', 'T1582', 'to=' + dest + ' body=' + text);
            return this.sendTextMessage(dest, sc, text, a, b);
        };
    });

    // ---- T1582 SMS Control: reading incoming SMS bodies (OTP interception) ----
    safe('SmsMessage.getMessageBody', function () {
        var SmsMessage = Java.use('android.telephony.SmsMessage');
        SmsMessage.getMessageBody.implementation = function () {
            var body = this.getMessageBody();
            emit('SMS body read (OTP interception surface)', 'T1582', body);
            return body;
        };
    });

    // ---- T1517 / T1582: aborting the SMS broadcast hides the message from the user ----
    safe('BroadcastReceiver.abortBroadcast', function () {
        var BR = Java.use('android.content.BroadcastReceiver');
        BR.abortBroadcast.implementation = function () {
            emit('SMS broadcast aborted (hiding message from user)', 'T1582', 'abortBroadcast()');
            return this.abortBroadcast();
        };
    });

    // ---- T1426 / T1422: device fingerprinting ----
    safe('TelephonyManager', function () {
        var TM = Java.use('android.telephony.TelephonyManager');
        ['getDeviceId', 'getSubscriberId', 'getLine1Number', 'getSimOperatorName'].forEach(function (m) {
            if (TM[m]) {
                TM[m].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var r = ov.apply(this, arguments);
                        emit('Device identifier read: ' + m, 'T1426', r);
                        return r;
                    };
                });
            }
        });
    });

    // ---- T1407 Download New Code: dynamic class loading (dropper / staged payload) ----
    safe('DexClassLoader', function () {
        var DCL = Java.use('dalvik.system.DexClassLoader');
        DCL.$init.implementation = function (dexPath, odex, libs, parent) {
            emit('Dynamic code loaded via DexClassLoader', 'T1407', dexPath);
            return this.$init(dexPath, odex, libs, parent);
        };
    });
    safe('PathClassLoader', function () {
        var PCL = Java.use('dalvik.system.PathClassLoader');
        PCL.$init.overload('java.lang.String', 'java.lang.ClassLoader')
          .implementation = function (p, parent) {
            emit('Dynamic code loaded via PathClassLoader', 'T1407', p);
            return this.$init(p, parent);
        };
    });

    // ---- T1521 Encrypted Channel: capture plaintext before custom encryption ----
    safe('Cipher.doFinal', function () {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (buf) {
            try {
                var s = Java.use('java.lang.String').$new(buf);
                if (s.length > 0) {
                    emit('Cipher.doFinal plaintext buffer (pre-encryption capture)',
                         'T1521', s.substring(0, 300));
                }
            } catch (e) { /* binary payload — not printable */ }
            return this.doFinal(buf);
        };
    });

    // ---- T1437 App Layer Protocol: C2 beaconing ----
    safe('URL.openConnection', function () {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            emit('Network connection opened', 'T1437', this.toString());
            return this.openConnection();
        };
    });

    // ---- T1417 Input Capture / T1516 Input Injection: accessibility abuse ----
    safe('AccessibilityService', function () {
        var AS = Java.use('android.accessibilityservice.AccessibilityService');
        AS.onAccessibilityEvent.implementation = function (ev) {
            emit('Accessibility event consumed (screen read)', 'T1417', ev.toString());
            return this.onAccessibilityEvent(ev);
        };
        if (AS.performGlobalAction) {
            AS.performGlobalAction.implementation = function (a) {
                emit('Accessibility global action (automated input)', 'T1516', 'action=' + a);
                return this.performGlobalAction(a);
            };
        }
    });

    // ---- T1414 Clipboard Data (crypto-address swapping) ----
    safe('ClipboardManager', function () {
        var CM = Java.use('android.content.ClipboardManager');
        if (CM.getPrimaryClip) {
            CM.getPrimaryClip.implementation = function () {
                var c = this.getPrimaryClip();
                emit('Clipboard read', 'T1414', String(c));
                return c;
            };
        }
        if (CM.setPrimaryClip) {
            CM.setPrimaryClip.implementation = function (c) {
                emit('Clipboard written (address-swap risk)', 'T1641.001', String(c));
                return this.setPrimaryClip(c);
            };
        }
    });

    // ---- T1626 Abuse Elevation: device-admin / persistence ----
    safe('DevicePolicyManager', function () {
        var DPM = Java.use('android.app.admin.DevicePolicyManager');
        if (DPM.isAdminActive) {
            DPM.isAdminActive.implementation = function (c) {
                emit('Device-admin status queried (persistence attempt)', 'T1626', String(c));
                return this.isAdminActive(c);
            };
        }
    });

    // ---- T1409 Access App Data: file reads of other apps' data ----
    safe('Runtime.exec', function () {
        var R = Java.use('java.lang.Runtime');
        R.exec.overload('java.lang.String').implementation = function (cmd) {
            emit('Shell command executed', 'T1409', cmd);
            return this.exec(cmd);
        };
    });

    send({ type: 'ready', detail: 'DRISHTI hooks installed' });
});
