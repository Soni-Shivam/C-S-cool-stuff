/*
 * DRISHTI observational Frida hooks. ADAPTed from v1's frida_hooks.js.
 *
 * docs/PHASE_4_DYNAMIC_SANDBOX.md T4.2, CLAUDE.md hard boundaries.
 *
 * EVERY HOOK HERE IS OBSERVATIONAL. Each one reads a value and reports that a call
 * happened. None adds capability to the sample, none changes a return value, and none
 * exists to make the app do something it was not already going to do. Morphs — which DO
 * return synthetic values — live in scripts/morph/ and are a separate, deliberate thing.
 *
 * Redaction happens HERE, in the guest, before a value crosses the boundary. The
 * ObservationEvent contract then refuses to construct on unredacted text, so a bug in
 * this file becomes a validation failure rather than a data leak. Belt and braces.
 *
 * `safe()` wraps every hook: a sample that lacks a class, or ships a stripped SDK, must
 * cost us that one hook and not the whole session. A single missing class taking down
 * instrumentation is how a detonation silently returns nothing.
 */

'use strict';

var MAX_PREVIEW = 96;

function emit(hook, technique, mitre, detail) {
    send({
        type: 'observation',
        technique: technique,
        mitre: mitre,
        source_hook: hook,
        detail: (detail || '').substring(0, 512),
        redacted: true
    });
}

/* Redact before anything leaves the guest. Digits are the sensitive part: OTPs, card
 * numbers, phone numbers and IMEIs are all digit runs, and the analyst needs to know a
 * value was READ, never what it was. */
function redact(value) {
    if (value === null || value === undefined) { return '<null>'; }
    var text = String(value);
    text = text.replace(/\d/g, '#');
    text = text.replace(/[A-Za-z0-9+/]{24,}={0,2}/g, '<b64>');
    if (text.length > MAX_PREVIEW) { text = text.substring(0, MAX_PREVIEW) + '...'; }
    return text;
}

function safe(name, fn) {
    try { fn(); } catch (err) {
        send({ type: 'hook_error', hook: name, error: String(err).substring(0, 200) });
    }
}

Java.perform(function () {

    /* ── environment probing: what the frontier answers ───────────────── */
    safe('PackageManager.getPackageInfo', function () {
        var PM = Java.use('android.app.ApplicationPackageManager');
        PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            emit('PackageManager.getPackageInfo', 'Software discovery', 'T1418',
                 'queried package=' + redact(pkg));
            return this.getPackageInfo(pkg, flags);
        };
    });

    safe('PackageManager.getInstalledPackages', function () {
        var PM = Java.use('android.app.ApplicationPackageManager');
        PM.getInstalledPackages.overload('int').implementation = function (flags) {
            var result = this.getInstalledPackages(flags);
            emit('PackageManager.getInstalledPackages', 'Software discovery', 'T1418',
                 'enumerated installed packages');
            return result;
        };
    });

    safe('TelephonyManager identifiers', function () {
        var TM = Java.use('android.telephony.TelephonyManager');
        ['getDeviceId', 'getSubscriberId', 'getSimSerialNumber',
         'getLine1Number', 'getSimCountryIso', 'getSimOperatorName'].forEach(function (name) {
            if (TM[name] === undefined) { return; }
            TM[name].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    var value = overload.apply(this, arguments);
                    emit('TelephonyManager.' + name, 'System information discovery', 'T1426',
                         name + ' -> ' + redact(value));
                    return value;
                };
            });
        });
    });

    /* ── SMS: the OTP path ─────────────────────────────────────────────── */
    safe('SmsManager.sendTextMessage', function () {
        var SM = Java.use('android.telephony.SmsManager');
        var original = SM.sendTextMessage.overload(
            'java.lang.String', 'java.lang.String', 'java.lang.String',
            'android.app.PendingIntent', 'android.app.PendingIntent');
        original.implementation = function (dest, sc, text, sent, delivered) {
            emit('SmsManager.sendTextMessage', 'SMS control', 'T1582',
                 'sms send to=' + redact(dest) + ' body=' + redact(text));
            return original.call(this, dest, sc, text, sent, delivered);
        };
    });

    safe('SmsMessage.getMessageBody', function () {
        var SMS = Java.use('android.telephony.SmsMessage');
        SMS.getMessageBody.implementation = function () {
            var body = this.getMessageBody();
            emit('SmsMessage.getMessageBody', 'Capture SMS messages', 'T1412',
                 'read sms body=' + redact(body));
            return body;
        };
    });

    /* ── runtime code loading: the dropper shape ───────────────────────── */
    safe('DexClassLoader.$init', function () {
        var DCL = Java.use('dalvik.system.DexClassLoader');
        DCL.$init.implementation = function (dexPath, optDir, libPath, parent) {
            emit('DexClassLoader.$init', 'Download new code at runtime', 'T1407',
                 'loaded dex path=' + redact(dexPath));
            return this.$init(dexPath, optDir, libPath, parent);
        };
    });

    /* ── crypto: plaintext BEFORE it is encrypted ──────────────────────── */
    /* This is the strongest single hook we have, and the reason HTTPS interception is
     * a deferred nicety rather than a blocker: doFinal sees the plaintext before it
     * ever reaches TLS, which also defeats custom crypto (T1521). */
    safe('Cipher.doFinal', function () {
        var Cipher = Java.use('javax.crypto.Cipher');
        var original = Cipher.doFinal.overload('[B');
        original.implementation = function (buffer) {
            var preview = '<unreadable>';
            try { preview = redact(Java.use('java.lang.String').$new(buffer)); } catch (e) { /* binary */ }
            emit('Cipher.doFinal', 'Encrypted channel', 'T1521', 'crypto op plaintext=' + preview);
            return original.call(this, buffer);
        };
    });

    /* ── exfiltration channel ──────────────────────────────────────────── */
    safe('URL.openConnection', function () {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            emit('URL.openConnection', 'Application layer protocol', 'T1437',
                 'opened connection to=' + redact(this.toString()));
            return this.openConnection();
        };
    });

    /* ── UI abuse ──────────────────────────────────────────────────────── */
    safe('WindowManager.addView', function () {
        var WM = Java.use('android.view.WindowManagerImpl');
        WM.addView.implementation = function (view, params) {
            emit('WindowManager.addView', 'Input capture via overlay', 'T1417',
                 'added a window over other apps');
            return this.addView(view, params);
        };
    });

    safe('ClipboardManager.getPrimaryClip', function () {
        var CM = Java.use('android.content.ClipboardManager');
        CM.getPrimaryClip.implementation = function () {
            var clip = this.getPrimaryClip();
            emit('ClipboardManager.getPrimaryClip', 'Clipboard data', 'T1414', 'read the clipboard');
            return clip;
        };
    });

    /* ── execution and persistence ─────────────────────────────────────── */
    safe('Runtime.exec', function () {
        var RT = Java.use('java.lang.Runtime');
        RT.exec.overload('java.lang.String').implementation = function (command) {
            emit('Runtime.exec', 'Command and scripting interpreter', 'T1623',
                 'exec ' + redact(command));
            return this.exec(command);
        };
    });

    safe('ContentResolver.query', function () {
        var CR = Java.use('android.content.ContentResolver');
        CR.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
                          '[Ljava.lang.String;', 'java.lang.String').implementation =
        function (uri, projection, sel, args, order) {
            var target = String(uri);
            var mitre = 'T1636';
            if (target.indexOf('sms') !== -1) { mitre = 'T1412'; }
            emit('ContentResolver.query', 'Protected user data', mitre,
                 'queried provider ' + redact(target));
            return this.query(uri, projection, sel, args, order);
        };
    });

    send({ type: 'hooks_installed', count: 13 });
});
