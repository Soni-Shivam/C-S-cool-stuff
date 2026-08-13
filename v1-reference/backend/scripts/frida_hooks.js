/* DRISHTI M3 allowlisted passive hook catalogue — version m3-hooks-1.0.0. */
'use strict';

var enabledHooks = null;
rpc.exports = {
    configure: function (hookIds) {
        enabledHooks = {};
        hookIds.forEach(function (id) { enabledHooks[id] = true; });
        return true;
    }
};

function redact(value, kind) {
    if (kind === 'message') return '[REDACTED:MESSAGE_BODY]';
    var text = String(value === null || value === undefined ? '' : value);
    text = text.replace(/\b(otp|one[ -]?time(?: password| code)?|verification code)\D{0,20}\d{4,8}\b/ig, '[REDACTED:OTP]');
    text = text.replace(/\b(password|passwd|passcode|pin|username|login)\s*[:=]\s*[^\s,;]{2,}/ig, '[REDACTED:CREDENTIAL]');
    text = text.replace(/\b(bearer\s+[a-z0-9._~+/=-]{8,}|(access|refresh|api|auth)[_-]?token\s*[:=]\s*[^\s,;]{8,})/ig, '[REDACTED:TOKEN]');
    return text.substring(0, 512);
}

function emit(hook, technique, mitre, detail, kind) {
    if (enabledHooks !== null && !enabledHooks[hook]) return;
    send({
        type: 'observation', source_hook: hook, technique: technique, mitre: mitre,
        detail: redact(detail, kind), redacted: true, occurred_at: new Date().toISOString()
    });
}

function emitSensitive(hook, technique, mitre, detail) {
    if (enabledHooks !== null && !enabledHooks[hook]) return;
    send({
        type: 'sensitive_observation', source_hook: hook, technique: technique, mitre: mitre,
        sensitive_detail: String(detail), redacted: true, occurred_at: new Date().toISOString()
    });
}

function safe(name, installer) {
    try { installer(); } catch (error) {
        send({type: 'hook_error', hook: name, error: redact(error)});
    }
}

Java.perform(function () {
    safe('SmsManager.sendTextMessage', function () {
        var SmsManager = Java.use('android.telephony.SmsManager');
        var original = SmsManager.sendTextMessage.overload(
            'java.lang.String', 'java.lang.String', 'java.lang.String',
            'android.app.PendingIntent', 'android.app.PendingIntent');
        original.implementation = function (dest, sc, body, sent, delivered) {
            emit('SmsManager.sendTextMessage', 'SMS send API invoked', 'T1582',
                 'destination=[REDACTED:PHONE] body=' + redact(body, 'message'));
            return original.call(this, dest, sc, body, sent, delivered);
        };
    });

    safe('SmsMessage.getMessageBody', function () {
        var SmsMessage = Java.use('android.telephony.SmsMessage');
        var original = SmsMessage.getMessageBody.overload();
        original.implementation = function () {
            var body = original.call(this);
            emit('SmsMessage.getMessageBody', 'SMS body read', 'T1582', body, 'message');
            return body;
        };
    });

    safe('BroadcastReceiver.abortBroadcast', function () {
        var Receiver = Java.use('android.content.BroadcastReceiver');
        var original = Receiver.abortBroadcast.overload();
        original.implementation = function () {
            emit('BroadcastReceiver.abortBroadcast', 'SMS broadcast aborted', 'T1582', 'abortBroadcast()');
            return original.call(this);
        };
    });

    safe('TelephonyManager.identifiers', function () {
        var Manager = Java.use('android.telephony.TelephonyManager');
        ['getDeviceId', 'getSubscriberId', 'getLine1Number', 'getSimOperatorName'].forEach(function (name) {
            if (!Manager[name]) return;
            Manager[name].overloads.forEach(function (original) {
                original.implementation = function () {
                    var result = original.apply(this, arguments);
                    emit('TelephonyManager.' + name, 'Device property read: ' + name, 'T1426', '[REDACTED:DEVICE_VALUE]');
                    return result;
                };
            });
        });
    });

    safe('DexClassLoader.$init', function () {
        var Loader = Java.use('dalvik.system.DexClassLoader');
        var original = Loader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader');
        original.implementation = function (dexPath, optimized, libraries, parent) {
            emit('DexClassLoader.$init', 'Local dynamic code loaded', 'T1407', 'path=' + redact(dexPath));
            return original.call(this, dexPath, optimized, libraries, parent);
        };
    });

    safe('PathClassLoader.$init', function () {
        var Loader = Java.use('dalvik.system.PathClassLoader');
        var original = Loader.$init.overload('java.lang.String', 'java.lang.ClassLoader');
        original.implementation = function (path, parent) {
            emit('PathClassLoader.$init', 'Local class path loaded', 'T1407', 'path=' + redact(path));
            return original.call(this, path, parent);
        };
    });

    safe('Cipher.doFinal', function () {
        var Cipher = Java.use('javax.crypto.Cipher');
        var original = Cipher.doFinal.overload('[B');
        original.implementation = function (buffer) {
            var preview = '[BINARY_OR_EMPTY]';
            try { preview = Java.use('java.lang.String').$new(buffer).toString(); } catch (_ignored) {}
            emitSensitive('Cipher.doFinal([B)', 'Plaintext passed to Cipher.doFinal', 'T1521', preview);
            return original.call(this, buffer);
        };
    });

    safe('URL.openConnection', function () {
        var URL = Java.use('java.net.URL');
        var original = URL.openConnection.overload();
        original.implementation = function () {
            var endpoint = this.getProtocol() + '://' + this.getHost() + ':' + this.getPort();
            emit('URL.openConnection', 'Network connection opened', 'T1437', endpoint);
            return original.call(this);
        };
    });

    safe('ClipboardManager.getPrimaryClip', function () {
        var Clipboard = Java.use('android.content.ClipboardManager');
        var original = Clipboard.getPrimaryClip.overload();
        original.implementation = function () {
            var result = original.call(this);
            emit('ClipboardManager.getPrimaryClip', 'Clipboard read', 'T1414', '[REDACTED:CLIPBOARD]');
            return result;
        };
    });

    safe('ClipboardManager.setPrimaryClip', function () {
        var Clipboard = Java.use('android.content.ClipboardManager');
        var original = Clipboard.setPrimaryClip.overload('android.content.ClipData');
        original.implementation = function (clip) {
            emit('ClipboardManager.setPrimaryClip', 'Clipboard written', 'T1641.001', '[REDACTED:CLIPBOARD]');
            return original.call(this, clip);
        };
    });

    safe('DevicePolicyManager.isAdminActive', function () {
        var Manager = Java.use('android.app.admin.DevicePolicyManager');
        var original = Manager.isAdminActive.overload('android.content.ComponentName');
        original.implementation = function (component) {
            emit('DevicePolicyManager.isAdminActive', 'Device-admin status queried', 'T1626', redact(component));
            return original.call(this, component);
        };
    });

    send({type: 'ready', hook_version: 'm3-hooks-1.0.0'});
});
