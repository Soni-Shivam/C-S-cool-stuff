package `in`.drishti.decoy.rtochallan

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Declared in the manifest for `SMS_RECEIVED` at maximum priority, which is what
 * makes the static surface look like an OTP interceptor.
 *
 * The body reads nothing. It does not call `Telephony.Sms.Intents.getMessagesFromIntent`,
 * does not touch `intent.extras`, does not read `pdus`, and does not call
 * `abortBroadcast()`. It logs one line and returns. That is the whole class.
 */
class SmsDeliveryReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        InertMarker.noop("SmsDeliveryReceiver.onReceive(action=${intent.action})")
    }
}
