package `in`.drishti.benign.sanchay

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Declared for `SMS_RECEIVED`, exactly as a real SMS-driven expense tracker would be.
 *
 * The body never touches the intent. It does not read `pdus`, does not build a
 * message, does not look at the sender. The declaration is the point — it is what
 * gives this control sample the same OTP_THEFT_SURFACE match the decoy gets, so the
 * demo can show two apps tripping the same rule and receiving different verdicts.
 */
class SmsAlertReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
        InertMarker.noop("SmsAlertReceiver.onReceive")
    }
}
