package `in`.drishti.decoy.rtochallan

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent

/**
 * The component that trips `ACCESSIBILITY_ABUSE` (critical, T1417) in the static
 * rules — because the rule fires on a service *bound* to
 * `BIND_ACCESSIBILITY_SERVICE`, which is a manifest fact.
 *
 * The implementation is empty. [onAccessibilityEvent] does not read the event, does
 * not walk the node tree, does not call `performGlobalAction`, and does not touch
 * `rootInActiveWindow`. There is no accessibility abuse here — only the declaration
 * that a detector should flag.
 */
class ChallanAccessibilityService : AccessibilityService() {
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // Intentionally empty. Reading `event` is exactly the behaviour this decoy
        // must not have.
    }

    override fun onInterrupt() {
        InertMarker.noop("ChallanAccessibilityService.onInterrupt")
    }

    override fun onServiceConnected() {
        InertMarker.noop("ChallanAccessibilityService.onServiceConnected")
    }
}
