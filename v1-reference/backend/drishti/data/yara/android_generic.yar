rule dynamic_code_loading
{
    meta:
        description = "Dynamic code loading primitives (dropper / staged payload)"
        severity = "high"
    strings:
        $a = "DexClassLoader" ascii wide
        $b = "PathClassLoader" ascii wide
        $c = "loadDex" ascii wide
        $d = "createPackageContext" ascii wide
    condition:
        any of them
}

rule accessibility_service_abuse
{
    meta:
        description = "Accessibility service hooks used for overlay/keylogging"
        severity = "high"
    strings:
        $a = "onAccessibilityEvent" ascii wide
        $b = "BIND_ACCESSIBILITY_SERVICE" ascii wide
        $c = "performGlobalAction" ascii wide
    condition:
        2 of them
}

rule sms_interception
{
    meta:
        description = "SMS/OTP interception primitives"
        severity = "high"
    strings:
        $a = "android.provider.Telephony.SMS_RECEIVED" ascii wide
        $b = "getMessageBody" ascii wide
        $c = "abortBroadcast" ascii wide
    condition:
        2 of them
}
