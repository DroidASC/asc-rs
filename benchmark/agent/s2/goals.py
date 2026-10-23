# S2 agent goals: one exposure question over a whole directory of APKs.
# Reference = APKs (file stem) where any rule has at least one row.
GOALS = {
    "memory_dex": {
        "intent": "Which of these APKs load DEX bytecode from memory, i.e. construct dalvik.system.InMemoryDexClassLoader?",
        "rules": ["method:dalvik.system.InMemoryDexClassLoader-><init>"],
    },
    "gesture_injection": {
        "intent": "Which of these APKs inject touch gestures through an accessibility service (calls to android.accessibilityservice.AccessibilityService.dispatchGesture)?",
        "rules": ["method:android.accessibilityservice.AccessibilityService->dispatchGesture"],
    },
    "send_sms": {
        "intent": "Which of these APKs send SMS from code (calls to android.telephony.SmsManager.sendTextMessage)?",
        "rules": ["method:android.telephony.SmsManager->sendTextMessage"],
    },
    "screen_capture": {
        "intent": "Which of these APKs request screen capture (calls to android.media.projection.MediaProjectionManager.createScreenCaptureIntent)?",
        "rules": ["method:android.media.projection.MediaProjectionManager->createScreenCaptureIntent"],
    },
}
