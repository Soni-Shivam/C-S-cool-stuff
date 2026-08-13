plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "in.drishti.canary"
    compileSdk = 35
    defaultConfig {
        applicationId = "in.drishti.canary"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }
}
