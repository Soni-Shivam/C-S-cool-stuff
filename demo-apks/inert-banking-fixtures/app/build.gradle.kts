plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "in.drishti.fixture.bank"
    compileSdk = 35
    defaultConfig { applicationId = "in.drishti.fixture.bank"; minSdk = 26; targetSdk = 35; versionCode = 1; versionName = "1.0" }
    flavorDimensions += "identity"
    productFlavors {
        create("bankOne") { dimension = "identity"; applicationIdSuffix = ".one"; resValue("string", "app_name", "Inert Bank One") }
        create("bankTwo") { dimension = "identity"; applicationIdSuffix = ".two"; resValue("string", "app_name", "Inert Bank Two") }
    }
}
