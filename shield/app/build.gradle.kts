plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android {
    namespace = "in.drishti.shield"
    compileSdk = 34

    defaultConfig {
        applicationId = "in.drishti.shield"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    // The demo installs a debug build. A release build would need a signing config
    // we do not want to keep on a laptop, and nothing about the demo depends on it.
    buildTypes {
        getByName("debug") { isMinifyEnabled = false }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

// Deliberately dependency-free beyond the Android framework. Views are built in
// Kotlin, HTTP is HttpURLConnection, JSON is org.json — all in the platform. One
// less resolution step to fail at hour 71, and the APK stays under 400 KB.
dependencies { }
