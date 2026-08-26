plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android {
    namespace = "in.drishti.benign.sanchay"
    compileSdk = 34

    defaultConfig {
        // A plausible consumer-app application id, for the same reason the decoy uses
        // com.rto.echallan.verify: the analysis pipeline must see the shape of a real
        // third-party app, not something with "drishti" written on it. The namespace
        // above keeps the source unambiguously ours.
        applicationId = "in.co.sanchay.expenses"
        minSdk = 26
        targetSdk = 34
        versionCode = 41
        versionName = "2.4.1"
    }

    buildTypes { getByName("debug") { isMinifyEnabled = false } }

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

dependencies { }
