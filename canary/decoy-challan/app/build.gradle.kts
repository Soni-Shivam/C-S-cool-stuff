plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android {
    namespace = "in.drishti.decoy.rtochallan"
    compileSdk = 34

    defaultConfig {
        // Deliberately NOT an in.drishti.* application id: the point of the decoy is
        // that the analysis pipeline sees something shaped like the real challan-fraud
        // family. The namespace above keeps the source unambiguously ours.
        applicationId = "com.rto.echallan.verify"
        minSdk = 26
        targetSdk = 34
        versionCode = 3
        versionName = "3.1.4"
    }

    // No minification, no shrinking, no obfuscation. An obfuscated decoy would be a
    // packing exercise, and CLAUDE.md forbids writing one.
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
