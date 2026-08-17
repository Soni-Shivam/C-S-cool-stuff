plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    // namespace and applicationId deliberately differ.
    //
    // `in` is a RESERVED KEYWORD in Kotlin, so a source package of `in.drishti.canary`
    // cannot compile ("Package name must be a '.'-separated identifier list"). The
    // namespace is a Kotlin/Java identifier and must avoid it; the applicationId is only
    // a string, so the *installed* package keeps the `.in` identity that canary/README.md
    // and the frontier's PROBE_PACKAGE both reference.
    namespace = "drishti.canary"
    compileSdk = 35
    defaultConfig {
        applicationId = "in.drishti.canary"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    // AGP defaults Java to 1.8 while Kotlin picks up the toolchain JDK (17), and Gradle
    // refuses to build on the mismatch. Pinning both to 17 is what AGP 8.7 expects.
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
