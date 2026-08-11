# DRISHTI Android client

Kotlin/Compose companion for user-selected pre-install APK analysis. Requires JDK 17 and Android SDK 35; minSdk is 26. Open this directory in Android Studio or run the checked-in Gradle 8.9 wrapper with `./gradlew testDebugUnitTest assembleDebug`.

The only broad-looking permission is `REQUEST_INSTALL_PACKAGES`, required to hand a user-acknowledged APK to Android's normal installer and check `canRequestPackageInstalls()`. The app does not use `QUERY_ALL_PACKAGES`. Cleartext HTTP is enabled only for emulator/LAN demo setup; use HTTPS and a network-security policy for deployment.
