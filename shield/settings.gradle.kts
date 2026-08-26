// Standalone Gradle build: the Shield guard app is not part of the Python package
// and is not part of canary/. It is built by `shield/build.sh` and installed on the
// demo emulator by `scripts/demo_up.sh`.
pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "DrishtiShield"
include(":app")
