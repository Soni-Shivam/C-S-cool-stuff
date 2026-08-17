"""Compile-time invariants for the one inert APK we author ourselves."""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_manifest_theme_is_declared_in_resources() -> None:
    """The canary must remain buildable without discovering a missing resource live."""
    manifest = ElementTree.parse(REPO_ROOT / "canary/app/src/main/AndroidManifest.xml").getroot()
    android = "{http://schemas.android.com/apk/res/android}"
    application = manifest.find("application")
    assert application is not None
    theme = application.get(android + "theme")
    assert theme is not None and theme.startswith("@style/")

    declared = set(
        re.findall(
            r'<style\s+name="([A-Za-z0-9_]+)"',
            (REPO_ROOT / "canary/app/src/main/res/values/styles.xml").read_text(),
        )
    )
    assert theme.removeprefix("@style/") in declared


def test_kotlin_and_java_targets_match_jdk_17() -> None:
    """AGP rejects mixed 1.8 Java and 17 Kotlin bytecode targets."""
    build = (REPO_ROOT / "canary/app/build.gradle.kts").read_text(encoding="utf-8")
    assert "sourceCompatibility = JavaVersion.VERSION_17" in build
    assert "targetCompatibility = JavaVersion.VERSION_17" in build
    assert "JvmTarget.JVM_17" in build


def test_kotlin_package_escapes_the_in_keyword() -> None:
    """The Android namespace is valid, but Kotlin requires `in` to be escaped."""
    source = (REPO_ROOT / "canary/app/src/main/java/in/drishti/canary/MainActivity.kt").read_text(
        encoding="utf-8"
    )
    assert source.startswith("package `in`.drishti.canary\n")
