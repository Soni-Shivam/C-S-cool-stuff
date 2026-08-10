#!/usr/bin/env python3
"""DRISHTI M3 — real dynamic analysis harness.

RUN ONLY ON THE SEALED DETONATION VM. This script EXECUTES the sample.
Refuses to run unless containment is verified (no internet egress).

Per sample:
  1. verify containment          (abort if the box can reach the internet)
  2. restore the clean snapshot  (no cross-sample contamination)
  3. install the APK
  4. launch it with Frida hooks attached (scripts/frida_hooks.js)
  5. exercise the UI with monkey so time/interaction-gated payloads fire
  6. collect hooked API events + logcat + attempted network traffic
  7. restore the clean snapshot again
  8. write observations.json  (the ONLY artefact that leaves the box)

Usage:
    sudo /opt/drishti/venv/bin/python scripts/dynamic_analyze.py sample.apk \
        --out observations.json --duration 120
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HOOKS = Path(__file__).with_name("frida_hooks.js")
VERIFY = Path("/opt/drishti/verify_containment.sh")
SNAPSHOT = "clean"


def sh(cmd, timeout=120, check=False):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                          text=True, timeout=timeout, check=check)


def require_containment(force: bool) -> None:
    """Refuse to detonate anything on a box that can reach the internet."""
    if VERIFY.exists():
        r = sh([str(VERIFY)], timeout=90)
        print(r.stdout)
        if r.returncode != 0:
            sys.exit("ABORT: containment check failed. Malware must not have egress.")
        return
    # Fallback probe if the helper script is absent.
    reachable = sh("curl -s -m 5 -o /dev/null https://example.com").returncode == 0
    if reachable and not force:
        sys.exit("ABORT: this host can reach the internet. Seal egress before detonating.\n"
                 "       (--i-understand-the-risk overrides, but do not do that with real malware.)")


def adb(*args, timeout=120):
    return sh(["adb", *args], timeout=timeout)


def wait_for_device(timeout=300) -> None:
    adb("wait-for-device", timeout=timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if adb("shell", "getprop", "sys.boot_completed").stdout.strip() == "1":
            return
        time.sleep(3)
    raise TimeoutError("emulator did not finish booting")


def restore_snapshot() -> bool:
    r = sh(f'adb emu avd snapshot load {SNAPSHOT}')
    ok = r.returncode == 0 and "KO" not in (r.stdout or "")
    if not ok:
        print(f"  ! snapshot '{SNAPSHOT}' unavailable ({(r.stdout or '').strip()}); "
              f"continuing without restore", file=sys.stderr)
    return ok


def start_frida_server() -> None:
    adb("root", timeout=60)
    time.sleep(2)
    adb("push", "/opt/drishti/tools/frida-server", "/data/local/tmp/frida-server")
    adb("shell", "chmod", "755", "/data/local/tmp/frida-server")
    subprocess.Popen(["adb", "shell", "/data/local/tmp/frida-server", "&"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(4)


def package_name(apk: str) -> str:
    """Prefer aapt; fall back to Androguard so this works without build-tools."""
    r = sh(["aapt", "dump", "badging", apk], timeout=120)
    m = re.search(r"package: name='([^']+)'", r.stdout or "")
    if m:
        return m.group(1)
    try:
        from androguard.core.apk import APK
        return APK(apk).get_package()
    except Exception as e:  # noqa: BLE001
        sys.exit(f"could not determine package name for {apk}: {e}")


def collect_frida(pkg: str, duration: int) -> tuple[list[dict], list[str]]:
    """Spawn the app under Frida, stream hook events for `duration` seconds."""
    import frida

    events: list[dict] = []
    errors: list[str] = []

    def on_message(message, data):
        if message.get("type") == "send":
            p = message.get("payload", {})
            if p.get("type") == "observation":
                events.append(p)
            elif p.get("type") == "hook_error":
                errors.append(f"{p.get('hook')}: {p.get('error')}")
        elif message.get("type") == "error":
            errors.append(str(message.get("description")))

    device = frida.get_usb_device(timeout=30)
    pid = device.spawn([pkg])
    session = device.attach(pid)
    script = session.create_script(HOOKS.read_text())
    script.on("message", on_message)
    script.load()
    device.resume(pid)

    # Exercise the UI so interaction/time-gated payloads have a chance to fire.
    subprocess.Popen(["adb", "shell", "monkey", "-p", pkg, "--throttle", "300",
                      "--ignore-crashes", "--ignore-timeouts", "-v", "600"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(duration)

    try:
        session.detach()
    except Exception:  # noqa: BLE001
        pass
    return events, errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("--out", default="observations.json")
    ap.add_argument("--duration", type=int, default=120, help="seconds to observe")
    ap.add_argument("--i-understand-the-risk", action="store_true", dest="force",
                    help="skip the egress abort (never use with real malware)")
    args = ap.parse_args()

    if not shutil.which("adb"):
        sys.exit("adb not found — run this on the detonator VM")
    if not HOOKS.exists():
        sys.exit(f"missing hook script: {HOOKS}")

    print("== containment check ==")
    require_containment(args.force)

    print("== preparing device ==")
    wait_for_device()
    snapshot_ok = restore_snapshot()
    start_frida_server()

    pkg = package_name(args.apk)
    print(f"== installing {pkg} ==")
    r = adb("install", "-r", "-g", args.apk, timeout=300)   # -g: grant perms so behaviour unrolls
    if "Success" not in (r.stdout or ""):
        print(f"  ! install issue: {(r.stdout or r.stderr).strip()[:300]}", file=sys.stderr)

    adb("logcat", "-c")
    print(f"== detonating for {args.duration}s ==")
    t0 = time.time()
    try:
        events, hook_errors = collect_frida(pkg, args.duration)
    except Exception as e:  # noqa: BLE001
        print(f"  ! frida session failed: {type(e).__name__}: {e}", file=sys.stderr)
        events, hook_errors = [], [f"{type(e).__name__}: {e}"]
    elapsed = round(time.time() - t0, 1)

    logcat = adb("logcat", "-d", "-t", "2000", timeout=120).stdout or ""

    print("== restoring clean state ==")
    adb("uninstall", pkg, timeout=120)
    if snapshot_ok:
        restore_snapshot()

    result = {
        "package": pkg,
        "apk": os.path.basename(args.apk),
        "duration_s": elapsed,
        "simulated": False,                       # THIS IS REAL EXECUTION
        "observation_count": len(events),
        "observations": events,
        "mitre_observed": sorted({e["mitre"] for e in events if e.get("mitre")}),
        "hook_errors": hook_errors,
        "logcat_tail": logcat[-20000:],
    }
    Path(args.out).write_text(json.dumps(result, indent=2))
    print(f"\nwrote {args.out}: {len(events)} observations, "
          f"MITRE={result['mitre_observed']}")
    print("Only this JSON should leave the box. The APK stays here.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
