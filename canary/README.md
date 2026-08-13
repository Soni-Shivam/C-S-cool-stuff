# canary — the one APK we author ourselves

**This app is deliberately inert.** It is the only application source in this repository,
and its purpose is to prove the JIT-morphing loop fires without involving a real sample.

## The boundary, verbatim from `docs/00_GUIDING_MAP.md` §4

> The one APK we author ourselves is `canary/` — a deliberately **inert** test target. Its
> entire behaviour is: query `PackageManager` for a package name, read `SmsManager` inbox
> count, attempt one HTTP GET to a configured host, and write `Log.i("CANARY", ...)` lines.
> It has **no** capability to harm a device or a user. It exists only to prove the
> JIT-morphing loop fires.

`app/src/main/java/in/drishti/canary/MainActivity.kt` implements exactly those four
behaviours and nothing else. `CLAUDE.md`: *"If a task asks to extend `canary/` beyond that,
stop and ask."*

## What it does, and what it refuses to do

| Does | Does **not** |
|---|---|
| Queries `PackageManager` for `in.drishti.canary.absent.target` | Send or forward SMS |
| Reads the SMS inbox **row count** (id column only) | Read any message body, address, or contact |
| One HTTP GET to `http://10.0.2.2:8080/canary` | Contact any routable address |
| Writes `Log.i("CANARY", …)` | Draw overlays, run an accessibility service, load code dynamically, touch the clipboard, capture credentials |

`10.0.2.2` is the emulator's alias for its own host loopback. It cannot reach the internet
even if egress were open.

### Narrower than v1's fixture, on purpose

v1's `demo-apks/m3-inert-fixture` also exercised the clipboard, a `Cipher`, and
`DexClassLoader` on its own APK. Those are harmless in isolation, but they are not on §4's
list. The value of an exhaustively-stated boundary is that it can be audited by reading one
file, and every behaviour added past the list erodes that.

## Why the probe misses

`PROBE_PACKAGE` is `in.drishti.canary.absent.target`, which is not installed on a clean
emulator. So:

1. **Pass 1** — the probe MISSES. The canary logs it and does nothing further.
2. **Frontier** — the morph planner sees the `EVASION_CHECK`, derives an
   `install_packages` morph from it, and synthesises the package.
3. **Pass 2** — the same query HITS.

That transition is the demo's central beat (`00_GUIDING_MAP.md` §2, beats 4–5), and the
canary lets us rehearse it without a real sample.

## Building

Requires a JDK and the Android SDK.

```bash
cd canary && ./gradlew :app:assembleDebug
cp app/build/outputs/apk/debug/app-debug.apk dist/canary.apk
```

The built artifact is committed at **`canary/dist/canary.apk`** so the demo does not depend
on a local toolchain. That path matters: `.gitignore` blocks `*.apk` repo-wide and allowlists
only `canary/dist/*.apk`, because **git cannot re-include a file whose parent directory is
excluded** — an allowlist pointing inside Gradle's ignored `build/` directory can never fire.
`tests/contract/test_repo_invariants.py` guards both directions.

> **Not yet built.** There is no JDK on the current development machine, so `dist/` is
> empty and no genuinely parseable APK has been ingested by M1 yet — androguard's success
> path is exercised only by code, never by a test. Build this on a machine with a JDK, or on
> a GCE builder, and commit the artifact.
