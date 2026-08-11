# M3 inert dynamic fixture

This application is harmless and exists only to validate the sealed M3 harness. It:

- writes and reads the literal `DRISHTI_FIXTURE_ONLY` through the clipboard;
- encrypts the literal `fixture-dummy-text` with an in-memory dummy AES key;
- opens one connection to the emulator host's local fake C2 at `10.0.2.2:8080`;
- loads its own APK through `DexClassLoader` and resolves a harmless marker class; and
- reads non-sensitive `Build` properties.

It does not access real SMS, contacts, credentials, files, accounts, or remote internet
services. It must be uninstalled and removed from the clean snapshot before imaging.
Its APK build output is ignored by Git.
