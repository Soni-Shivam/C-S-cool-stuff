# Shady Demo — inert fixture

This project builds a harmless APK whose manifest declares a small set of suspicious permissions so DRISHTI's static rules have visible evidence. The app displays one local text screen. It contains no network permission and no code that reads SMS or contacts, draws overlays, installs packages, captures credentials, uses accessibility, or communicates with a server.

Use this fixture—not real malware—on a physical demonstration phone. Never install malware or an unknown third-party APK on that phone. Build output (`*.apk`) is ignored and must not be committed.
