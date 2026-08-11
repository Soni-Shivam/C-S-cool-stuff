# Inert banking-app fixtures

Two product flavors (`bankOne`, `bankTwo`) provide harmless foreground applications for
M3 environment morphing. They have no permissions, storage, network, login form, or user
data. Build them and rename the outputs to `bank-one.apk` and `bank-two.apk` only inside
the immutable-image builder input. APK outputs are ignored and never committed.
