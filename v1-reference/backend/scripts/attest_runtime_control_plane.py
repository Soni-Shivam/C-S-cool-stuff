#!/usr/bin/env python3
"""Create the operator-signed control-plane half of M3 containment."""
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from drishti.sandbox.containment import sign_control_plane_attestation


def gcloud(*args: str):
    result = subprocess.run(["gcloud", *args, "--format=json"], capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != 0:
        raise SystemExit("gcloud inspection failed: " + result.stderr[:300])
    return json.loads(result.stdout or "null")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--zone", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    instance = gcloud("compute", "instances", "describe", args.instance, "--project", args.project, "--zone", args.zone)
    routers = gcloud("compute", "routers", "list", "--project", args.project, "--filter", f"network:{args.network}") or []
    nat_absent = True
    for router in routers:
        region = str(router.get("region", "")).rsplit("/", 1)[-1]
        detail = gcloud("compute", "routers", "describe", router["name"], "--project", args.project, "--region", region)
        nat_absent = nat_absent and not detail.get("nats")
    access = [config for interface in instance.get("networkInterfaces", []) for config in interface.get("accessConfigs", [])]
    checks = {
        "external_ip_absent": not access,
        "cloud_nat_absent": nat_absent,
        "service_account_absent": not instance.get("serviceAccounts"),
        "machine_type_n2_standard_4": str(instance.get("machineType", "")).endswith("/n2-standard-4"),
        "nested_virtualization_enabled": bool(instance.get("advancedMachineFeatures", {}).get("enableNestedVirtualization")),
        "detonator_tag_present": "detonator" in instance.get("tags", {}).get("items", []),
        "disposable_disk": bool(instance.get("disks")) and all(disk.get("autoDelete") for disk in instance.get("disks", [])),
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise SystemExit("control-plane containment failed: " + ", ".join(failed))
    now = datetime.now(timezone.utc)
    attestation = sign_control_plane_attestation({
        "instance_id": str(instance["id"]), "runtime_image": args.runtime_image,
        "issued_at": now, "expires_at": now + timedelta(minutes=15), "checks": checks,
    }, args.signing_key.read_text().strip())
    args.out.write_text(attestation.model_dump_json(indent=2))
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
