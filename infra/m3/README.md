# M3 builder and sealed runtime

These files describe the M3-B/M3-C infrastructure. They are intentionally not part of
the backend API and are never invoked by tests or `docker compose`.

## Safety order

1. Build the inert fixture locally; never provide a malware path to the image builder.
2. Run `build_tools_image.sh`. Its temporary builder permits DNS and HTTPS only and is
   deleted by Packer; a shell trap removes both builder firewall rules on every exit.
3. Finish Phase A with `phase_a_teardown.sh`: upload only `features.csv`, delete the
   extractor, and delete Cloud NAT. The script verifies both resources are gone.
4. Apply `terraform/runtime`. It creates one `n2-standard-4` runtime from the immutable
   image with nested virtualization, no external IP, no service account, an auto-deleted
   disk, IAP-only SSH ingress, and a target-tagged deny-all egress rule.
5. Through IAP, boot the emulator, run `verify_containment.py`, and create the signed
   short-lived manifest. `dynamic_analyze.py` refuses missing, invalid, or stale manifests.

All mutation scripts require `DRISHTI_APPLY=YES`. Review `M3_RUNBOOK.md` before use.
