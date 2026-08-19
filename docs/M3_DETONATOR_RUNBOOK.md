# M3 detonator VM — runbook

The sealed VM is the **only** place a real APK is ever executed. Everything here
runs against live GCP and costs money. `make lab-down` is the last step of every
session, not an optional one.

Read this whole file before running step 1. Two things must be fixed first
(§0.3), and one decision (§0.2) is cheaper to get right than to undo.

---

## 0. Before you spend anything

### 0.1 State as of `92a6aea`

| Thing | State |
|---|---|
| `cybershield-505518` buckets (corpus/artifacts/models) | exist, **US-EAST1** |
| Detonator VM | does **not** exist |
| `drishti-runtime` VPC | does **not** exist (only `default`) |
| `drishti-m3-tools-*` image | does **not** exist |
| Extractor VM `instance-20260817-080247` | **RUNNING**, n2-standard-8, ~$0.39/hr |

Stop the extractor first if its batch is finished — it is the larger bill:

```bash
gcloud compute instances stop instance-20260817-080247 --zone=us-east1-c --project=internship-505513
```

### 0.2 Region — change `.env` before you build

`.env` currently says `DRISHTI_GCP_ZONE=asia-south1-a`, which is CLAUDE.md's
default. **The buckets are in US-EAST1.** Building the lab in asia-south1 means
every corpus read and every artifact write crosses a continent at egress rates.

Set this in `.env` and keep it consistent everywhere below:

```bash
DRISHTI_GCP_ZONE=us-east1-c
```

N2 supports nested virtualisation in us-east1-c, so nothing is lost. This is
already recorded as a deviation in `STATUS.md` for the same reason (the
extractor lives there).

### 0.3 Two blockers you must clear first

**(a) The Packer template points at files that do not exist.**
`infra/gcp/packer/detonator.pkr.hcl` lines 37–40 provision from
`backend/scripts/` — v1 paths. In this repo those are:

| Packer expects | Actually at |
|---|---|
| `backend/scripts/frida_hooks.js` | `drishti/m3_dynamic/scripts/hooks.js` |
| `backend/scripts/verify_containment.py` | **not written** — logic is in `drishti/m3_dynamic/containment.py`, no CLI entrypoint |
| `backend/scripts/emulator_control.sh` | `infra/gcp/emulator_control.sh` |
| `backend/scripts/dynamic_analyze.py` | **not written** — this is `frida_runner.py`, still unbuilt |

Two of the four do not exist in any form. `packer build` will fail at the file
provisioner, before it spends a minute of VM time — so this is a cheap failure,
not a dangerous one, but it *will* fail.

**(b) `runtime_prepare.sh` calls `/opt/drishti/harness/verify_containment.py`
and `/opt/drishti/fake_c2.py`.** Both come out of the image build, so they
inherit (a).

**What this means:** the image build is blocked on writing the two missing
harness scripts. Steps 1–6 below are correct and complete for the moment they
exist; do not run step 2 until they do.

### 0.4 Prerequisites on your laptop

```bash
gcloud --version && packer version && terraform version
```

```bash
gcloud auth login && gcloud auth application-default login
gcloud config set project cybershield-505518
```

`gcloud auth list` must agree with `gcloud config get account`. A configured
account with no credentials produces an error that reads exactly like a missing
IAM role — this has cost hours before.

---

## 1. Networks

Two VPCs, and the difference between them is the entire safety property.

```bash
export DRISHTI_GCP_PROJECT=cybershield-505518
export DRISHTI_GCP_ZONE=us-east1-c
export DRISHTI_GCP_REGION=us-east1
```

`drishti-build` has Cloud NAT — the image build needs apt and GitHub.
`drishti-runtime` has **no NAT and default-deny egress** — the detonator lives
there and can reach nothing.

```bash
gcloud compute networks create drishti-build --subnet-mode=auto
gcloud compute routers create drishti-build-router --network=drishti-build --region=us-east1
gcloud compute routers nats create drishti-build-nat \
  --router=drishti-build-router --region=us-east1 \
  --auto-allocate-nat-external-ip --nat-all-subnet-ip-ranges
```

```bash
gcloud compute networks create drishti-runtime --subnet-mode=auto
```

Do **not** create a NAT on `drishti-runtime`. If a runtime tool needs apt, bake
it into the image instead — that is what the Packer build is for.

---

## 2. Build the image  *(blocked — see §0.3)*

Runs on `drishti-build`, ~15–25 min, ~$0.15.

```bash
cd infra/gcp/packer
packer init detonator.pkr.hcl
packer build \
  -var "project=cybershield-505518" \
  -var "zone=us-east1-c" \
  -var "network=drishti-build" \
  detonator.pkr.hcl
```

`builder_setup.sh` encodes five fixes that each cost real hours. Do not
"simplify" them:

- **frida pinned `<17`.** Ubuntu 22.04 ships Python 3.10; frida ≥17 imports
  `typing.NotRequired`, so `import frida` raises and the whole collector dies —
  not just a version probe.
- **frida-server version comes from the importable module**, never from the
  `frida` CLI, and `curl --location` because release assets redirect. Getting
  this wrong ships an image with no frida-server and a 404 nobody notices until
  detonation.
- **`libxkbfile1` is in the apt list on purpose.** Without it
  `qemu-system-x86_64` will not start even with `-no-window`.
- **Verify the emulator with `emulator -version`, never `ldd`.** Qt resolves via
  RPATH out of `$SDK/emulator/lib64`; `ldd` reports false "not found".
- **No `-writable-system`.** `adb remount` claims success while `/system` stays
  read-only, and `adb reboot` can wedge the guest `offline` permanently.

Record the resulting image name — step 3 needs it:

```bash
gcloud compute images list --no-standard-images --format='value(name)'
```

---

## 3. Create the VM

```bash
cd infra/gcp/terraform/runtime
terraform init
terraform apply \
  -var "project=cybershield-505518" \
  -var "zone=us-east1-c" \
  -var "region=us-east1" \
  -var "network=drishti-runtime" \
  -var "subnetwork=drishti-runtime" \
  -var "runtime_image=drishti-m3-tools-<timestamp>"
```

This creates the deny-all-egress rule, the IAP-SSH allow, and the instance with
`enable_nested_virtualization = true`. **Read the plan before approving** — in
particular confirm no `access_config` block, i.e. no external IP.

Then confirm containment is structural, not aspirational:

```bash
terraform output runtime_has_external_ip   # must be false
```

---

## 4. Per-session lifecycle

```bash
make lab-status
```

```bash
make lab-up
```

Then, over IAP, prepare the runtime (iptables lockdown, fake C2, emulator):

```bash
gcloud compute ssh drishti-detonator --zone=us-east1-c --tunnel-through-iap \
  --command='sudo /opt/drishti/runtime_prepare.sh'
```

There are **no SSH keys in the image and no external IP** — IAP is the only way
in. If it hangs, the IAP firewall rule (`35.235.240.0/20`) is what to check.

---

## 5. Verify containment — never skip

```bash
make lab-verify
```

This is a gate, not a report. It aborts the batch on failure and never
downgrades to a warning. What it proves, and why each half exists:

- **Negative control** (`127.0.0.1:1`, must read unreachable) and **positive
  control** (a listener it starts, must read reachable) run *before* any verdict
  is believed. v1 shipped a probe using `nc -z` — a flag toybox does not have —
  so it exited 1 unconditionally and **every containment check passed regardless
  of the real network state**. A signed manifest attested containment that had
  never been tested.
- **A timeout is blocked, not unknown.** A blackhole `-j DROP` makes the probe
  hang past its deadline; rc 124 reads as blocked. Unhandled, this turned
  verification into a coin flip on DNS cache state.
- Then the real check: `169.254.169.254:80` (metadata), `8.8.8.8:53`,
  `1.1.1.1:443`, `10.0.0.1:22` must all be unreachable from inside the guest.

The probe's output is what the attestation manifest signs. If the probe did not
run, the manifest says so — and so does the report.

---

## 6. Detonate

Samples move GCS → VM scratch. They are never copied to a laptop.

```bash
gcloud compute ssh drishti-detonator --zone=us-east1-c --tunnel-through-iap
```

On the VM:

```bash
sudo /opt/drishti/venv/bin/python /opt/drishti/harness/dynamic_analyze.py \
  --sample gs://cybershield-505518-corpus/<sha256>.apk \
  --duration 120 --out /opt/drishti/results/
```

For a batch, **read the sample list on FD 3**:

```bash
while read -u 3 sha; do dynamic_analyze.py --sample "$sha"; done 3< samples.txt
```

`dynamic_analyze.py` consumes stdin. A naive `while read` loop silently stops
after one sample and looks exactly like a data problem.

Record per run: sample sha256, image version, VM instance id, containment
manifest. The UI's live-vs-replay badge is derived from those, read from the
trace — never from a config flag.

---

## 7. Shut down — every time

```bash
make lab-down
```

```bash
gcloud compute instances list --project=cybershield-505518
```

A forgotten nested-virt VM is the single easiest way to burn the budget. Never
move the emulator to a preemptible/Spot VM: a mid-detonation preemption loses
the trace and leaves the AVD dirty.

**Full teardown**, when the hackathon is over:

```bash
bash infra/gcp/lab.sh teardown
```

---

## Cost

| Item | Rate | Typical |
|---|---|---|
| Image build (n2-standard-4, one-off) | ~$0.19/hr | ~$0.08 |
| Detonator running | ~$0.19/hr | pay only while detonating |
| Detonator stopped (disk only) | ~$0.01/hr | negligible |
| Image storage | ~$0.05/GB/mo | ~$0.50 |

A full session — build, ten detonations, shut down — is a few dollars. Leaving
the VM up for a weekend is not.

## What is still unbuilt

`emulator.py`, `frida_runner.py`, snapshot/crash self-repair, mitmproxy/TLS
interception, and the morph scripts. `hooks.js` exists and is statically audited
in CI, but **has never been executed**.

HTTPS interception is deliberately deferred: the `Cipher.doFinal` hook already
yields plaintext *before* encryption, which is the stronger result and also
defeats T1521 custom crypto. Do not block M3 on installing a system CA.
