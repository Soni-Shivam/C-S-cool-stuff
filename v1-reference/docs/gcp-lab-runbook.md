# DRISHTI on Google Cloud — Malware Lab + Product Runbook

Two entirely separate concerns. Do not mix them in one project.

1. **The Lab** — an isolated, disposable GCP project where real malware is handled.
   Produces: a trained model + real evaluation metrics for the paper.
2. **The Product** — the deployed DRISHTI service (API + dashboard) that consumes the
   trained model. Handles user-uploaded APKs safely. Never runs malware.

---

## Part 0 — Ground rules (non-negotiable)

- **A dedicated GCP project** for the lab. It is the blast radius and the kill switch
  (`gcloud projects delete`). Never the project your product or personal data lives in.
- **Malware never touches your laptop.** Only feature CSVs and metrics leave the lab.
- **Never execute an APK on the extraction box.** Static parsing only.
- **The detonation box has zero egress.** Malware that can reach the internet makes you
  the operator of an attack platform — that is both an AUP violation (account suspension)
  and potentially unlawful. Blackhole all outbound traffic.
- **No powerful service accounts on lab VMs.** If the box is compromised it must have
  nothing worth stealing. One narrowly-scoped SA that can only write to one bucket.
- **Research datasets (AndroZoo, CICMalDroid, Drebin) are used under their licence terms.**
  AndroZoo access is granted per-researcher; do not redistribute samples.
- Treat every lab disk as contaminated. Rebuild between batches; do not reuse for anything else.

---

## Part 1 — The Lab

### 1.1 Create the isolated project

```bash
export LAB_PROJECT="drishti-lab-$RANDOM"
export REGION="asia-south1"          # Mumbai; pick your nearest
export ZONE="${REGION}-a"

gcloud projects create "$LAB_PROJECT" --name="DRISHTI Malware Lab"
# link billing (get your account id from: gcloud billing accounts list)
gcloud billing projects link "$LAB_PROJECT" --billing-account=XXXXXX-XXXXXX-XXXXXX
gcloud config set project "$LAB_PROJECT"

gcloud services enable compute.googleapis.com storage.googleapis.com \
    iap.googleapis.com secretmanager.googleapis.com
```

### 1.2 Network: isolated VPC, no public IPs, SSH via IAP

```bash
gcloud compute networks create drishti-lab --subnet-mode=custom

gcloud compute networks subnets create lab-subnet \
    --network=drishti-lab --region="$REGION" --range=10.10.0.0/24 \
    --enable-private-ip-google-access          # reach GCS without a public IP

# SSH only from Google's IAP range — no public IP, no open port 22 to the world
gcloud compute firewall-rules create allow-ssh-from-iap \
    --network=drishti-lab --direction=INGRESS --action=ALLOW \
    --rules=tcp:22 --source-ranges=35.235.240.0/20

# Deny ALL other ingress explicitly (defence in depth)
gcloud compute firewall-rules create deny-all-ingress \
    --network=drishti-lab --direction=INGRESS --action=DENY \
    --rules=all --source-ranges=0.0.0.0/0 --priority=65533
```

**Egress — this is where the two boxes diverge.**

```bash
# Baseline: deny all egress (low priority so specific allows win)
gcloud compute firewall-rules create deny-all-egress \
    --network=drishti-lab --direction=EGRESS --action=DENY \
    --rules=all --destination-ranges=0.0.0.0/0 --priority=65534

# EXTRACTOR ONLY (tag: extractor): allow outbound HTTPS to fetch APKs + packages.
# Note: AndroZoo's IP is not stable, so this is port-scoped rather than IP-pinned.
# Acceptable because this box never EXECUTES a sample.
gcloud compute firewall-rules create allow-https-egress-extractor \
    --network=drishti-lab --direction=EGRESS --action=ALLOW \
    --rules=tcp:443 --destination-ranges=0.0.0.0/0 \
    --target-tags=extractor --priority=1000

# DETONATOR (tag: detonator): NO allow rule. It inherits deny-all-egress.
# Samples are pre-staged from GCS via Private Google Access before the deny takes effect,
# or staged at image-build time. Malware gets a black hole.
```

Because there is **no external IP and no Cloud NAT**, egress also requires Cloud NAT to
work at all. Create NAT only for the extractor, and delete it when the batch finishes:

```bash
gcloud compute routers create lab-router --network=drishti-lab --region="$REGION"
gcloud compute routers nats create lab-nat --router=lab-router --region="$REGION" \
    --nat-all-subnet-ip-ranges --auto-allocate-nat-external-ip
# When extraction is done:  gcloud compute routers nats delete lab-nat --router=lab-router --region=$REGION
```

### 1.3 Output bucket + least-privilege service account

```bash
export OUT_BUCKET="gs://${LAB_PROJECT}-features"
gcloud storage buckets create "$OUT_BUCKET" --location="$REGION" \
    --uniform-bucket-level-access --public-access-prevention

gcloud iam service-accounts create drishti-lab-vm --display-name="DRISHTI lab VM"
export LAB_SA="drishti-lab-vm@${LAB_PROJECT}.iam.gserviceaccount.com"

# ONLY write objects to the one output bucket. No project-wide roles.
gcloud storage buckets add-iam-policy-binding "$OUT_BUCKET" \
    --member="serviceAccount:${LAB_SA}" --role="roles/storage.objectCreator"
```

### 1.4 Store the AndroZoo key in Secret Manager (not in the VM image)

```bash
printf '%s' "YOUR_ANDROZOO_KEY" | gcloud secrets create androzoo-key --data-file=-
gcloud secrets add-iam-policy-binding androzoo-key \
    --member="serviceAccount:${LAB_SA}" --role="roles/secretmanager.secretAccessor"
```

### 1.5 Box A — the Extractor (static features; safe)

```bash
gcloud compute instances create drishti-extractor \
    --zone="$ZONE" --machine-type=e2-standard-2 \
    --subnet=lab-subnet --no-address \
    --image-family=debian-12 --image-project=debian-cloud \
    --boot-disk-size=50GB --boot-disk-type=pd-balanced \
    --service-account="$LAB_SA" \
    --scopes=https://www.googleapis.com/auth/cloud-platform \
    --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
    --tags=extractor \
    --provisioning-model=SPOT --instance-termination-action=DELETE \
    --metadata-from-file=startup-script=backend/scripts/gcp/extractor_startup.sh \
    --metadata=out-bucket="$OUT_BUCKET"

# connect (no public IP — tunnelled through IAP)
gcloud compute ssh drishti-extractor --zone="$ZONE" --tunnel-through-iap
```

`e2-standard-2` = 2 vCPU / **8 GB**. The 8 GB matters: Androguard peaks ~400–460 MB on a
12 MB APK and several GB on large packed multi-DEX samples. 2 GB would OOM on exactly the
interesting malware.

**Run the extraction** (see `backend/scripts/androzoo_extract.py`):

```bash
export ANDROZOO_API_KEY=$(gcloud secrets versions access latest --secret=androzoo-key)
python scripts/androzoo_extract.py samples.csv features.csv
gcloud storage cp features.csv "$OUT_BUCKET/features_$(date +%F).csv"
```

Each APK is downloaded, parsed, and **deleted immediately**. Only `features.csv` leaves.

Then **delete the box and the NAT**:
```bash
gcloud compute instances delete drishti-extractor --zone="$ZONE" --quiet
gcloud compute routers nats delete lab-nat --router=lab-router --region="$REGION" --quiet
```

### 1.6 Box B — the Detonator (real dynamic analysis; Phase 2, optional)

Only build this if you want real M3 behaviour instead of the current simulation.

```bash
gcloud compute instances create drishti-detonator \
    --zone="$ZONE" --machine-type=n2-standard-4 \
    --enable-nested-virtualization \
    --subnet=lab-subnet --no-address \
    --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud \
    --boot-disk-size=100GB \
    --service-account="$LAB_SA" --scopes=https://www.googleapis.com/auth/cloud-platform \
    --shielded-secure-boot --shielded-vtpm \
    --tags=detonator \
    --provisioning-model=SPOT --instance-termination-action=DELETE
```

Inside it:

| Component | Purpose |
|---|---|
| Android SDK cmdline-tools + `system-images;android-30;google_apis;x86_64` | the victim device |
| `emulator -avd drishti -no-window -no-audio -writable-system` | headless AVD (KVM works via nested virt) |
| **Frida server** pushed to the AVD | API hooking / SSL unpinning (paper §4.3) |
| **mitmproxy** as the AVD's proxy | TLS interception; also plays the **fake C2** |
| `iptables` DROP on all egress + a local sinkhole | malware's real C2 is unreachable; mitmproxy answers instead |
| `avd snapshot` save/load | restore to clean state between samples |

Workflow: stage APKs from GCS → boot snapshot → install → Frida-hook → run N minutes →
collect API traces + captured traffic → **restore snapshot** → next sample. Feed the
observations into `drishti/sandbox/` as *real* `dynamic_obs` nodes replacing the simulated ones.

Verify nested virt is actually on:
```bash
grep -cw vmx /proc/cpuinfo      # must be > 0
```

### 1.7 Teardown (do this every time)

```bash
gcloud projects delete "$LAB_PROJECT"    # nukes everything
```

---

## Part 2 — The Product (deployed DRISHTI)

Separate GCP project. **Never** runs malware; it analyses statically and reasons with Gemini.

```
Browser (Next.js dashboard on Cloud Run)
        │  upload APK
        ▼
FastAPI web tier (Cloud Run) ──► quarantine bucket (GCS, no public access)
        │  enqueue analysis job
        ▼
Cloud Tasks / Pub-Sub
        ▼
Analysis worker (Cloud Run job, own service account, gVisor-isolated container)
   M1 ingest → M2 static → M5 model (from GCS) → M4 Gemini → M6 score → M7 report
        │
        ├──► Firestore / Cloud SQL   : verdicts + evidence ledger (append-only)
        └──► Secret Manager          : GEMINI_API_KEY (never in env files or images)
```

Key production decisions:

| Concern | Choice |
|---|---|
| Hosting | **Cloud Run** — containers, scales to zero, no VM babysitting. Backend + frontend as two services. |
| Why a separate worker | The web tier must never parse untrusted APK bytes in the request path. Isolate the parser; if Androguard is exploited it is in a throwaway container with no privileges. |
| Uploaded APKs | Quarantine bucket, `public-access-prevention`, lifecycle rule to auto-delete after N days. **Never served back to any client.** |
| Secrets | **Secret Manager**, injected at runtime. Replace the current `.env` before anything is public. |
| Gemini | Current API key works. For production, consider **Vertex AI Gemini** (same models, IAM auth, no long-lived key, data-residency controls). |
| Model artifact | Trained `.joblib` in GCS, versioned; worker loads at cold start. |
| Ledger | Append-only table; keep the Ed25519 signature per analysis so verdicts stay independently verifiable. |
| Abuse control | Auth on upload (Firebase Auth / IAP), rate limits, max file size. An open "upload any APK" endpoint will be abused as free malware storage. |
| Cost | Cloud Run scales to zero → near-$0 idle. Fine for a demo and honest for a pitch. |

---

## Part 3 — Order of work (what actually matters for the competition)

1. **Build the balanced AndroZoo sample list** (`scripts/build_sample_list.py`) — includes a
   **time split** (train on pre-cutoff samples, test on newer families) so you can report the
   paper's §9.1 "time-split generalisation" honestly.
2. **Run Box A once** (~1–3k samples, well under an hour, a few cents) → `features.csv`.
3. **Retrain** with `train_from_dataframe()` → replace the synthetic baseline → **report real
   precision / recall / PR-AUC**. This is the single biggest credibility upgrade available;
   the paper's Table 9 currently says "projected".
4. **Build M7 + FastAPI + dashboard** → the clickable demo.
5. **Deploy to Cloud Run** → a live URL for judges.
6. Box B / real dynamic analysis → genuine Phase 2. Label it as future work if time runs out.

Steps 1–3 convert DRISHTI from "architecture with a synthetic placeholder" into "system with
measured results on real malware". Everything else is presentation.
