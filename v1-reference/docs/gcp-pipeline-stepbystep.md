# DRISHTI — Step-by-Step Pipeline on Google Cloud

Budget assumed: ₹30,000. Realistic total spend for everything below: **under ₹2,000.**
Cost is not your constraint; time is. Prices are estimates — verify in the GCP calculator.

## The two pipelines (do not conflate them)

```
TRAINING PIPELINE  (batch · offline · in the isolated lab · runs occasionally)
  AndroZoo index ──► sample list ──► [LAB VM] download → extract features → delete APK
                                          │
                                          ├──► features.csv  ──► train + time-split eval
                                          └──► (optional) detonate → real dynamic traces
                                                                    │
                                                              model.joblib + metrics
                                                                    │
INFERENCE PIPELINE (realtime · online · in the product · runs per user upload)
  APK upload ──► M1 hash ──► M2 static ──► M5 model ──► M4 Gemini ──► M6 score ──► report
                                              ▲                            (seconds)
                                    loads model.joblib
```

The model is produced offline and *consumed* online. New samples do not update the model
live — they enter a review queue and are folded in at the next scheduled retrain. Live
per-sample learning is unstable and lets an attacker poison your classifier.

---

# PHASE A — Real static corpus + trained model
**Time: ~2 hours. Cost: ~₹200. Risk: low (nothing executes).**
This is the highest-value phase. Do it first. It converts the paper's "projected" Table 9
into measured numbers.

### A1. On your laptop — get the AndroZoo index (safe: metadata only, no APK bytes)
```bash
curl -O https://androzoo.uni.lu/static/lists/latest.csv     # ~4 GB
```

### A2. On your laptop — build a balanced, time-split sample list
```bash
cd backend
python scripts/build_sample_list.py ../latest.csv samples.csv \
    --per-class 1500 --cutoff 2023-01-01 --malware-min-vt 10
```
Produces 6,000 rows: {train,test} × {malware,benign} × 1500. Test samples are strictly
newer than train samples → measures generalisation, not memorisation.

### A3. Create the isolated lab project
```bash
export LAB_PROJECT="drishti-lab-$RANDOM"
export REGION="asia-south1"; export ZONE="${REGION}-a"

gcloud projects create "$LAB_PROJECT" --name="DRISHTI Malware Lab"
gcloud billing accounts list                      # copy your billing account id
gcloud billing projects link "$LAB_PROJECT" --billing-account=XXXXXX-XXXXXX-XXXXXX
gcloud config set project "$LAB_PROJECT"
gcloud services enable compute.googleapis.com storage.googleapis.com \
    iap.googleapis.com secretmanager.googleapis.com
```

### A4. Network + bucket + least-privilege identity
Run every command in `docs/gcp-lab-runbook.md` §1.2–1.4. Summary of what it builds:
isolated VPC, **no public IPs**, SSH only via IAP, deny-all egress baseline with HTTPS
allowed *only* for the extractor tag, a write-only output bucket, and the AndroZoo key in
Secret Manager.

### A5. Launch the extractor (Spot, auto-deletes if preempted)
```bash
gcloud compute instances create drishti-extractor \
    --zone="$ZONE" --machine-type=e2-standard-2 \
    --subnet=lab-subnet --no-address \
    --image-family=debian-12 --image-project=debian-cloud \
    --boot-disk-size=50GB --service-account="$LAB_SA" \
    --scopes=https://www.googleapis.com/auth/cloud-platform \
    --shielded-secure-boot --shielded-vtpm --tags=extractor \
    --provisioning-model=SPOT --instance-termination-action=DELETE \
    --metadata-from-file=startup-script=backend/scripts/gcp/extractor_startup.sh \
    --metadata=out-bucket="$OUT_BUCKET"
```

### A6. Ship the code + sample list up, then extract
```bash
gcloud compute scp --recurse backend samples.csv drishti-extractor:~ \
    --zone="$ZONE" --tunnel-through-iap
gcloud compute ssh drishti-extractor --zone="$ZONE" --tunnel-through-iap

# on the VM:
export ANDROZOO_API_KEY=$(gcloud secrets versions access latest --secret=androzoo-key)
cd ~/backend
/opt/drishti/venv/bin/python scripts/androzoo_extract.py ~/samples.csv features.csv
gcloud storage cp features.csv "$OUT_BUCKET/"
```
~6,000 APKs at ~2–3 s each ≈ 3–5 hours. Checkpoints every 25 samples, so Spot preemption
costs almost nothing — just re-run the same command and it resumes.

### A7. Destroy the lab compute
```bash
gcloud compute instances delete drishti-extractor --zone="$ZONE" --quiet
gcloud compute routers nats delete lab-nat --router=lab-router --region="$REGION" --quiet
```

### A8. On your laptop — train on real data and get paper metrics
```bash
gcloud storage cp "$OUT_BUCKET/features.csv" .
python scripts/train_real.py features.csv \
    --save drishti/data/models/androzoo.joblib \
    --metrics-json ../docs/real_metrics.json
```
**Output = the numbers for the paper.** Expect precision ~0.85–0.95, not 1.0. If you see
1.0, something is leaking and you should be suspicious.

---

# PHASE B — Real dynamic analysis (the paper's M3)
**Time: 1–2 days. Cost: ~₹500. Risk: HIGH — this is where malware actually executes.**
Optional. Do it only after Phase A works. If time runs out, keep M3 labelled *simulated*
— that is already what the paper's roadmap says.

### B1. Why GCP makes this possible
GCP exposes **nested virtualization** on N1/N2/C2 (Intel Haswell+), so a normal VM can run
a KVM-accelerated x86 Android emulator. Not available on `e2` or ARM `t2a`. This is why the
detonation lab is affordable here and was not on non-metal AWS.

### B2. Launch the detonator — note: NO egress allow rule
```bash
gcloud compute instances create drishti-detonator \
    --zone="$ZONE" --machine-type=n2-standard-4 \
    --enable-nested-virtualization \
    --subnet=lab-subnet --no-address \
    --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud \
    --boot-disk-size=100GB --service-account="$LAB_SA" \
    --scopes=https://www.googleapis.com/auth/cloud-platform \
    --shielded-secure-boot --shielded-vtpm --tags=detonator \
    --provisioning-model=SPOT --instance-termination-action=DELETE \
    --metadata-from-file=startup-script=backend/scripts/gcp/detonator_setup.sh
```
It inherits `deny-all-egress`. **Malware on this box cannot reach the internet.** That is
mandatory, not optional: a sample that phones home makes you the operator of an attack
platform — grounds for account termination and potentially unlawful.

### B3. Verify containment BEFORE staging any sample
```bash
gcloud compute ssh drishti-detonator --zone="$ZONE" --tunnel-through-iap
grep -cw vmx /proc/cpuinfo          # must be > 0  → nested virt is live
curl -m 5 https://example.com       # must FAIL/timeout → egress is sealed
sudo /opt/drishti/verify_containment.sh
```
If `curl` succeeds, **stop**. Fix egress before continuing.

### B4. Stage samples and detonate
```bash
# staging happens over Private Google Access (internal), not the public internet
gcloud storage cp "gs://your-quarantine/sample.apk" /opt/drishti/samples/
sudo /opt/drishti/venv/bin/python scripts/dynamic_analyze.py \
    /opt/drishti/samples/sample.apk --out observations.json --duration 120
```
Per sample: restore clean snapshot → install → attach Frida hooks → exercise the UI →
capture logcat + hooked API calls + attempted network traffic (answered by a local fake C2)
→ restore snapshot. Only `observations.json` leaves the box.

### B5. Feed real observations back into DRISHTI
```bash
python -c "
from drishti.sandbox import load_real_observations
print(load_real_observations('observations.json'))"
```
This replaces the `[SIMULATED]` behaviours with real `dynamic_obs` evidence nodes, so `B`
in the risk score becomes measured rather than derived.

### B6. Destroy it
```bash
gcloud compute instances delete drishti-detonator --zone="$ZONE" --quiet
```
Treat the disk as contaminated. Never reuse it for anything else.

---

# PHASE C — Ship the product (the "instant report")
**Time: 1–2 days. Cost: ~₹0 idle (Cloud Run scales to zero).**

### C1. Separate project — never the lab project
```bash
gcloud projects create drishti-prod --name="DRISHTI"
gcloud config set project drishti-prod
gcloud services enable run.googleapis.com artifactregistry.googleapis.com \
    secretmanager.googleapis.com firestore.googleapis.com cloudtasks.googleapis.com
```

### C2. Secrets out of `.env` and into Secret Manager
```bash
printf '%s' "$GEMINI_KEY" | gcloud secrets create gemini-api-key --data-file=-
```
Mandatory before anything is publicly reachable.

### C3. Two Cloud Run services + a queue
| Service | Role |
|---|---|
| `drishti-api` (FastAPI) | Accepts upload → writes to quarantine bucket → enqueues job. **Never parses APK bytes in the request path.** |
| `drishti-worker` (Cloud Run job) | Pulls job → runs M1→M7 → writes verdict + ledger to Firestore. Isolated, minimal permissions. |
| `drishti-web` (Next.js) | Dashboard: score gauge, report, MITRE grid, evidence-ledger graph. |

Why split: if Androguard is ever exploited by a malicious APK, it happens in a throwaway
container with no privileges — not in your public web tier.

### C4. Model artifact
Upload `androzoo.joblib` to GCS; the worker loads it at cold start. Version it so a verdict
can name the model that produced it (reproducibility for the ledger).

### C5. Guardrails before going public
- Auth on upload (Firebase Auth or IAP) + rate limits + max file size.
  An open "upload any APK" endpoint **will** be abused as free malware hosting.
- Quarantine bucket: `public-access-prevention`, lifecycle auto-delete, **never served back**.
- Show provenance in the UI: which model version, Gemini live vs mock, M3 real vs simulated.

---

# Recommended order (be honest about what fits)

1. **Phase A** — real corpus + measured metrics. *Biggest credibility win. Do this.*
2. **Phase C** — the clickable product. *What judges actually experience.*
3. **Phase B** — real detonation. *Genuine research; label as future work if time runs out.*

A + C gives you a defensible, demoable system with real numbers. B makes it a research
contribution. Do not start B before A works end to end.
