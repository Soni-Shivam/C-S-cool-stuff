# DRISHTI 3–5 minute judging script

## 0:00–0:40 — The boundary

“DRISHTI is a stock-Android companion, not a silent device controller. It analyzes an APK the user explicitly selects or shares, then the user—not DRISHTI—decides whether Android's installer opens. This phone contains only our inert fixture; real malware is never installed here.”

Show the app onboarding and the configured backend. Point out the health response: Gemini is `live` or `mock`, and dynamic execution is `disabled`.

## 0:40–1:30 — Select before install

Open Downloads, share the **Shady Demo — INERT** APK to DRISHTI (or use **Select APK**). Show the locally computed SHA-256 and upload progress. Explain that Android Storage Access Framework grants only the selected content URI and DRISHTI copies only that file into its private cache.

## 1:30–2:40 — Evidence-backed verdict

When the notification says **Analysis complete**, open the verdict. Show:

- threat score, severity, and confidence;
- ML model version and Gemini live/mock badge;
- dynamic status (`absent` in the normal instant flow);
- conservative potential consequences (“could”), suspicious permissions, MITRE Mobile techniques, and IOCs;
- evidence details with node IDs.

Say: “A capability is not an observation. Simulation is labeled simulated and cannot increase the observed-runtime score. Only a pre-existing SHA-matched artifact from the separately configured no-egress detonator can appear as observed.”

## 2:40–3:30 — Safe decision

Tap **Continue to system installer** and show the acknowledgement. Cancel it first. Explain that stock Android does not let a normal companion silently block all installations. For the judging phone, choose **Delete / Cancel**. If judges request the installer path, continue only with the inert fixture and show Android's own unknown-source setting/confirmation.

## 3:30–4:30 — Backend trust story

Show the architecture diagram. Explain random quarantine filenames, size/ZIP validation, process-isolated parsing, automatic deletion, token authentication, no static-file exposure, and no API route that runs the dynamic analyzer. Close with the signed evidence ledger and MLflow evaluation gates for citation validity, grounding, MITRE correctness, prompt injection, conservative language, and benign false alarms.
