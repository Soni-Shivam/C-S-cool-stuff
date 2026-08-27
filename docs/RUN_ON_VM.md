# Running DRISHTI on the VM, viewing it from your laptop

Compute (androguard, the ML model, the LLM calls, the ledger) runs on the GCE VM. Your
laptop only renders the page.

| | |
|---|---|
| VM | `instance-20260817-080247` · zone `us-east1-c` · project `internship-505513` |
| App directory on the VM | `~/drishti-run` |
| API on the VM | `127.0.0.1:8080` |
| Dashboard on the VM | `127.0.0.1:4173` |
| Your laptop sees | `http://localhost:7000` (UI) · `http://localhost:7001` (API) |

Both VM services bind to `127.0.0.1` on purpose — nothing is exposed to the VPC or the
internet. You reach them through an SSH tunnel, which is why the forwarding step below
is not optional.

---

## Start

### 1. On the VM — start the API and the dashboard

One SSH session, both services, detached so they survive you logging out:

```bash
gcloud compute ssh instance-20260817-080247 --zone=us-east1-c --project=internship-505513 --tunnel-through-iap --command='cd ~/drishti-run && (setsid nohup uv run uvicorn drishti.api.main:app --host 127.0.0.1 --port 8080 > /tmp/drishti-api.log 2>&1 &) && (cd ui && setsid nohup npm exec vite preview -- --port 4173 --host 127.0.0.1 > /tmp/drishti-ui.log 2>&1 &) && sleep 6 && ss -ltn | grep -E ":(8080|4173)"'
```

You should see two `LISTEN` lines. If you see none, read `/tmp/drishti-api.log` and
`/tmp/drishti-ui.log` on the VM — both are backgrounded, so a startup crash is silent
otherwise.

The dashboard is served as a **production build** (`vite preview`), not `vite dev`. If
you changed UI source on the VM, rebuild first or you will be looking at the old bundle:

```bash
gcloud compute ssh instance-20260817-080247 --zone=us-east1-c --project=internship-505513 --tunnel-through-iap --command='cd ~/drishti-run/ui && npm run build'
```

### 2. On your laptop — forward the ports

Leave this running in its own terminal. It is the tunnel; closing it closes your access.

```bash
gcloud compute ssh instance-20260817-080247 --zone=us-east1-c --project=internship-505513 --tunnel-through-iap -- -L 7000:127.0.0.1:4173 -L 7001:127.0.0.1:8080 -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=1000
```

- `-N` means "forward only, no shell" — it will sit there printing nothing. That is correct.
- `ExitOnForwardFailure=yes` makes it fail loudly if port 7000 or 7001 is already taken,
  instead of connecting and silently forwarding nothing.
- `ServerAliveInterval` keeps it from dying on an idle demo.

### 3. Open it

```
http://localhost:7000
```

**Do not use `gcloud compute start-iap-tunnel` for this.** An IAP tunnel connects to the
VM's *internal IP*; these services are bound to `127.0.0.1`, so it fails with
`4003: failed to connect to backend`. SSH forwarding reaches loopback, which is the whole
reason the command above is an `ssh -L` and not a tunnel.

---

## Check it is actually working

```bash
curl -s http://localhost:7001/api/health          # {"status":"ok","version":"0.1.0"}
curl -s http://localhost:7000/ -o /dev/null -w '%{http_code}\n'   # 200
```

Submit a sample and confirm the **VM** did the work:

```bash
curl -s -X POST http://localhost:7001/api/jobs -F "apk=@canary/dist/canary.apk"
curl -s http://localhost:7001/api/jobs | python3 -m json.tool | head -20
```

---

## Stop

### Stop the forwarding (laptop)

`Ctrl-C` in that terminal. If you backgrounded it:

```bash
pkill -f "L 7000:127.0.0.1:4173"
```

### Stop the services (VM)

```bash
gcloud compute ssh instance-20260817-080247 --zone=us-east1-c --project=internship-505513 --tunnel-through-iap --command='pkill -f "uvicorn drishti.api.main:app"; pkill -f "vite preview"; sleep 2; ss -ltn | grep -E ":(8080|4173)" || echo "both stopped"'
```

### Stop the VM itself

Only when you are done for the day — this is the one that costs money. `n2-standard-16`
is not cheap to leave idle.

```bash
gcloud compute instances stop instance-20260817-080247 --zone=us-east1-c --project=internship-505513
```

---

## Troubleshooting

**`bind: Address already in use`** — something already holds 7000 or 7001 on your laptop.
Find it with `ss -ltnp | grep 700` and either kill it or change the left-hand number:
`-L 7010:127.0.0.1:4173`, then open `http://localhost:7010`.

**Page loads but every panel is empty** — the UI is up and the API is not. Check
`curl -s http://localhost:7001/api/health`; if that fails, the `-L 7001` half is fine but
uvicorn on the VM is down. Restart it with the step-1 command and read
`/tmp/drishti-api.log`.

**Tunnel drops mid-demo** — the `ServerAliveInterval` options above are what prevent it.
If it still dies, just re-run the step-2 command; the VM services keep running and
nothing is lost.

**You changed code and nothing changed on screen** — `uvicorn` there runs *without*
`--reload`, and the UI is a built bundle. Restart the API (stop + start) and re-run
`npm run build` for the UI.

---

## Which code is on the VM

Worth checking before a demo, because it is easy to assume:

```bash
gcloud compute ssh instance-20260817-080247 --zone=us-east1-c --project=internship-505513 --tunnel-through-iap --command='cd ~/drishti-run && git branch --show-current && git log --oneline -1 && git status --short'
```

As of 2026-08-27 that VM was on `main` at `fa04cdf` with uncommitted local edits, i.e.
**not** the `claude/sandbox-progress-plan-94f41e` branch. If you want the branch's work
(the live-detonation trace, the YARA refang, the overlay fix, the STIX never-benign fix),
that has to be deployed there first — and the uncommitted edits on the VM need saving
before any checkout, or they are gone.
