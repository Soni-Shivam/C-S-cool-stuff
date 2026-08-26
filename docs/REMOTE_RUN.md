# Running the stack on the analysis VM, with the dashboard in a local browser

The engine runs on the GCE VM. The browser runs on the laptop. Nothing is exposed
on the VM's public interface — a port-forward is the whole of the access control,
which is what keeps the analysis host consistent with the containment posture in
`CLAUDE.md`.

```
laptop browser :15173 ──ssh -L──> VM 127.0.0.1:4173  (vite preview)
                                        │ /api proxy
                                        v
                                  VM 127.0.0.1:8080  (uvicorn)
```

## Once per VM

```bash
git clone <repo> ~/drishti-run && cd ~/drishti-run && git checkout main
uv sync --group dev
sudo apt-get install -y nodejs npm     # vite 7 needs node >= 20.19
cd ui && npm install && npm run build
# .env must exist on the VM; the API refuses to start without GROQ_API_KEY
```

Use a **separate clone** from any working checkout on the same VM. A corpus
extraction batch running out of `~/CyberShield` must not be disturbed by a
`git reset` underneath it.

## Every session

```bash
VM=<instance> ZONE=<zone> PROJECT=<proj> bash scripts/remote_up.sh
VM_IP=<external-ip> bash scripts/remote_tunnel.sh      # leave running
```

Then open <http://localhost:15173>.

## Confirm you are looking at the VM

This is not paranoia; it has already happened once. If another checkout on the
laptop is serving on 8080/4173, the forward fails only its bind and you read a
**local** dashboard believing it is the VM's. The two look identical.

```bash
curl -s localhost:18080/api/jobs     # VM
curl -s localhost:8080/api/jobs      # whatever is local, if anything
```

Different job lists mean different instances. `ss -tlnp | grep -E '15173|18080'`
should show `ssh` owning both forwarded ports.

## Traps worth knowing

- **Detach properly.** `setsid nohup … < /dev/null &`. Without the stdin redirect
  the launch dies with the ssh session and reads as an app crash.
- **Never `pkill -f` a pattern that appears in your own command line.** The shell
  matches itself and dies with exit 144. Put the pattern in a script file.
- **Verify with the API, not the health endpoint.** `/api/health` is identical on
  every instance and proves nothing about which one answered.
