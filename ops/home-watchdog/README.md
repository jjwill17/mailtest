# Home-side API + tunnel watchdog

Two-layer self-diagnosis watchdog that catches the recurring failure modes
this project has hit in production:

**Layer 1 — Local API health (auto-heals).** Catches the *"WSL ↔ docker-proxy
port mapping goes stale"* symptom: `https://demo...xyz` returns `502` from
Caddy, `docker compose ps` shows `mailtest-api` as `Up`, uvicorn logs look
fine, but `curl http://127.0.0.1:8080/health` from the WSL host hangs.
Probes every minute; if `/health` fails twice in a row (5s apart), kicks the
`api` container so `docker-proxy` re-binds. A 10-minute cooldown prevents
thrashing during a real outage so [HetrixTools](https://hetrixtools.com)
still pages you.

**Layer 2 — Public URL health (diagnoses, doesn't heal).** Runs only when
Layer 1 was healthy. Probes the public URL; if it's down while the local API
is fine, the fault is on the tunnel/VPS side. Fingerprints the cause using
`systemctl is-active mailtest-tunnel` and prints a targeted diagnostic
(including the exact fix command) into the journal. Rate-limited to one
diagnostic every 15 minutes during a sustained outage. **Does not** auto-heal
because that would require stashing an admin SSH key on this host — the
diagnostic points you at the one command to run on the VPS instead.

## Files

| File | Lands at | What |
|--|--|--|
| `mailtest-watchdog.sh`      | stays in repo, referenced by the unit | Probe + heal logic. |
| `mailtest-watchdog.service` | `/etc/systemd/system/mailtest-watchdog.service` | One-shot unit, runs as `justin`. |
| `mailtest-watchdog.timer`   | `/etc/systemd/system/mailtest-watchdog.timer`   | Fires the service every minute. |

## Install [home]

```bash
# 1. Make sure the script is executable in the repo.
chmod +x /home/justin/mailtest/ops/home-watchdog/mailtest-watchdog.sh

# 2. Install the systemd units.
sudo cp /home/justin/mailtest/ops/home-watchdog/mailtest-watchdog.service \
        /etc/systemd/system/
sudo cp /home/justin/mailtest/ops/home-watchdog/mailtest-watchdog.timer \
        /etc/systemd/system/
sudo systemctl daemon-reload

# 3. Enable + start the timer (NOT the service — the timer fires the service).
sudo systemctl enable --now mailtest-watchdog.timer
```

## Verify [home]

```bash
# Timer is queued + has fired at least once.
systemctl list-timers mailtest-watchdog.timer
systemctl status mailtest-watchdog.timer | head -n 10

# Last few probes — healthy probes log nothing, only events log.
journalctl -u mailtest-watchdog.service -n 30 --no-pager
```

A healthy timer should show `Trigger: ...; ... left` and most service runs will be
silent (exit 0, no log lines). The first interesting log is the first time it
heals: look for `DOWN: ... kicking mailtest-api` followed by `RECOVERED: ...`.

## Smoke-test the heal path [home]

To prove the watchdog actually heals (without waiting for the next real
incident):

```bash
# Stop the api container by hand.
cd /home/justin/mailtest && docker compose stop api

# Within ~2 minutes (two timer ticks) the watchdog should bring it back.
# Watch it happen:
journalctl -u mailtest-watchdog.service -f
```

You should see a `DOWN: ... kicking mailtest-api` line, then `RECOVERED: ...`,
then `docker compose ps` will show `api` running again.

## Tuning

The script honors these environment variables; defaults are usually fine.
Override by adding `Environment=NAME=value` lines to the `.service` unit:

| Var | Default | What |
|--|--|--|
| `HEALTH_URL`                    | `http://127.0.0.1:8080/health`                 | Layer 1 probe target. |
| `PUBLIC_URL`                    | `https://demo.mailtest.justfortesting.xyz/health` | Layer 2 probe target. |
| `COMPOSE_DIR`                   | `/home/justin/mailtest`                        | Where `docker compose` runs. |
| `COOLDOWN_SECONDS`              | `600`                                          | Min seconds between Layer 1 auto-heals. |
| `PUBLIC_DIAG_COOLDOWN_SECONDS`  | `900`                                          | Min seconds between Layer 2 diagnostic re-logs. |
| `TUNNEL_SERVICE`                | `mailtest-tunnel.service`                      | Systemd unit checked to fingerprint tunnel faults. |

## Disable temporarily [home]

```bash
sudo systemctl disable --now mailtest-watchdog.timer
# Re-enable later with: sudo systemctl enable --now mailtest-watchdog.timer
```
