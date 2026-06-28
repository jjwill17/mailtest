# Home-side API watchdog

Self-healing watchdog that catches the recurring **"WSL ↔ docker-proxy port
mapping goes stale"** failure mode. Symptom: `https://demo...xyz` returns 502
from Caddy, `docker compose ps` shows `mailtest-api` as `Up`, uvicorn logs look
fine, but `curl http://127.0.0.1:8080/health` from the WSL host hangs or fails.

The watchdog probes `/health` every minute; if it fails twice in a row it
restarts the `api` container. A 10-minute cooldown prevents thrashing during a
real outage so [HetrixTools](https://hetrixtools.com) (or whichever external
monitor you use) can still page you.

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

The script honors three environment variables; defaults are usually fine.
Override by editing the `Environment=` lines in the `.service` unit:

| Var | Default | What |
|--|--|--|
| `HEALTH_URL`        | `http://127.0.0.1:8080/health` | What to probe. |
| `COMPOSE_DIR`       | `/home/justin/mailtest`        | Where `docker compose` runs. |
| `COOLDOWN_SECONDS`  | `600`                          | Min seconds between auto-heals. |

## Disable temporarily [home]

```bash
sudo systemctl disable --now mailtest-watchdog.timer
# Re-enable later with: sudo systemctl enable --now mailtest-watchdog.timer
```
