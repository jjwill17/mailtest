#!/usr/bin/env bash
# mailtest-watchdog.sh
#
# Two-layer health watchdog:
#
#   Layer 1 (local API):  probes http://127.0.0.1:8080/health. If it fails
#                         twice in a row (5s apart), kicks the api container
#                         so docker-proxy re-binds and uvicorn comes back.
#                         Auto-heal on a 10-min cooldown.
#
#   Layer 2 (public URL): probes https://demo.mailtest.justfortesting.xyz/health.
#                         If the local API is healthy but the public URL is
#                         not, the tunnel or VPS is at fault. This script
#                         DOES NOT auto-heal that (would require an admin key
#                         on this host) — it logs a rich diagnostic pointing
#                         at the exact fix command. A 15-min diagnostic
#                         cooldown keeps the journal readable during a real
#                         outage.
#
# Designed to be invoked every minute by mailtest-watchdog.timer.

set -uo pipefail

HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8080/health}"
PUBLIC_URL="${PUBLIC_URL:-https://demo.mailtest.justfortesting.xyz/health}"
COMPOSE_DIR="${COMPOSE_DIR:-/home/justin/mailtest}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-600}"
PUBLIC_DIAG_COOLDOWN_SECONDS="${PUBLIC_DIAG_COOLDOWN_SECONDS:-900}"
TUNNEL_SERVICE="${TUNNEL_SERVICE:-mailtest-tunnel.service}"
STATE_DIR="${STATE_DIR:-/run/mailtest-watchdog}"
LAST_HEAL_FILE="${STATE_DIR}/last-heal"
LAST_PUBLIC_DIAG_FILE="${STATE_DIR}/last-public-diag"

# Under systemd the RuntimeDirectory= directive creates /run/mailtest-watchdog
# owned by the service user. When run manually (dev / debugging), that path
# isn't writable, so fall back to $HOME/.cache/ or /tmp/.
if ! mkdir -p "$STATE_DIR" 2>/dev/null && [[ ! -w "$STATE_DIR" ]]; then
  STATE_DIR="${HOME:-/tmp}/.cache/mailtest-watchdog"
  mkdir -p "$STATE_DIR" 2>/dev/null || STATE_DIR="/tmp/mailtest-watchdog-$$"
  mkdir -p "$STATE_DIR"
  LAST_HEAL_FILE="${STATE_DIR}/last-heal"
  LAST_PUBLIC_DIAG_FILE="${STATE_DIR}/last-public-diag"
fi

# -f = fail on HTTP errors; -s = silent. No -S because Layer 2 does its own
# detailed diagnostic and we don't want raw curl chatter in the journal.
probe_local()  { curl -fs -m 3  -o /dev/null "$HEALTH_URL"; }
probe_public() { curl -fs -m 10 -o /dev/null "$PUBLIC_URL"; }

# ---------------------------------------------------------------------------
# Layer 1: local API health + auto-heal
# ---------------------------------------------------------------------------

if ! probe_local; then
  sleep 5
  if probe_local; then
    echo "transient blip on $HEALTH_URL recovered without intervention"
  else
    now=$(date +%s)
    if [[ -f "$LAST_HEAL_FILE" ]]; then
      last=$(cat "$LAST_HEAL_FILE" 2>/dev/null || echo 0)
      age=$(( now - last ))
      if (( age < COOLDOWN_SECONDS )); then
        echo "DOWN: $HEALTH_URL unresponsive, but last heal was ${age}s ago (<${COOLDOWN_SECONDS}s cooldown). Skipping; HetrixTools should be alerting."
        exit 1
      fi
    fi

    echo "DOWN: $HEALTH_URL failed twice; kicking mailtest-api container"
    cd "$COMPOSE_DIR" || { echo "ABORT: cannot cd to COMPOSE_DIR=$COMPOSE_DIR"; exit 2; }
    docker compose kill api
    docker compose up -d api
    echo "$now" > "$LAST_HEAL_FILE"

    sleep 5
    if probe_local; then
      echo "RECOVERED: $HEALTH_URL responding after container restart"
    else
      echo "STILL DOWN after restart — operator intervention required"
      exit 3
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Layer 2: public URL health + diagnostic (no auto-heal)
# ---------------------------------------------------------------------------

if probe_public; then
  exit 0
fi
sleep 5
if probe_public; then
  echo "transient blip on $PUBLIC_URL recovered without intervention"
  exit 0
fi

# Public URL is DOWN but local API is HEALTHY. Rate-limit the diagnostic
# so we don't spam the journal every minute during a real outage.
now=$(date +%s)
if [[ -f "$LAST_PUBLIC_DIAG_FILE" ]]; then
  last=$(cat "$LAST_PUBLIC_DIAG_FILE" 2>/dev/null || echo 0)
  age=$(( now - last ))
  if (( age < PUBLIC_DIAG_COOLDOWN_SECONDS )); then
    exit 4
  fi
fi
echo "$now" > "$LAST_PUBLIC_DIAG_FILE"

echo "======================================================================="
echo "PUBLIC URL DOWN: $PUBLIC_URL"
echo "  Local /health is HEALTHY, so this is a tunnel-side or VPS-side fault."
echo "  This diagnostic will only re-log every ${PUBLIC_DIAG_COOLDOWN_SECONDS}s during an ongoing outage."
echo

tunnel_state=$(systemctl is-active "$TUNNEL_SERVICE" 2>&1 || true)
echo "  Tunnel service state: $tunnel_state"

if [[ "$tunnel_state" != "active" ]]; then
  echo
  echo "  DIAGNOSIS: The autossh tunnel is not established."
  echo "  Recent tunnel log (last 5 lines):"
  journalctl -u "$TUNNEL_SERVICE" -n 5 --no-pager 2>&1 | sed 's/^/    | /'
  echo
  echo "  If the log shows 'remote port forwarding failed for listen port 18080',"
  echo "  a stale sshd on the VPS is holding the port. Fix from the VPS:"
  echo "      sudo pkill -f 'sshd.*tunnel' && sleep 2 && sudo ss -lntp 'sport = :18080'"
  echo "  After that, autossh here will reconnect within ~10 seconds."
else
  echo
  echo "  DIAGNOSIS: Tunnel service is 'active' locally, so the fault is upstream."
  echo "  Likely causes (in decreasing likelihood):"
  echo "    - Caddy on the VPS is down or misconfigured  (VPS: 'systemctl status caddy')"
  echo "    - VPS itself is down or unreachable          (from outside: 'ping 209.141.48.115')"
  echo "    - Home internet upstream is broken           (from here: 'curl -s https://1.1.1.1')"
  echo "    - VPS-side sshd is holding a stale forward   (VPS: 'ss -lntp sport = :18080')"
fi
echo "======================================================================="
exit 4
