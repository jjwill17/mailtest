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
#                         not, fingerprints the fault (VPS unreachable vs
#                         stale sshd forward vs Caddy) and logs a targeted
#                         diagnostic. Does NOT auto-heal Layer 2 (would
#                         require an admin key on this host). Diagnostics
#                         are rate-limited to once per 15 minutes.
#
# Designed to be invoked every minute by mailtest-watchdog.timer.
#
# Exit codes:
#   0 = healthy (or Layer 1 healed successfully)
#   1 = Layer 1 cooldown skip (still down, not thrashing)
#   2 = cannot cd to COMPOSE_DIR
#   3 = Layer 1 still down after restart
#   4 = Layer 2 public URL down (diagnostic logged or cooldown skip)

set -uo pipefail

HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8080/health}"
PUBLIC_URL="${PUBLIC_URL:-https://demo.mailtest.justfortesting.xyz/health}"
COMPOSE_DIR="${COMPOSE_DIR:-/home/justin/mailtest}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-600}"
PUBLIC_DIAG_COOLDOWN_SECONDS="${PUBLIC_DIAG_COOLDOWN_SECONDS:-900}"
TUNNEL_SERVICE="${TUNNEL_SERVICE:-mailtest-tunnel.service}"
VPS_HOST="${VPS_HOST:-mailtest.justfortesting.xyz}"
VPS_IP="${VPS_IP:-209.141.48.115}"

# Persist cooldown state across oneshot runs. RuntimeDirectory is wiped when
# a Type=oneshot unit exits, which used to defeat the 15-min diagnostic
# rate-limit and spam the journal every minute during a real outage.
STATE_DIR="${STATE_DIR:-${HOME:-/home/justin}/.cache/mailtest-watchdog}"
mkdir -p "$STATE_DIR"
LAST_HEAL_FILE="${STATE_DIR}/last-heal"
LAST_PUBLIC_DIAG_FILE="${STATE_DIR}/last-public-diag"

# -f = fail on HTTP errors; -s = silent. No -S — Layer 2 does its own diagnostic.
probe_local()  { curl -fs -m 3  -o /dev/null "$HEALTH_URL"; }
probe_public() { curl -fs -m 10 -o /dev/null "$PUBLIC_URL"; }

# Cheap TCP reachability probe (no SSH auth). Returns 0 if the port accepts.
tcp_ok() {
  local host=$1 port=$2
  timeout 3 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null
}

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

# Public URL is DOWN but local API is HEALTHY. Rate-limit the diagnostic.
now=$(date +%s)
if [[ -f "$LAST_PUBLIC_DIAG_FILE" ]]; then
  last=$(cat "$LAST_PUBLIC_DIAG_FILE" 2>/dev/null || echo 0)
  age=$(( now - last ))
  if (( age < PUBLIC_DIAG_COOLDOWN_SECONDS )); then
    exit 4
  fi
fi
echo "$now" > "$LAST_PUBLIC_DIAG_FILE"

tunnel_state=$(systemctl is-active "$TUNNEL_SERVICE" 2>&1 || true)
recent_tunnel=$(journalctl -u "$TUNNEL_SERVICE" -n 8 --no-pager 2>&1 || true)
internet_ok=0
tcp_ok 1.1.1.1 443 && internet_ok=1
vps_ssh_ok=0
tcp_ok "$VPS_IP" 22 && vps_ssh_ok=1
vps_https_ok=0
tcp_ok "$VPS_IP" 443 && vps_https_ok=1

echo "======================================================================="
echo "PUBLIC URL DOWN: $PUBLIC_URL"
echo "  Local /health is HEALTHY — fault is tunnel-side or VPS-side."
echo "  Re-logs at most every ${PUBLIC_DIAG_COOLDOWN_SECONDS}s during a sustained outage."
echo
echo "  Tunnel service state : $tunnel_state"
echo "  Home internet (1.1.1.1:443): $([[ $internet_ok -eq 1 ]] && echo OK || echo FAIL)"
echo "  VPS SSH   (${VPS_IP}:22)   : $([[ $vps_ssh_ok -eq 1 ]] && echo OK || echo FAIL)"
echo "  VPS HTTPS (${VPS_IP}:443)  : $([[ $vps_https_ok -eq 1 ]] && echo OK || echo FAIL)"
echo
echo "  Recent tunnel log:"
echo "$recent_tunnel" | sed 's/^/    | /'
echo

if [[ $internet_ok -eq 0 ]]; then
  echo "  DIAGNOSIS: Home internet upstream is broken."
  echo "  Fix: restore home connectivity. autossh will reconnect on its own."
elif [[ $vps_ssh_ok -eq 0 ]]; then
  echo "  DIAGNOSIS: VPS is unreachable from home (TCP ${VPS_IP}:22 times out)."
  echo "  Local stack + home internet are fine; the tunnel cannot re-establish"
  echo "  until the VPS answers on port 22 again."
  echo
  echo "  Check from the VPS provider console / KVM (not over SSH):"
  echo "      1. Is the VPS powered on?"
  echo "      2. systemctl is-active sshd caddy postfix"
  echo "      3. sudo ss -lntp 'sport = :22 or sport = :443 or sport = :18080'"
  echo "      4. If the host is wedged: reboot from the provider panel."
  echo
  echo "  Once the VPS answers on :22, autossh on this host reconnects"
  echo "  automatically within ~2–3 minutes (no home-side action needed)."
elif echo "$recent_tunnel" | grep -q 'remote port forwarding failed for listen port 18080'; then
  echo "  DIAGNOSIS: Stale sshd on the VPS is holding port 18080."
  echo "  Fix from the VPS:"
  echo "      sudo pkill -f 'sshd.*tunnel' && sleep 2 && sudo ss -lntp 'sport = :18080'"
  echo "  autossh here reconnects within ~10 seconds after the port is free."
elif [[ $vps_https_ok -eq 0 ]]; then
  echo "  DIAGNOSIS: VPS answers SSH but not HTTPS — Caddy likely down."
  echo "  Fix from the VPS: sudo systemctl status caddy && sudo systemctl restart caddy"
elif [[ "$tunnel_state" != "active" ]]; then
  echo "  DIAGNOSIS: Tunnel service is not active on this host."
  echo "  Fix: sudo systemctl restart $TUNNEL_SERVICE"
else
  echo "  DIAGNOSIS: VPS ports look reachable from here, but the public URL"
  echo "  still fails. Check Caddy reverse-proxy target and that :18080 is"
  echo "  listening on the VPS: sudo ss -lntp 'sport = :18080'"
fi
echo "======================================================================="
exit 4
