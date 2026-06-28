#!/usr/bin/env bash
# mailtest-watchdog.sh
#
# Probes the local API's /health endpoint. If it fails twice in a row
# (5s apart), kick the api container so docker-proxy re-binds and uvicorn
# comes back. Designed to self-heal the recurring "WSL <-> docker-proxy
# port mapping goes stale" failure mode without operator intervention.
#
# Cooldown: only heals once per ${COOLDOWN_SECONDS} (default 600s / 10min).
# This means a *real* outage (bad code push, dependency crash-loop) will
# not be thrashed into oblivion; HetrixTools alerts you instead.
#
# Designed to be invoked every minute by mailtest-watchdog.timer.

set -uo pipefail

HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8080/health}"
COMPOSE_DIR="${COMPOSE_DIR:-/home/justin/mailtest}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-600}"
STATE_DIR="${STATE_DIR:-/run/mailtest-watchdog}"
LAST_HEAL_FILE="${STATE_DIR}/last-heal"

mkdir -p "$STATE_DIR" 2>/dev/null || true

probe() {
  curl -fsS -m 3 -o /dev/null "$HEALTH_URL"
}

# Two-strike check: ignore transient single-curl blips.
if probe; then
  exit 0
fi
sleep 5
if probe; then
  echo "transient blip on $HEALTH_URL recovered without intervention"
  exit 0
fi

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

# Give uvicorn ~5s to bind before reporting recovery status.
sleep 5
if probe; then
  echo "RECOVERED: $HEALTH_URL responding after container restart"
  exit 0
else
  echo "STILL DOWN after restart — operator intervention required"
  exit 3
fi
