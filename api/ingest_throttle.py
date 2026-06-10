"""Per-IP throttling for POST /ingest.

Two rules, both enforced on every public request:

1. `INGEST_MIN_INTERVAL_SECONDS` (default 60s) — clients must space their
   ingests out by at least this many seconds. Prevents one impatient tester
   from jamming the queue.
2. `INGEST_DAILY_CAP` (default 20) — clients get at most this many ingests
   per **UTC calendar day**, resetting at 00:00 UTC (not a rolling 24h
   window). Bounds the blast radius of any single abusive source.

Internal traffic (no `X-Forwarded-For` header) bypasses both rules, so the
`email-bridge` container can keep ingesting real inbound mail unthrottled.
We trust the **last** IP in X-Forwarded-For because Caddy (our only public
ingress) *appends* the real client IP to whatever the client sent — so a
client-supplied XFF gets out-voted by Caddy's appended value.

This is an in-process store; fine for a single-worker FastAPI deployment.
Swap `_state` for Redis if this ever runs with multiple workers.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status


DAILY_CAP: int = int(os.environ.get("INGEST_DAILY_CAP", "20"))
MIN_INTERVAL_SECONDS: int = int(os.environ.get("INGEST_MIN_INTERVAL_SECONDS", "60"))


@dataclass
class _IPState:
    last_request_epoch: float = 0.0
    count_today: int = 0
    day_utc: str = ""  # YYYY-MM-DD


_state: dict[str, _IPState] = {}
_lock = asyncio.Lock()


def _today_utc() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


def _now_epoch() -> float:
    return datetime.now(tz=timezone.utc).timestamp()


def _client_ip(request: Request) -> str | None:
    """Return the rightmost (Caddy-appended) XFF IP, or None if internal."""
    xff = request.headers.get("x-forwarded-for", "")
    if not xff:
        return None
    parts = [p.strip() for p in xff.split(",") if p.strip()]
    return parts[-1] if parts else None


async def enforce_ingest_throttle(request: Request) -> None:
    """FastAPI dependency: apply the per-IP rate + daily cap to /ingest."""
    ip = _client_ip(request)
    if ip is None:
        return  # Internal caller (e.g. email-bridge). No limit applied.

    now = _now_epoch()
    today = _today_utc()

    async with _lock:
        st = _state.get(ip) or _IPState()

        if st.day_utc != today:
            st.day_utc = today
            st.count_today = 0

        if st.count_today >= DAILY_CAP:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Daily limit of {DAILY_CAP} ingests reached for this IP. "
                    "Resets at 00:00 UTC."
                ),
            )

        elapsed = now - st.last_request_epoch
        if elapsed < MIN_INTERVAL_SECONDS:
            retry_in = max(1, int(MIN_INTERVAL_SECONDS - elapsed))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Please wait {retry_in}s between ingests "
                    f"(limit: 1 per {MIN_INTERVAL_SECONDS}s)."
                ),
                headers={"Retry-After": str(retry_in)},
            )

        st.last_request_epoch = now
        st.count_today += 1
        _state[ip] = st
