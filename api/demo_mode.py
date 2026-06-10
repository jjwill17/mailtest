"""Demo / portfolio-mode safety rails.

When this project is exposed on the public internet as an interview/portfolio
demo, we want visitors to be able to browse and send a handful of test emails,
but we do *not* want anyone to be able to bulk-delete the seeded data, kick
off expensive whole-table reanalysis, or peek at internal debug output.

Environment variables
---------------------
DEMO_MODE            "true"/"false" (default false). When true:
                       - destructive / expensive endpoints that depend on
                         `require_writable` return 403 unless the caller
                         supplies a matching X-Admin-Key header.
                       - /ingest still works (mail has to keep landing),
                         but is size-capped and rate-limited.
ADMIN_API_KEY        Long random string. If set AND DEMO_MODE=true, requests
                       carrying `X-Admin-Key: <value>` bypass the write guard.
                       If empty, the guard simply denies all writes in demo
                       mode (safest default for a shared deploy).
MAX_INGEST_BYTES     Hard cap on a single /ingest payload body. Default 1 MiB.
DEFAULT_RATE_LIMIT   Fallback rate-limit for every route (default "120/minute").
                       /ingest has its own stricter per-IP throttle in
                       `ingest_throttle.py` (1/min + 20/UTC-day by default).
"""
from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException, status
from slowapi import Limiter
from slowapi.util import get_remote_address


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


DEMO_MODE: bool = _env_bool("DEMO_MODE", default=False)
ADMIN_API_KEY: str = (os.environ.get("ADMIN_API_KEY") or "").strip()

MAX_INGEST_BYTES: int = int(os.environ.get("MAX_INGEST_BYTES", str(1 * 1024 * 1024)))
DEFAULT_RATE_LIMIT: str = os.environ.get("DEFAULT_RATE_LIMIT", "120/minute")


def _admin_key_valid(provided: str | None) -> bool:
    if not ADMIN_API_KEY or not provided:
        return False
    return hmac.compare_digest(ADMIN_API_KEY, provided.strip())


def should_redact(x_admin_key: str | None) -> bool:
    """True when this GET request should receive redacted (demo-visitor) data.

    - Returns False when DEMO_MODE is off (dev / trusted deploys).
    - Returns False when a valid X-Admin-Key is presented (owner bypass).
    - Returns True for everyone else in demo mode.

    Intended for response-shaping on read endpoints. Unlike
    ``require_writable`` this never raises: it just answers the question
    "should I strip PII from this response?".
    """
    if not DEMO_MODE:
        return False
    return not _admin_key_valid(x_admin_key)


def require_writable(x_admin_key: str | None = Header(default=None)) -> None:
    """FastAPI dependency: block destructive routes when DEMO_MODE is on.

    Attach with `Depends(require_writable)` on endpoints that mutate or delete
    data, or that are expensive enough that a stranger shouldn't be able to
    trigger them. No-op when DEMO_MODE=false.
    """
    if not DEMO_MODE:
        return
    if _admin_key_valid(x_admin_key):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="This endpoint is disabled in demo mode.",
    )


def enforce_ingest_size(raw_message: str | None, raw_message_b64: str | None) -> None:
    """Reject oversized /ingest payloads before we persist or analyze them."""
    size = 0
    if raw_message:
        size += len(raw_message.encode("utf-8", errors="replace"))
    if raw_message_b64:
        size += len(raw_message_b64)
    if size > MAX_INGEST_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"raw_message exceeds {MAX_INGEST_BYTES} bytes",
        )


limiter = Limiter(key_func=get_remote_address, default_limits=[DEFAULT_RATE_LIMIT])
