"""Seed the demo database and (optionally) reset it daily.

Two modes:

    python seed_and_reset.py --once
        Truncate `test_emails`, then load every .eml under SEED_DIR, analyze
        each, and insert a row with source="seed". Exits 0 on success.

    python seed_and_reset.py --daemon
        Seed once immediately, then sleep until the next UTC midnight (+60s
        grace) and reseed. Repeat forever. Intended to run as a sidecar
        container alongside the API.

Environment variables
---------------------
SEED_DIR              Directory containing .eml files to load.
                      Default: /app/seed_emails (baked into the api image).
DATABASE_URL          Same value the API uses; inherited from compose.
SEED_SOURCE_LABEL     Value written to `test_emails.source`.
                      Default: "seed".

The whole table is truncated on each run. That is deliberate: this script
doubles as the nightly reset — any data ingested during the day gets
wiped and only the curated seed set remains. Bounds the blast radius of
abuse to ~24h.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import text

from analyzer import analyze_message
from database import Base, SessionLocal, engine
from models import TestEmail


SEED_DIR = Path(os.environ.get("SEED_DIR", "/app/seed_emails"))
SEED_SOURCE_LABEL = os.environ.get("SEED_SOURCE_LABEL", "seed")


def _load_seed_files(seed_dir: Path) -> list[tuple[str, bytes]]:
    if not seed_dir.is_dir():
        print(f"[seed] WARNING: seed dir not found: {seed_dir}", flush=True)
        return []
    files = sorted(p for p in seed_dir.glob("*.eml") if p.is_file())
    out: list[tuple[str, bytes]] = []
    for path in files:
        try:
            out.append((path.name, path.read_bytes()))
        except OSError as exc:
            print(f"[seed] skipping {path.name}: {exc}", flush=True)
    return out


def reset_and_seed() -> int:
    """Truncate test_emails and insert every seed .eml. Returns row count."""
    Base.metadata.create_all(bind=engine)
    seeds = _load_seed_files(SEED_DIR)

    db = SessionLocal()
    try:
        db.execute(text("TRUNCATE TABLE test_emails RESTART IDENTITY"))
        inserted = 0
        for filename, raw_bytes in seeds:
            try:
                raw_message = raw_bytes.decode("utf-8", errors="replace")
                analysis = analyze_message(raw_message, None)
                parsed_subject = (analysis.get("subject") or "").strip()
                row = TestEmail(
                    subject=parsed_subject or f"(seed: {filename})",
                    raw_message=raw_message,
                    raw_message_b64=None,
                    parsed_headers=analysis.get("headers"),
                    mime_tree=analysis.get("mime_tree"),
                    auth_results=analysis.get("auth_results"),
                    links=analysis.get("links"),
                    images=analysis.get("images"),
                    deliverability=analysis.get("deliverability"),
                    source=SEED_SOURCE_LABEL,
                )
                db.add(row)
                inserted += 1
            except Exception as exc:  # noqa: BLE001
                print(f"[seed] analyze failed for {filename}: {exc}", flush=True)
                traceback.print_exc()
        db.commit()
        print(
            f"[seed] reset complete: inserted {inserted} rows from {SEED_DIR}",
            flush=True,
        )
        return inserted
    finally:
        db.close()


def _seconds_until_next_utc_midnight() -> float:
    now = datetime.now(tz=timezone.utc)
    # Run 60s after midnight so clients that trigger right at the boundary
    # don't race the truncate.
    next_run = (now + timedelta(days=1)).replace(
        hour=0, minute=1, second=0, microsecond=0
    )
    return (next_run - now).total_seconds()


def _wait_for_db(max_attempts: int = 30, delay_s: float = 2.0) -> None:
    """Compose has depends_on but not readiness; poll until the DB accepts us."""
    last_err: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            print(
                f"[seed] DB not ready (attempt {attempt}/{max_attempts}): {exc}",
                flush=True,
            )
            time.sleep(delay_s)
    raise RuntimeError(f"database never became ready: {last_err}")


def run_daemon() -> None:
    _wait_for_db()
    while True:
        try:
            reset_and_seed()
        except Exception as exc:  # noqa: BLE001
            print(f"[seed] reset_and_seed failed: {exc}", flush=True)
            traceback.print_exc()
        sleep_for = _seconds_until_next_utc_midnight()
        next_ts = datetime.now(tz=timezone.utc) + timedelta(seconds=sleep_for)
        print(
            f"[seed] sleeping {int(sleep_for)}s until next reset "
            f"at {next_ts.isoformat()} UTC",
            flush=True,
        )
        time.sleep(sleep_for)


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed/reset the demo database.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true", help="seed once and exit")
    mode.add_argument(
        "--daemon",
        action="store_true",
        help="seed now, then reseed every UTC midnight",
    )
    args = parser.parse_args()

    if args.once:
        _wait_for_db()
        reset_and_seed()
        return 0

    run_daemon()
    return 0


if __name__ == "__main__":
    sys.exit(main())
