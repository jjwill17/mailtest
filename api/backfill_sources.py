#!/usr/bin/env python3
"""
One-shot backfill for the `source` column on older test_emails rows.

Rows ingested before the `source` column was added (or before the pipe/bridge
started setting it) have `source IS NULL`. This script applies conservative,
subject-based heuristics to label rows that we can identify unambiguously:

  subject                                                         -> source
  -------------------------------------------------------------   ------------------------------------
  Mailtest abuse feedback report (RFC 5965 simulator)             simulator-arf
  Abuse feedback report (Mailtest simulator, RFC 5965)            simulator-arf
  SMTP capture (complaint simulator)                              postfix-pipe-complaint-simulator
  SMTP capture                                                    smtp

Rows whose subject came from the real sender (e.g. an incoming marketing
email, or a user-typed test) are intentionally LEFT NULL because we cannot
tell them apart from legitimate captures.

Optional `--pair-complaints` mode: in addition to the above, for every
`simulator-arf` row, look for the nearest earlier NULL-source row within
a small time window and mark it `postfix-pipe-complaint-simulator`. This
catches the primary complaint capture whose subject was set from the real
email Subject header. Off by default to keep the backfill strictly safe.

Run inside the api container:

    docker compose exec api python backfill_sources.py              # dry run
    docker compose exec api python backfill_sources.py --apply      # commit
    docker compose exec api python backfill_sources.py --apply --pair-complaints
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys

from sqlalchemy import text

from database import SessionLocal
from models import TestEmail


EXACT_SUBJECT_MAP = {
    "Mailtest abuse feedback report (RFC 5965 simulator)": "simulator-arf",
    "Abuse feedback report (Mailtest simulator, RFC 5965)": "simulator-arf",
    "SMTP capture (complaint simulator)": "postfix-pipe-complaint-simulator",
    "SMTP capture": "smtp",
}

# Maximum gap between a primary complaint capture and its ARF companion
# when --pair-complaints is enabled. Both are written in the same pipe run
# within ~1s, but we leave margin for slow ingest.
PAIR_WINDOW_SECONDS = 30


def run_exact(session, apply_changes: bool) -> dict[str, int]:
    counts: dict[str, int] = {}
    total = 0
    rows = (
        session.query(TestEmail)
        .filter(TestEmail.source.is_(None))
        .filter(TestEmail.subject.in_(list(EXACT_SUBJECT_MAP.keys())))
        .order_by(TestEmail.id.asc())
        .all()
    )
    for row in rows:
        new_source = EXACT_SUBJECT_MAP[row.subject]
        counts[new_source] = counts.get(new_source, 0) + 1
        total += 1
        row.source = new_source
    session.flush()
    if apply_changes:
        session.commit()
    print(
        f"[exact] matched {total} row(s) by subject -> "
        f"{{{', '.join(f'{k}: {v}' for k, v in sorted(counts.items()))}}}"
    )
    return counts


def run_pair_complaints(session, apply_changes: bool) -> int:
    """For each simulator-arf row, set the nearest earlier NULL row within PAIR_WINDOW_SECONDS
    to 'postfix-pipe-complaint-simulator'. The arf row itself must come AFTER the primary."""
    arf_rows = (
        session.query(TestEmail)
        .filter(TestEmail.source == "simulator-arf")
        .order_by(TestEmail.id.asc())
        .all()
    )
    paired = 0
    for arf in arf_rows:
        if not arf.created_at:
            continue
        window_start = arf.created_at - dt.timedelta(seconds=PAIR_WINDOW_SECONDS)
        candidate = (
            session.query(TestEmail)
            .filter(TestEmail.source.is_(None))
            .filter(TestEmail.id < arf.id)
            .filter(TestEmail.created_at >= window_start)
            .filter(TestEmail.created_at <= arf.created_at)
            .order_by(TestEmail.created_at.desc(), TestEmail.id.desc())
            .first()
        )
        if candidate is None:
            continue
        paired += 1
        candidate.source = "postfix-pipe-complaint-simulator"
    session.flush()
    if apply_changes:
        session.commit()
    print(f"[pair] paired {paired} primary complaint capture(s) with ARF row(s)")
    return paired


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill test_emails.source for legacy rows.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write changes (default is a dry run that commits nothing).",
    )
    parser.add_argument(
        "--pair-complaints",
        action="store_true",
        help="Also mark the primary complaint capture paired with each simulator-arf row.",
    )
    args = parser.parse_args()

    session = SessionLocal()
    try:
        total_null_before = (
            session.query(TestEmail).filter(TestEmail.source.is_(None)).count()
        )
        print(f"rows with source IS NULL before: {total_null_before}")

        run_exact(session, apply_changes=args.apply)
        if args.pair_complaints:
            run_pair_complaints(session, apply_changes=args.apply)

        if not args.apply:
            session.rollback()

        total_null_after = (
            session.query(TestEmail).filter(TestEmail.source.is_(None)).count()
        )
        print(
            f"rows with source IS NULL after:  {total_null_after} "
            f"({'APPLIED' if args.apply else 'dry run — no changes committed'})"
        )
        session.execute(text("SELECT 1"))
    finally:
        session.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
