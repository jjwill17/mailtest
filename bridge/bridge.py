import base64
import collections
import email.utils
import hashlib
import re
import json
import os
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

import requests
from aiosmtpd.controller import Controller

INGEST_URL = os.environ.get("INGEST_URL", "http://api:8080/ingest")
QUEUE_DIR = Path(os.environ.get("QUEUE_DIR", "/app/queue"))
RETRY_INTERVAL_SECONDS = int(os.environ.get("RETRY_INTERVAL_SECONDS", "300"))
MAX_RETRY_WINDOW_SECONDS = int(os.environ.get("MAX_RETRY_WINDOW_SECONDS", "1200"))

# Bridge-wide (global, all-sources) flood cap. This is the last line of defense
# against a spam blast that sneaks past Postfix's per-IP limits on the VPS and
# any API-side public throttle. It caps fresh SMTP intake across *all* peers so
# the demo UI can't be buried faster than the nightly 00:00 UTC reset can
# clean it. A cap-hit returns SMTP 4xx so legitimate senders queue+retry.
BRIDGE_RATE_CAP = int(os.environ.get("BRIDGE_RATE_CAP", "30"))
BRIDGE_RATE_WINDOW_SECONDS = int(os.environ.get("BRIDGE_RATE_WINDOW_SECONDS", "60"))

MAILTEST_DOMAIN = (os.environ.get("MAILTEST_DOMAIN") or "mailtest.justfortesting.xyz").strip().lower()
CHECK_ADDR = f"check@{MAILTEST_DOMAIN}"
DEMO_ADDR = f"demo@{MAILTEST_DOMAIN}"
COMPLAINT_ADDR = f"complaint@{MAILTEST_DOMAIN}"
BOUNCE_ADDR = f"bounce@{MAILTEST_DOMAIN}"

# Rolling timestamps of messages we've accepted at handle_DATA. aiosmtpd runs
# its handlers in a worker thread distinct from the main retry loop, so a
# plain threading.Lock is the right primitive.
_ingest_times: "collections.deque[float]" = collections.deque()
_ingest_lock = threading.Lock()


def _under_global_cap() -> bool:
    """Return True if we're under the rolling cap and may accept this message.

    Uses a simple rolling-window counter. On True, this records the accept;
    on False, nothing is recorded so repeated rejections don't deepen the hole.
    """
    now = time.monotonic()
    cutoff = now - BRIDGE_RATE_WINDOW_SECONDS
    with _ingest_lock:
        while _ingest_times and _ingest_times[0] < cutoff:
            _ingest_times.popleft()
        if len(_ingest_times) >= BRIDGE_RATE_CAP:
            return False
        _ingest_times.append(now)
        return True


def _addr_spec(address) -> str:
    """Normalize RCPT address to addr-spec (lower case)."""
    if hasattr(address, "addr_spec"):
        return (getattr(address, "addr_spec", None) or "").strip().lower()
    s = str(address).strip()
    if s.startswith("<") and s.endswith(">"):
        s = s[1:-1].strip()
    return s.lower()


def _envelope_from(envelope) -> str:
    return (envelope.mail_from or "").strip()


def _client_ip(session) -> str:
    if getattr(session, "peer", None) and isinstance(session.peer, (list, tuple)) and session.peer:
        return str(session.peer[0] or "").strip()
    return ""


_RETURN_PATH_HEADER_RE = re.compile(r"(?im)^return-path:")


def _apply_synthetic_headers(raw_email: str, envelope_from: str, client_ip: str) -> str:
    synthetic_headers = []
    # Record SMTP MAIL FROM at our MX. Prefer X-Mailtest-Envelope-From for the analyzer
    # (stripped before DKIM verify). Also add Return-Path when missing so the stored
    # MIME matches what Gmail/Apple Mail show, without using Postfix pipe R= on ingest.
    # Null sender stays as the bare token "<>" on the Return-Path line; only real
    # addresses are wrapped in angle brackets, otherwise we'd emit "<<>>" (invalid).
    if envelope_from:
        x_value = envelope_from
        return_path_value = f"<{envelope_from}>"
    else:
        x_value = "<>"
        return_path_value = "<>"
    synthetic_headers.append(f"X-Mailtest-Envelope-From: {x_value}")
    if not _RETURN_PATH_HEADER_RE.search(raw_email):
        synthetic_headers.append(f"Return-Path: {return_path_value}")
    if client_ip:
        synthetic_headers.append(f"X-Mailtest-Client-IP: {client_ip}")
    return "\n".join(synthetic_headers) + "\n" + raw_email


def _build_arf_report(
    *,
    envelope_from: str,
    original_rcpt: str,
    client_ip: str,
    original_body: str,
) -> str:
    """
    Minimal RFC 5965 multipart/report (report-type=feedback-report) abuse report,
    aligned with Appendix B structure (text/plain + message/feedback-report + message/rfc822).
    """
    boundary = f"mailtest_{uuid.uuid4().hex}"
    now = email.utils.formatdate(localtime=True)
    reporting_mta = MAILTEST_DOMAIN
    ip_line = client_ip or "0.0.0.0"
    orig_from = envelope_from or ""
    if orig_from and not orig_from.startswith("<"):
        orig_from_display = f"<{orig_from}>"
    else:
        orig_from_display = orig_from or "<>"

    human = (
        f"This is an email abuse report for a message handled by the Mailtest mailbox simulator "
        f"(complaint@{MAILTEST_DOMAIN}). For ARF details see RFC 5965.\n"
    )

    feedback_lines = [
        "Feedback-Type: abuse",
        "User-Agent: Mailtest-Simulator/1.0",
        "Version: 1",
        f"Original-Mail-From: {orig_from_display}",
        f"Original-Rcpt-To: <{original_rcpt}>",
        f"Arrival-Date: {now}",
        f"Reporting-MTA: dns; {reporting_mta}",
        f"Source-IP: {ip_line}",
    ]
    feedback_block = "\r\n".join(feedback_lines) + "\r\n\r\n"

    # message/rfc822 part: original SMTP DATA as received (no Mailtest synthetic headers)
    rfc822 = original_body.replace("\r\n", "\n")
    if not rfc822.endswith("\n"):
        rfc822 += "\n"

    parts = [
        f"--{boundary}\r\n"
        f'Content-Type: text/plain; charset="utf-8"\r\n'
        f"Content-Transfer-Encoding: 8bit\r\n\r\n"
        f"{human}\r\n",
        f"--{boundary}\r\n"
        f"Content-Type: message/feedback-report\r\n"
        f"Content-Transfer-Encoding: 8bit\r\n\r\n"
        f"{feedback_block}\r\n",
        f"--{boundary}\r\n"
        f"Content-Type: message/rfc822\r\n"
        f"Content-Disposition: inline\r\n\r\n"
        f"{rfc822}\r\n",
        f"--{boundary}--\r\n",
    ]

    outer_headers = [
        f"From: Mailtest Simulator <noreply@{MAILTEST_DOMAIN}>",
        f"To: {orig_from_display}",
        f"Subject: Mailtest abuse feedback report (RFC 5965 simulator)",
        "MIME-Version: 1.0",
        f"Date: {now}",
        f'Content-Type: multipart/report; report-type=feedback-report; boundary="{boundary}"',
        "",
    ]
    return "\r\n".join(outer_headers) + "".join(parts)


class EmailHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        spec = _addr_spec(address)
        if spec == BOUNCE_ADDR:
            # Match SES mailbox simulator: hard bounce / unknown user at SMTP RCPT time.
            return "550 5.1.1 User unknown"
        if spec in (CHECK_ADDR, DEMO_ADDR, COMPLAINT_ADDR):
            envelope.rcpt_tos.append(address)
            return "250 OK"
        return "550 No such user"

    async def handle_DATA(self, server, session, envelope):
        rcpt_specs = [_addr_spec(a) for a in (envelope.rcpt_tos or [])]
        print(f"handle_DATA rcpt_tos={rcpt_specs!r}")

        allowed = {CHECK_ADDR, DEMO_ADDR, COMPLAINT_ADDR}
        if not rcpt_specs or any(s not in allowed for s in rcpt_specs):
            return "550 No such user"

        if not _under_global_cap():
            # 451 is a temporary failure so well-behaved MTAs (Postfix on the
            # VPS, Gmail, SES, etc.) will queue and retry. Spammers that don't
            # retry just get capped. The rolling window clears naturally.
            print(
                f"Global rate cap hit "
                f"(cap={BRIDGE_RATE_CAP} / window={BRIDGE_RATE_WINDOW_SECONDS}s); "
                f"peer={_client_ip(session)!r} rcpts={rcpt_specs!r}"
            )
            return "451 4.7.1 Service busy, please retry later"

        original_bytes = getattr(envelope, "original_content", None)
        if not isinstance(original_bytes, (bytes, bytearray)) or not original_bytes:
            original_bytes = envelope.content or b""
        raw_bytes = bytes(original_bytes)
        body_for_embed = raw_bytes.decode("utf-8", errors="replace")
        mail_from = _envelope_from(envelope)
        client_ip = _client_ip(session)
        print(f"SMTP MAIL FROM={mail_from!r} client_ip={client_ip!r} peer={getattr(session, 'peer', None)!r}")
        raw_email = _apply_synthetic_headers(body_for_embed, mail_from, client_ip)
        raw_message_b64 = base64.b64encode(raw_bytes).decode("ascii")
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        want_complaint = COMPLAINT_ADDR in rcpt_specs

        payload = {
            "subject": "SMTP capture (complaint simulator)" if want_complaint else "SMTP capture",
            "raw_message": raw_email,
            "raw_message_b64": raw_message_b64,
            "raw_sha256": raw_sha256,
            "source": "smtp-complaint-simulator" if want_complaint else "smtp",
            "smtp_envelope_from": mail_from,
            "smtp_client_ip": client_ip or None,
        }

        try:
            ingest = _post_payload(payload)
            print(f"Ingested id={ingest.get('id')!r} complaint_sim={want_complaint}")
            if want_complaint:
                arf = _build_arf_report(
                    envelope_from=_envelope_from(envelope),
                    original_rcpt=COMPLAINT_ADDR,
                    client_ip=_client_ip(session),
                    original_body=body_for_embed,
                )
                arf_bytes = arf.encode("utf-8")
                arf_payload = {
                    "subject": "Abuse feedback report (Mailtest simulator, RFC 5965)",
                    "raw_message": arf,
                    "raw_message_b64": base64.b64encode(arf_bytes).decode("ascii"),
                    "raw_sha256": hashlib.sha256(arf_bytes).hexdigest(),
                    "source": "simulator-arf",
                }
                _post_payload(arf_payload)
                print("Ingested companion ARF report")
            return "250 OK"
        except Exception as e:
            print(f"Immediate ingest failed, queueing: {e}")
            _queue_payload(payload, str(e))
            return "250 Queued"


def _post_payload(payload: dict) -> dict:
    response = requests.post(INGEST_URL, json=payload, timeout=30)
    if response.status_code >= 400:
        raise RuntimeError(f"HTTP {response.status_code}: {response.text[:300]}")
    try:
        return response.json() if response.content else {}
    except Exception:
        return {}


def _queue_payload(payload: dict, last_error: str) -> None:
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    item = {
        "id": str(uuid.uuid4()),
        "created_at": now,
        "last_attempt_at": now,
        "attempts": 1,
        "last_error": last_error[:500],
        "payload": payload,
    }
    out_path = QUEUE_DIR / f"{item['id']}.json"
    tmp_path = QUEUE_DIR / f"{item['id']}.tmp"
    tmp_path.write_text(json.dumps(item), encoding="utf-8")
    tmp_path.replace(out_path)
    print(f"Queued message {item['id']}")


def _process_retry_queue() -> None:
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    for item_path in sorted(QUEUE_DIR.glob("*.json")):
        try:
            item = json.loads(item_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"Skipping invalid queue item {item_path.name}: {exc}")
            item_path.unlink(missing_ok=True)
            continue

        created_at = int(item.get("created_at", now))
        last_attempt_at = int(item.get("last_attempt_at", 0))
        age = now - created_at
        if age > MAX_RETRY_WINDOW_SECONDS:
            print(f"Dropping queued message {item.get('id')} after {age}s (max {MAX_RETRY_WINDOW_SECONDS}s)")
            item_path.unlink(missing_ok=True)
            continue

        if (now - last_attempt_at) < RETRY_INTERVAL_SECONDS:
            continue

        try:
            _post_payload(item["payload"])
            print(f"Retried queued message {item.get('id')} successfully")
            item_path.unlink(missing_ok=True)
        except Exception as exc:
            item["attempts"] = int(item.get("attempts", 0)) + 1
            item["last_attempt_at"] = now
            item["last_error"] = str(exc)[:500]
            item_path.write_text(json.dumps(item), encoding="utf-8")
            print(f"Retry failed for {item.get('id')}: {exc}")


def verify_bind(host: str, port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
        s.listen(1)
        print(f"Verified bind {host}:{port}")
    finally:
        s.close()


if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = 10025

    verify_bind(HOST, PORT)

    handler = EmailHandler()
    controller = Controller(handler, hostname=HOST, port=PORT)

    print("Starting aiosmtpd controller...")
    controller.start()
    print(f"Email bridge listening on {HOST}:{PORT}")
    print(f"Ingest target: {INGEST_URL}")
    print(
        f"Accepted recipients: {CHECK_ADDR}, {DEMO_ADDR}, {COMPLAINT_ADDR}, {BOUNCE_ADDR} "
        f"(domain from MAILTEST_DOMAIN)"
    )
    print(
        f"Retry policy: every {RETRY_INTERVAL_SECONDS}s, "
        f"drop after {MAX_RETRY_WINDOW_SECONDS}s; queue={QUEUE_DIR}"
    )
    print(
        f"Global rate cap: {BRIDGE_RATE_CAP} messages per "
        f"{BRIDGE_RATE_WINDOW_SECONDS}s (all sources combined)"
    )

    try:
        last_retry_run = 0
        while True:
            now = int(time.time())
            if now - last_retry_run >= 5:
                _process_retry_queue()
                last_retry_run = now
            time.sleep(5)
    except KeyboardInterrupt:
        print("Stopping controller...")
        controller.stop()
        sys.exit(0)
