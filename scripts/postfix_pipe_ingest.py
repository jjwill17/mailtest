#!/usr/bin/env python3
"""
Postfix pipe(8) delivery agent: read the full message bytes from stdin and POST to mailtest /ingest.

Install on the VPS (example):
  install -m 755 scripts/postfix_pipe_ingest.py /usr/local/lib/mailtest/postfix_pipe_ingest.py

The wrapper shell script (/usr/local/bin/mailtest-pipe-ingest) must pass recipient(s) through:

  #!/bin/sh
  export INGEST_URL=http://127.0.0.1:18080/ingest
  export SOURCE=postfix-pipe
  exec /usr/bin/python3 /usr/local/lib/mailtest/postfix_pipe_ingest.py "$@"

And master.cf must pass ${recipient} so this script can detect the simulator local-part:

  mailtest-pipe unix  -  n  n  -  -  pipe
    flags= user=nobody argv=/usr/local/bin/mailtest-pipe-ingest ${recipient}

Environment:
  INGEST_URL        Required, e.g. http://127.0.0.1:18080/ingest (SSH reverse tunnel to home API).
  SOURCE            Optional. Default: postfix-pipe.
  MAILTEST_DOMAIN   Optional. Default: mailtest.justfortesting.xyz. Used to detect
                    the complaint@<domain> mailbox simulator like Amazon SES.
  RECIPIENT         Optional fallback if argv is not passed.

Simulator behavior (Amazon SES parity):
  * complaint@<domain>  -> normal capture + an extra RFC 5965 feedback-report (ARF) capture.
  * bounce@<domain>     -> not expected here. Postfix smtpd_recipient_restrictions /
                           recipient_access rejects that RCPT with 550 5.1.1 BEFORE the
                           pipe runs, matching Amazon SES bounce@simulator.amazonses.com.
"""
from __future__ import annotations

import base64
import email.utils
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid


def _default_domain() -> str:
    return (os.environ.get("MAILTEST_DOMAIN") or "mailtest.justfortesting.xyz").strip().lower()


def _parse_recipients(argv: list[str]) -> list[str]:
    """
    Postfix's ${recipient} may arrive as:
      - one argv entry per recipient, or
      - a single argv entry that is a comma/space separated list.
    Normalize to a flat list of lowercased addr-specs.
    """
    raw_parts: list[str] = []
    for a in argv[1:]:
        for chunk in a.replace(";", ",").split(","):
            chunk = chunk.strip()
            if chunk:
                raw_parts.append(chunk)
    if not raw_parts:
        env_r = (os.environ.get("RECIPIENT") or "").strip()
        if env_r:
            raw_parts.append(env_r)

    out: list[str] = []
    for r in raw_parts:
        if r.startswith("<") and r.endswith(">"):
            r = r[1:-1].strip()
        if r:
            out.append(r.lower())
    return out


def _normalize_addr_spec(value: str) -> str:
    return (value or "").strip().strip("<>").strip()


def _postfix_envelope_sender() -> str:
    """
    Postfix pipe(8) exports the envelope sender as $sender in the child environment.
    This is the true MAIL FROM (bounce address), not the friendly From: header.
    """
    raw = (os.environ.get("sender") or os.environ.get("SENDER") or "").strip()
    return _normalize_addr_spec(raw)


_RETURN_PATH_HEADER_RE = re.compile(r"(?im)^return-path:")


def _apply_capture_headers(raw_text: str, envelope_from: str) -> str:
    """Record SMTP MAIL FROM; mirror as Return-Path when absent (do not use pipe R=)."""
    # Null sender stays as the bare token "<>" on the Return-Path line; only real
    # addresses are wrapped in angle brackets, otherwise we'd emit "<<>>" (invalid).
    if envelope_from:
        x_value = envelope_from
        return_path_value = f"<{envelope_from}>"
    else:
        x_value = "<>"
        return_path_value = "<>"
    lines = [f"X-Mailtest-Envelope-From: {x_value}"]
    if not _RETURN_PATH_HEADER_RE.search(raw_text):
        lines.append(f"Return-Path: {return_path_value}")
    return "\n".join(lines) + "\n" + raw_text


def _post_ingest(ingest_url: str, payload: dict) -> int:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        ingest_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            _ = resp.read()
            return resp.getcode()
    except urllib.error.HTTPError as exc:
        print(f"mailtest-pipe-ingest: HTTP {exc.code} {exc.read()[:500]!r}", file=sys.stderr)
        return exc.code or 599
    except Exception as exc:
        print(f"mailtest-pipe-ingest: request failed: {exc}", file=sys.stderr)
        return 599


def _build_arf(
    *,
    domain: str,
    recipient: str,
    original_text: str,
) -> bytes:
    """
    Minimal RFC 5965 abuse feedback report (multipart/report; report-type=feedback-report).
    Structure: text/plain + message/feedback-report + message/rfc822.
    """
    boundary = f"mailtest_{uuid.uuid4().hex}"
    now = email.utils.formatdate(localtime=True)

    human = (
        f"This is an email abuse report for a message handled by the Mailtest mailbox "
        f"simulator (complaint@{domain}). For ARF details see RFC 5965.\r\n"
    )
    feedback_block = (
        "Feedback-Type: abuse\r\n"
        "User-Agent: Mailtest-Simulator/1.0\r\n"
        "Version: 1\r\n"
        f"Original-Rcpt-To: <{recipient}>\r\n"
        f"Arrival-Date: {now}\r\n"
        f"Reporting-MTA: dns; {domain}\r\n"
        "\r\n"
    )

    rfc822 = original_text.replace("\r\n", "\n")
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

    headers = [
        f"From: Mailtest Simulator <noreply@{domain}>",
        f"To: <postmaster@{domain}>",
        "Subject: Mailtest abuse feedback report (RFC 5965 simulator)",
        "MIME-Version: 1.0",
        f"Date: {now}",
        f'Content-Type: multipart/report; report-type=feedback-report; boundary="{boundary}"',
        "",
    ]
    msg = "\r\n".join(headers) + "".join(parts)
    return msg.encode("utf-8")


def main() -> int:
    ingest_url = (os.environ.get("INGEST_URL") or "").strip()
    if not ingest_url:
        print("mailtest-pipe-ingest: INGEST_URL is not set", file=sys.stderr)
        return 1

    default_source = (os.environ.get("SOURCE") or "postfix-pipe").strip()
    domain = _default_domain()
    recipients = _parse_recipients(sys.argv)
    is_complaint = any(r == f"complaint@{domain}" for r in recipients)

    raw = sys.stdin.buffer.read()
    if not raw:
        print("mailtest-pipe-ingest: empty stdin", file=sys.stderr)
        return 1

    raw_b64 = base64.b64encode(raw).decode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    raw_text = raw.decode("utf-8", errors="replace")
    envelope_from = _postfix_envelope_sender()
    raw_text = _apply_capture_headers(raw_text, envelope_from)

    primary_source = "postfix-pipe-complaint-simulator" if is_complaint else default_source
    primary_subject = "SMTP capture (complaint simulator)" if is_complaint else "SMTP capture"
    primary = {
        "subject": primary_subject,
        "raw_message": raw_text,
        "raw_message_b64": raw_b64,
        "raw_sha256": digest,
        "source": primary_source,
        "smtp_envelope_from": envelope_from or None,
    }
    code = _post_ingest(ingest_url, primary)
    if code >= 400:
        print(f"mailtest-pipe-ingest: primary ingest failed status={code}", file=sys.stderr)
        return 1

    if is_complaint:
        arf_bytes = _build_arf(
            domain=domain,
            recipient=f"complaint@{domain}",
            original_text=raw_text,
        )
        arf_payload = {
            "subject": "Abuse feedback report (Mailtest simulator, RFC 5965)",
            "raw_message": arf_bytes.decode("utf-8", errors="replace"),
            "raw_message_b64": base64.b64encode(arf_bytes).decode("ascii"),
            "raw_sha256": hashlib.sha256(arf_bytes).hexdigest(),
            "source": "simulator-arf",
        }
        code = _post_ingest(ingest_url, arf_payload)
        if code >= 400:
            print(
                f"mailtest-pipe-ingest: ARF ingest failed status={code} "
                f"(primary already ingested)",
                file=sys.stderr,
            )
            return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
