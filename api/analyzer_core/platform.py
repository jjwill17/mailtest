from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

_SMTP_COM_HOST_RE = re.compile(
    r"(?:^|[\s(\[@<,])([a-z0-9][a-z0-9.-]*\.smtp\.com)\b",
    re.IGNORECASE,
)


def _contains_any(text: str, needles: List[str]) -> bool:
    t = (text or "").lower()
    return any(n in t for n in needles)


def _domain_is_under(host: str, parent: str) -> bool:
    h = (host or "").lower().rstrip(".")
    p = (parent or "").lower().lstrip(".")
    return bool(p and (h == p or h.endswith("." + p)))


def _x_mailtest_envelope_domain(headers: Dict[str, str]) -> str:
    """Bridge captures SMTP MAIL FROM in X-Mailtest-Envelope-From (Return-Path often absent in the MIME)."""
    raw = (headers.get("x-mailtest-envelope-from") or "").strip().strip("<>")
    if not raw or "@" not in raw:
        return ""
    return raw.rsplit("@", 1)[-1].lower().rstrip(".")


def _platform_candidates(headers: Dict[str, str], header_facts: Dict[str, Any]) -> List[Tuple[str, int, str]]:
    candidates: List[Tuple[str, int, str]] = []

    from_domain = (header_facts.get("from_domain") or "").lower()
    return_path_domain = (header_facts.get("return_path_domain") or "").lower()
    envelope_mail_domain = _x_mailtest_envelope_domain(headers)
    authres = (headers.get("authentication-results") or "").lower()
    received = (headers.get("received") or "").lower()
    dkim_sig = (headers.get("dkim-signature") or "").lower()
    all_headers_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items()).lower()

    # Gmail / Google Workspace
    if from_domain == "gmail.com" or _contains_any(authres, ["header.from=gmail.com"]) or _contains_any(
        received, ["google.com", "gmail.com", "googlemail.com", "1e100.net"]
    ):
        candidates.append(("Gmail", 90 if from_domain == "gmail.com" else 75, "Google/Gmail header fingerprint"))
    if _contains_any(dkim_sig, [" d=gmail.com", " d=1e100.net"]):
        candidates.append(("Gmail", 80, "DKIM signed by Google"))

    # AWS SES
    if _contains_any(all_headers_blob, ["x-ses-", "amazonses.com", "amazonses"]):
        candidates.append(("AWS SES", 88, "SES-specific header/domain fingerprint"))
    if _contains_any(received, ["amazonses.com"]):
        candidates.append(("AWS SES", 80, "Received chain references amazonses.com"))

    # SparkPost
    if _contains_any(all_headers_blob, ["x-msys-api", "x-msys-message-id", "sparkpost", "sparkpostmail.com"]):
        candidates.append(("SparkPost", 88, "SparkPost-specific header/domain fingerprint"))
    if _contains_any(received, ["sparkpostmail.com", "smtp.sparkpostmail.com"]):
        candidates.append(("SparkPost", 80, "Received chain references SparkPost infrastructure"))

    # SendGrid
    if _contains_any(all_headers_blob, ["x-sg-id", "x-sg-eid", "sendgrid.net", "sendgrid"]):
        candidates.append(("SendGrid", 86, "SendGrid-specific header/domain fingerprint"))

    # SMTP.com (MAIL FROM often only appears as X-Mailtest-Envelope-From on bridge ingest)
    if _domain_is_under(return_path_domain, "smtp.com") or _domain_is_under(envelope_mail_domain, "smtp.com"):
        candidates.append(
            (
                "SMTP.com",
                94,
                "MAIL FROM domain under smtp.com (X-Mailtest-Envelope-From or Return-Path)",
            )
        )
    if _SMTP_COM_HOST_RE.search(received or ""):
        candidates.append(("SMTP.com", 80, "Received chain references smtp.com infrastructure"))

    # Mailgun
    if _contains_any(all_headers_blob, ["x-mailgun-", "mailgun.org", "mailgun"]):
        candidates.append(("Mailgun", 86, "Mailgun-specific header/domain fingerprint"))

    # Microsoft 365 / Outlook
    if _contains_any(received, ["protection.outlook.com", "outbound.protection.outlook.com"]) or _contains_any(
        all_headers_blob, ["microsoft", "outlook.com"]
    ):
        candidates.append(("Microsoft 365", 76, "Microsoft mail protection/outbound fingerprint"))

    # Brevo (Sendinblue)
    if _contains_any(all_headers_blob, ["sendinblue", "brevo"]):
        candidates.append(("Brevo", 82, "Brevo/Sendinblue header fingerprint"))

    # Postmark
    if _contains_any(all_headers_blob, ["postmarkapp.com", "x-pm-message-id", "postmark"]):
        candidates.append(("Postmark", 86, "Postmark header/domain fingerprint"))

    # Fallback to mailbox provider when obvious but not an ESP
    if from_domain in {"yahoo.com", "outlook.com", "hotmail.com", "icloud.com"}:
        mailbox_map = {
            "yahoo.com": "Yahoo Mail",
            "outlook.com": "Outlook.com",
            "hotmail.com": "Outlook.com",
            "icloud.com": "iCloud Mail",
        }
        candidates.append((mailbox_map[from_domain], 70, "Consumer mailbox sender domain"))

    if return_path_domain and return_path_domain == from_domain and not candidates:
        candidates.append(("Self-hosted / Unknown", 45, "No clear ESP markers; sender and return-path align"))

    return candidates


def detect_platform(headers: Dict[str, str], header_facts: Dict[str, Any]) -> Dict[str, Any]:
    candidates = _platform_candidates(headers, header_facts)
    if not candidates:
        return {"name": "Unknown", "confidence": 0, "reason": "No provider fingerprint matched"}

    best = sorted(candidates, key=lambda c: c[1], reverse=True)[0]
    return {
        "name": best[0],
        "confidence": int(best[1]),
        "reason": best[2],
        "candidates": [
            {"name": name, "confidence": conf, "reason": reason}
            for name, conf, reason in sorted(candidates, key=lambda c: c[1], reverse=True)[:4]
        ],
    }
