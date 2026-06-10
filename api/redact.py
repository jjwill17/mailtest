"""PII redaction helpers for the public demo.

The project is intentionally exposed on the public internet as a portfolio
demo. Without these helpers, anyone could see (or scrape via /tests,
/export, or the UI) the real email addresses of everyone who sent a test
through the service.

Design goals
------------
- Keep the *analytical* value of a test intact: grades, auth results,
  domain-level alignment checks, platform detection, links/images, etc.
  remain fully visible.
- Mask direct PII: specifically the envelope-from address on the SPF
  card, and anywhere else we later decide to treat as PII.
- Replace free-form blobs (raw message, parsed-headers dump) with an
  explicit placeholder string rather than trying to regex-scrub them,
  which is both fragile and easy to miss one field.
- Be non-destructive: never mutate a SQLAlchemy-loaded row. Every
  helper here returns a deep-copied, redacted value so the original
  ORM objects and database rows are untouched.

Redaction format
----------------
Emails:    ``justin@example.com`` -> ``j*****@example.com``
Always five stars regardless of original length (so a short local part
like ``jw`` doesn't leak its length via the redacted representation,
and a long one doesn't either).
"""

from __future__ import annotations

import copy
import re
from typing import Any

REDACT_STARS = "*****"

REDACTED_EXPORT_RAW = (
    "[REDACTED in demo export. Unlock Admin to export the full raw message.]"
)
REDACTED_EXPORT_RAW_B64 = (
    "[REDACTED in demo export. Unlock Admin to export the base64 raw message.]"
)
REDACTED_EXPORT_HEADERS = (
    "[REDACTED in demo export. Unlock Admin to export the full parsed headers.]"
)
REDACTED_EXPORT_MIME_PAYLOAD = (
    "[REDACTED in demo export. Unlock Admin to export MIME part payloads.]"
)

REDACTED_UI_RAW = (
    "Raw message is hidden in demo mode. Click Admin (top-right), enter your key, "
    "then use 'Load raw message' below to view it."
)
REDACTED_UI_HEADERS = (
    "Full parsed headers are hidden in demo mode. Click Admin (top-right), enter "
    "your key, then use 'Load full headers' below to view them."
)

# Dict keys whose values are a single bare email address. These get masked
# with the 5-star rule (``j*****@domain``). Applies anywhere the key
# appears inside the nested export/deliverability structure.
_EMAIL_KEYS: frozenset[str] = frozenset({
    "envelope_from",
    "from_addr",
    "reply_to_addr",
    "return_path_addr",
    "message_id",
})

# Dict keys whose values may contain an email inside a longer string
# (typically ``"Display Name <local@domain>"``). For these we preserve the
# surrounding text (so the display name your earlier decision asked to
# keep is still visible) and only mask the embedded email address.
_EMAIL_IN_STRING_KEYS: frozenset[str] = frozenset({
    "from_raw",
    "reply_to_raw",
    "return_path_raw",
})

# Intentionally lenient RFC-2822-ish email pattern. Captures the first char
# of the local part and the domain so we can build the masked replacement.
_EMBEDDED_EMAIL_RE = re.compile(
    r"([A-Za-z0-9])[A-Za-z0-9._%+\-]*@([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})"
)


def redact_email(value: Any) -> Any:
    """Mask a single email-address string.

    - Returns ``j*****@domain`` for a valid ``local@domain`` string.
    - Preserves ``<...>`` brackets if the input was bracketed (common for
      Message-IDs and Return-Path values).
    - Passes through non-strings, empty strings, or strings with no ``@``
      untouched (so we don't accidentally transform ``n/a`` or ``None``).
    """
    if not isinstance(value, str):
        return value
    s = value.strip()
    if not s or "@" not in s:
        return value

    has_brackets = s.startswith("<") and s.endswith(">")
    if has_brackets:
        s = s[1:-1].strip()

    local, _, domain = s.rpartition("@")
    local = local.strip()
    domain = domain.strip()
    if not local or not domain:
        return value

    masked = f"{local[0]}{REDACT_STARS}@{domain}"
    return f"<{masked}>" if has_brackets else masked


def _redact_embedded_emails(value: Any) -> Any:
    """Mask every email-like substring inside a longer string.

    Used for fields like ``from_raw`` whose value is something like
    ``"Justin Willmore <justinjwillmore@gmail.com>"`` — we want to keep
    the display name (per the demo's redaction policy) and mask only the
    address itself, resulting in ``"Justin Willmore <j*****@gmail.com>"``.
    """
    if not isinstance(value, str) or not value:
        return value
    return _EMBEDDED_EMAIL_RE.sub(
        lambda m: f"{m.group(1)}{REDACT_STARS}@{m.group(2)}",
        value,
    )


def _redact_pii_in_place(node: Any) -> None:
    """Recursively mask known-PII keys anywhere inside a nested container."""
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if k in _EMAIL_KEYS:
                node[k] = redact_email(v)
            elif k in _EMAIL_IN_STRING_KEYS:
                node[k] = _redact_embedded_emails(v)
            else:
                _redact_pii_in_place(v)
    elif isinstance(node, list):
        for item in node:
            _redact_pii_in_place(item)


def redact_deliverability(deliverability: Any) -> Any:
    """Return a deep-copied, PII-redacted version of a deliverability payload.

    No-op for falsy / None inputs so template code can safely chain on it.
    """
    if not deliverability:
        return deliverability
    cloned = copy.deepcopy(deliverability)
    _redact_pii_in_place(cloned)
    return cloned


def redact_export_payload(payload: dict) -> dict:
    """Return a deep-copied export payload suitable for a non-admin viewer.

    - Masks every known PII key everywhere it appears inside nested data
      (``envelope_from``, ``from_addr``, ``from_raw``, ``reply_to_*``,
      ``return_path_*``, ``message_id``, ...).
    - Replaces ``raw_message``, ``raw_message_b64``, ``headers``, and
      each MIME part's ``payload`` with a human-readable placeholder.
      Keys remain present so downstream tooling doesn't choke on missing
      fields; the placeholder value makes the reason explicit.
    """
    cloned = copy.deepcopy(payload)
    _redact_pii_in_place(cloned)
    if "raw_message" in cloned:
        cloned["raw_message"] = REDACTED_EXPORT_RAW
    if "raw_message_b64" in cloned:
        cloned["raw_message_b64"] = REDACTED_EXPORT_RAW_B64
    if "headers" in cloned:
        cloned["headers"] = REDACTED_EXPORT_HEADERS

    # MIME payloads hold the parsed body text, which is whatever the
    # contributor typed into their email and must not be exposed in the
    # public export. We only touch the `payload` key, leaving metadata
    # (content_type, size, filename, etc.) intact for structural debug.
    mime_tree = cloned.get("mime_tree")
    if isinstance(mime_tree, list):
        for part in mime_tree:
            if isinstance(part, dict) and part.get("payload"):
                part["payload"] = REDACTED_EXPORT_MIME_PAYLOAD

    return cloned
