from __future__ import annotations

from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any, Dict, List
from urllib.parse import urlparse
import ipaddress
import re

from bs4 import BeautifulSoup

IP_RE = re.compile(r"\[([0-9a-fA-F:.]+)\]")
URL_RE = re.compile(r"https?://[^\s<>()\"']+", re.IGNORECASE)
SMTP_MAILFROM_RE = re.compile(r"\bsmtp\.mailfrom=([^\s;)]+)", re.IGNORECASE)
_RETURN_PATH_HEADER_RE = re.compile(r"(?im)^return-path:")


def parse_message(raw: str) -> Any:
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8", errors="replace")
    else:
        raw_bytes = raw
    return BytesParser(policy=policy.default).parsebytes(raw_bytes)


def extract_headers(msg: Any) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for name, value in msg.items():
        lname = name.lower()
        if lname in headers:
            headers[lname] = f"{headers[lname]}\n{value}"
        else:
            headers[lname] = str(value)
    return headers


def build_mime_tree(msg: Any) -> List[Dict[str, Any]]:
    parts: List[Dict[str, Any]] = []
    for i, part in enumerate(msg.walk()):
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        payload = part.get_payload(decode=True)
        size = len(payload) if payload else 0

        is_body = (
            not part.is_multipart()
            and disposition is None
            and content_type in ("text/plain", "text/html")
        )

        parts.append(
            {
                "index": i,
                "content_type": content_type,
                "disposition": disposition,
                "filename": filename,
                "size": size,
                "is_body": is_body,
                "payload": payload.decode("utf-8", errors="replace") if payload else "",
            }
        )
    return parts


def get_preferred_text_body(mime_tree: List[Dict[str, Any]]) -> str:
    text_parts = [p for p in mime_tree if p["content_type"] == "text/plain" and p["is_body"]]
    return text_parts[0]["payload"] if text_parts else ""


def get_preferred_html_body(mime_tree: List[Dict[str, Any]]) -> str:
    html_parts = [p for p in mime_tree if p["content_type"] == "text/html" and p["is_body"]]
    return html_parts[0]["payload"] if html_parts else ""


def extract_links_and_images(html_body: str) -> Dict[str, Any]:
    if not html_body:
        return {"links": [], "images": [], "total_links": 0, "total_images": 0}

    soup = BeautifulSoup(html_body, "html.parser")
    links: List[Dict[str, Any]] = []
    images: List[Dict[str, Any]] = []

    for a in soup.find_all("a", href=True):
        href = a["href"]
        parsed = urlparse(href)
        links.append(
            {
                "href": href,
                "domain": parsed.netloc.lower() or "",
                "text": a.get_text(strip=True)[:50],
                "is_relative": not parsed.netloc,
                "has_params": bool(parsed.query),
                "is_tracker": any(
                    token in parsed.netloc.lower()
                    for token in ("google", "facebook", "doubleclick")
                ),
            }
        )

    for img in soup.find_all("img", src=True):
        src = img["src"]
        parsed = urlparse(src)
        images.append(
            {
                "src": src,
                "domain": parsed.netloc.lower() or "",
                "alt": img.get("alt", "")[:50],
                "is_cid": src.startswith("cid:"),
                "is_relative": not parsed.netloc and not src.startswith("cid:"),
                "width": img.get("width", ""),
                "height": img.get("height", ""),
            }
        )

    return {
        "links": links[:20],
        "images": images[:20],
        "total_links": len(links),
        "total_images": len(images),
    }


def compute_content_metrics(
    *,
    text_body: str,
    html_body: str,
    total_links: int,
    total_images: int,
) -> Dict[str, Any]:
    text = (text_body or "").strip()
    html = (html_body or "").strip()

    if text:
        text_len = len(text)
        urls_in_text = len(URL_RE.findall(text))
    elif html:
        html_text = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
        text_len = len(html_text)
        urls_in_text = len(URL_RE.findall(html_text))
    else:
        text_len = 0
        urls_in_text = 0

    url_count = max(int(total_links or 0), urls_in_text)
    url_density_per_1k = (url_count / max(1, text_len)) * 1000.0
    image_count = int(total_images or 0)
    images_per_1k_chars = (image_count / max(1, text_len)) * 1000.0
    image_to_text_ratio = image_count / max(1.0, text_len / 1000.0)

    return {
        "text_length": text_len,
        "url_count": url_count,
        "url_density_per_1k_chars": round(url_density_per_1k, 2),
        "image_count": image_count,
        "images_per_1k_chars": round(images_per_1k_chars, 2),
        "image_to_text_ratio": round(image_to_text_ratio, 2),
    }


def _decode_mime_header_value(value: str) -> str:
    """Unfold MIME encoded-words (e.g. =?utf-8?b?...?=) before parseaddr."""
    if not value:
        return ""
    parts: List[str] = []
    for fragment, charset in decode_header(value):
        if isinstance(fragment, bytes):
            parts.append(fragment.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(str(fragment))
    return "".join(parts)


def extract_header_facts(headers: Dict[str, str]) -> Dict[str, Any]:
    from_raw = _decode_mime_header_value((headers.get("from") or "").strip())
    reply_to_raw = _decode_mime_header_value((headers.get("reply-to") or "").strip())
    return_path_raw = _decode_mime_header_value((headers.get("return-path") or "").strip())

    from_name, from_addr = parseaddr(from_raw)
    _, reply_to_addr = parseaddr(reply_to_raw)
    return_path_addr = return_path_raw.strip("<>").strip() if return_path_raw else ""

    received_count = 0
    for k in headers.keys():
        if k.lower() == "received":
            received_count += 1
    if received_count == 0:
        received_val = headers.get("received") or ""
        received_count = 1 if received_val else 0

    message_id = (headers.get("message-id") or "").strip()
    date = (headers.get("date") or "").strip()

    def _domain(addr: str) -> str:
        addr = (addr or "").strip()
        if "@" not in addr:
            return ""
        return addr.rsplit("@", 1)[-1].lower()

    facts: Dict[str, Any] = {
        "from_raw": from_raw or None,
        "from_name": from_name or None,
        "from_addr": from_addr or None,
        "from_domain": _domain(from_addr),
        "reply_to_raw": reply_to_raw or None,
        "reply_to_addr": reply_to_addr or None,
        "reply_to_domain": _domain(reply_to_addr),
        "return_path_raw": return_path_raw or None,
        "return_path_addr": return_path_addr or None,
        "return_path_domain": _domain(return_path_addr),
        "message_id": message_id or None,
        "has_message_id": bool(message_id),
        "date": date or None,
        "has_date": bool(date),
        "received_count": received_count,
    }
    facts["envelope_from_source"] = envelope_from_source(headers, facts)
    return facts


def extract_sender_ip(headers: Dict[str, str]) -> str:
    explicit = (headers.get("x-mailtest-client-ip") or "").strip()
    if explicit:
        try:
            ipaddress.ip_address(explicit)
            return explicit
        except ValueError:
            pass

    for line in (headers.get("received") or "").splitlines():
        m = IP_RE.search(line)
        if not m:
            continue
        candidate = m.group(1).strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return ""


def _normalize_addr_spec(value: str) -> str:
    return (value or "").strip().strip("<>").strip()


def apply_smtp_session_metadata(
    raw_message: str,
    *,
    envelope_from: str | None = None,
    client_ip: str | None = None,
) -> str:
    """
    Stamp SMTP session facts onto the message before analysis.

    Used when the inbound MTA (VPS Postfix or home bridge) knows MAIL FROM from the
    SMTP envelope but the MIME body lacks Return-Path (common on pipe/relay paths).
    """
    if re.search(r"(?im)^x-mailtest-envelope-from:", raw_message or ""):
        return raw_message
    lines: List[str] = []
    if envelope_from is not None:
        display = _normalize_addr_spec(envelope_from) if envelope_from else "<>"
        lines.append(f"X-Mailtest-Envelope-From: {display}")
        if not _RETURN_PATH_HEADER_RE.search(raw_message):
            lines.append(f"Return-Path: <{display}>")
    if client_ip:
        lines.append(f"X-Mailtest-Client-IP: {client_ip.strip()}")
    if not lines:
        return raw_message
    return "\n".join(lines) + "\n" + raw_message


def _extract_smtp_mailfrom_from_auth_headers(headers: Dict[str, str]) -> str:
    """Best-effort MAIL FROM from upstream Authentication-Results / Received-SPF."""
    blobs = [
        headers.get("received-spf") or "",
        headers.get("authentication-results") or "",
        headers.get("authentication-results-original") or "",
        headers.get("arc-authentication-results") or "",
    ]
    for blob in blobs:
        for match in SMTP_MAILFROM_RE.finditer(blob):
            addr = _normalize_addr_spec(match.group(1))
            if "@" in addr:
                return addr
    return ""


def envelope_from_source(headers: Dict[str, str], header_facts: Dict[str, Any]) -> str:
    """Where we got the envelope sender used for SPF (for UI/debugging)."""
    if "x-mailtest-envelope-from" in headers:
        return "smtp-envelope"
    if (header_facts.get("return_path_addr") or "").strip():
        return "return-path"
    if _extract_smtp_mailfrom_from_auth_headers(headers):
        return "authentication-results"
    if (header_facts.get("from_addr") or "").strip():
        return "header-from-fallback"
    return "unknown"


def extract_envelope_from(headers: Dict[str, str], header_facts: Dict[str, Any]) -> str:
    # Captured at ingest (bridge SMTP session or Postfix pipe $sender). Authoritative
    # even when empty/null (<>), so we do not fall back to Header From.
    if "x-mailtest-envelope-from" in headers:
        return _normalize_addr_spec(headers.get("x-mailtest-envelope-from") or "")

    return_path = (header_facts.get("return_path_addr") or "").strip()
    if return_path:
        return return_path

    ar_mailfrom = _extract_smtp_mailfrom_from_auth_headers(headers)
    if ar_mailfrom:
        return ar_mailfrom

    return (header_facts.get("from_addr") or "").strip()
