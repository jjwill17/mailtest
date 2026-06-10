from __future__ import annotations

from typing import Any, Dict
import base64

from .auth import build_auth_details, fallback_auth_results, parse_auth_results
from .checks import run_all_checks
from .parsing import (
    build_mime_tree,
    compute_content_metrics,
    extract_header_facts,
    extract_headers,
    extract_links_and_images,
    get_preferred_html_body,
    get_preferred_text_body,
    parse_message,
)
from .platform import detect_platform
from .scoring import aggregate_deliverability


def analyze_message(raw_message: str, raw_message_b64: str | None = None) -> Dict[str, Any]:
    raw_message_bytes: bytes | None = None
    if raw_message_b64:
        try:
            raw_message_bytes = base64.b64decode(raw_message_b64, validate=True)
        except Exception:
            raw_message_bytes = None

    msg = parse_message(raw_message)
    headers = extract_headers(msg)
    parsed_subject = (msg.get("subject") or "").strip() or None
    mime_tree = build_mime_tree(msg)
    header_facts = extract_header_facts(headers)
    platform = detect_platform(headers, header_facts)

    auth_results = parse_auth_results(headers)
    auth_results = fallback_auth_results(
        raw_message=raw_message,
        raw_message_bytes=raw_message_bytes,
        headers=headers,
        header_facts=header_facts,
        auth_results=auth_results,
    )
    auth_details = build_auth_details(
        raw_message=raw_message,
        raw_message_bytes=raw_message_bytes,
        headers=headers,
        header_facts=header_facts,
        auth_results=auth_results,
    )

    text_body = get_preferred_text_body(mime_tree)
    html_body = get_preferred_html_body(mime_tree)
    links_images = extract_links_and_images(html_body)
    content_metrics = compute_content_metrics(
        text_body=text_body,
        html_body=html_body,
        total_links=links_images["total_links"],
        total_images=links_images["total_images"],
    )

    facts_blob = {
        "auth_results": auth_results,
        "auth_details": auth_details,
        "platform": platform,
        "header_facts": header_facts,
        "content_metrics": content_metrics,
        "total_links": links_images["total_links"],
        "total_images": links_images["total_images"],
    }
    analysis_for_checks: Dict[str, Any] = {
        "auth_results": auth_results,
        "auth_details": auth_details,
        "platform": platform,
        "header_facts": header_facts,
        "content_metrics": content_metrics,
        "links": links_images["links"],
        "total_links": links_images["total_links"],
        "total_images": links_images["total_images"],
    }
    checks = run_all_checks(analysis_for_checks)
    deliverability = aggregate_deliverability(checks=checks, facts=facts_blob)

    return {
        "subject": parsed_subject,
        "headers": headers,
        "header_facts": header_facts,
        "platform": platform,
        "mime_tree": mime_tree,
        "auth_results": auth_results,
        "auth_details": auth_details,
        **links_images,
        "text_body": text_body,
        "html_body": html_body,
        "content_metrics": content_metrics,
        "deliverability": deliverability,
    }
