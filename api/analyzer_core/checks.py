from __future__ import annotations

from typing import Any, Dict, List


def make_check(
    *,
    check_id: str,
    category: str,
    status: str,
    severity: str,
    message: str,
    impact: int = 0,
    evidence: Dict[str, Any] | None = None,
    fix: str | None = None,
) -> Dict[str, Any]:
    return {
        "id": check_id,
        "category": category,
        "status": status,
        "severity": severity,
        "message": message,
        "impact": impact,
        "evidence": evidence or {},
        "fix": fix,
    }


def run_auth_checks(auth: Dict[str, Any], auth_details: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    details = auth_details or {}

    for mech in ("spf", "dkim", "dmarc"):
        result = (auth.get(mech) or "none").lower()
        if mech == "spf" and result in ("pass", "none"):
            checks.append(
                make_check(
                    check_id=f"auth.{mech}.result",
                    category="auth",
                    status="pass" if result == "pass" else "info",
                    severity="info",
                    message=f"{mech.upper()} result: {result}",
                    impact=0,
                    evidence={mech: result},
                )
            )
            continue

        if result == "pass":
            checks.append(
                make_check(
                    check_id=f"auth.{mech}.result",
                    category="auth",
                    status="pass",
                    severity="info",
                    message=f"{mech.upper()} passed",
                    evidence={mech: result},
                )
            )
        else:
            checks.append(
                make_check(
                    check_id=f"auth.{mech}.result",
                    category="auth",
                    status="fail",
                    severity="fail",
                    message=f"{mech.upper()} result: {result}",
                    impact=-25,
                    evidence={mech: result},
                    fix=f"Ensure {mech.upper()} authentication is configured and aligned for the From domain.",
                )
            )
    spf_details = details.get("spf") or {}
    lookup_estimate = int(spf_details.get("lookup_estimate") or 0)
    if lookup_estimate > 10:
        checks.append(
            make_check(
                check_id="auth.spf.lookup_limit",
                category="auth",
                status="warn",
                severity="warn",
                message=f"Estimated SPF DNS lookup depth exceeds RFC limit (estimate={lookup_estimate})",
                impact=-10,
                evidence={"lookup_estimate": lookup_estimate, "spf_domain": spf_details.get("domain")},
                fix="Reduce SPF includes/mechanisms to keep DNS-lookup depth at 10 or fewer.",
            )
        )

    if not spf_details.get("record"):
        checks.append(
            make_check(
                check_id="auth.spf.record_missing",
                category="auth",
                status="warn",
                severity="warn",
                message="No SPF record found for evaluated MAIL FROM domain",
                impact=-10,
                evidence={"spf_domain": spf_details.get("domain"), "lookup_error": spf_details.get("lookup_error")},
                fix="Publish a valid SPF TXT record for the envelope sender domain.",
            )
        )

    dkim_details = details.get("dkim") or {}
    signatures = dkim_details.get("signatures") or []
    if not signatures:
        checks.append(
            make_check(
                check_id="auth.dkim.signature_missing",
                category="auth",
                status="warn",
                severity="warn",
                message="No DKIM-Signature header found",
                impact=-10,
                fix="Sign outbound mail with DKIM using at least one stable selector.",
            )
        )
    else:
        for sig in signatures[:3]:
            selector = sig.get("selector") or "(missing)"
            domain = sig.get("domain") or "(missing)"
            if selector == "(missing)" or domain == "(missing)":
                checks.append(
                    make_check(
                        check_id="auth.dkim.signature_malformed",
                        category="auth",
                        status="warn",
                        severity="warn",
                        message="DKIM signature is missing d= or s= tag",
                        impact=-10,
                        evidence={"signature": sig},
                        fix="Ensure DKIM signatures include both d= and s= tags.",
                    )
                )
                break
            checks.append(
                make_check(
                    check_id=f"auth.dkim.signature.{sig.get('index', 0)}",
                    category="auth",
                    status="info",
                    severity="info",
                    message=f"DKIM signature observed (d={domain}, s={selector})",
                    evidence={"signature": sig},
                )
            )

    dmarc_details = details.get("dmarc") or {}
    alignment = details.get("alignment") or {}

    if not dmarc_details.get("record"):
        checks.append(
            make_check(
                check_id="auth.dmarc.record_missing",
                category="auth",
                status="warn",
                severity="warn",
                message="No DMARC record found for Header From domain",
                impact=-10,
                evidence={
                    "from_domain": dmarc_details.get("from_domain"),
                    "lookup_error": dmarc_details.get("lookup_error"),
                },
                fix="Publish a DMARC TXT record at _dmarc.<from-domain>; receivers also check parent domains per RFC 7489.",
            )
        )
    else:
        policy = dmarc_details.get("policy")
        checks.append(
            make_check(
                check_id="auth.dmarc.policy",
                category="auth",
                status="info",
                severity="info",
                message=f"DMARC policy observed: p={policy or 'unspecified'}",
                evidence={
                    "policy": policy,
                    "adkim": dmarc_details.get("adkim"),
                    "aspf": dmarc_details.get("aspf"),
                    "record_domain": dmarc_details.get("record_domain"),
                    "record_source": dmarc_details.get("record_source"),
                },
            )
        )

    if alignment:
        if alignment.get("dmarc_aligned"):
            checks.append(
                make_check(
                    check_id="auth.dmarc.alignment",
                    category="auth",
                    status="pass",
                    severity="info",
                    message="At least one aligned identifier passed (SPF or DKIM)",
                    evidence=alignment,
                )
            )
        else:
            checks.append(
                make_check(
                    check_id="auth.dmarc.alignment",
                    category="auth",
                    status="fail",
                    severity="fail",
                    message="No aligned SPF or DKIM identifier for Header From domain",
                    impact=-15,
                    evidence=alignment,
                    fix="Align MAIL FROM and/or DKIM d= with the visible From domain.",
                )
            )

    return checks


def run_content_checks(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    total_links = int(analysis.get("total_links") or 0)
    metrics = analysis.get("content_metrics") or {}

    if total_links > 15:
        checks.append(
            make_check(
                check_id="content.links.excessive",
                category="content",
                status="warn",
                severity="warn",
                message=f"Excessive links: {total_links}",
                impact=-10,
                evidence={"total_links": total_links},
                fix="Reduce link count and concentrate CTAs into fewer, high-trust links.",
            )
        )

    url_density = metrics.get("url_density_per_1k_chars")
    if isinstance(url_density, (int, float)):
        if url_density >= 8:
            checks.append(
                make_check(
                    check_id="content.url_density.high",
                    category="content",
                    status="warn",
                    severity="warn",
                    message=f"High URL density ({url_density}/1k chars)",
                    impact=-10,
                    evidence={"url_density_per_1k_chars": url_density},
                    fix="Increase explanatory text and reduce dense clusters of links.",
                )
            )
        elif url_density >= 4:
            checks.append(
                make_check(
                    check_id="content.url_density.moderate",
                    category="content",
                    status="info",
                    severity="info",
                    message=f"Moderate URL density ({url_density}/1k chars)",
                    impact=-5,
                    evidence={"url_density_per_1k_chars": url_density},
                )
            )

    img_ratio = metrics.get("image_to_text_ratio")
    if isinstance(img_ratio, (int, float)) and img_ratio >= 8:
        checks.append(
            make_check(
                check_id="content.image_heavy",
                category="content",
                status="warn",
                severity="warn",
                message=f"Image-heavy content (ratio {img_ratio})",
                impact=-10,
                evidence={"image_to_text_ratio": img_ratio},
                fix="Add more live text content and reduce dependency on image-only messaging.",
            )
        )

    tracker_links = sum(1 for link in analysis.get("links", []) if link.get("is_tracker"))
    if tracker_links > 2:
        checks.append(
            make_check(
                check_id="content.trackers",
                category="content",
                status="warn",
                severity="warn",
                message=f"Tracking links detected: {tracker_links}",
                impact=-10,
                evidence={"tracker_links": tracker_links},
                fix="Limit third-party tracking redirects where possible.",
            )
        )
    return checks


def run_header_checks(header_facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    if not header_facts:
        return checks

    if not header_facts.get("has_message_id", True):
        checks.append(
            make_check(
                check_id="header.message_id.missing",
                category="headers",
                status="warn",
                severity="warn",
                message="Missing Message-ID header",
                impact=-10,
                fix="Ensure your MTA injects RFC-compliant Message-ID values.",
            )
        )

    if not header_facts.get("has_date", True):
        checks.append(
            make_check(
                check_id="header.date.missing",
                category="headers",
                status="info",
                severity="info",
                message="Missing Date header",
                impact=-5,
                fix="Ensure Date is set at final message submission time.",
            )
        )

    from_domain = header_facts.get("from_domain") or ""
    reply_to_domain = header_facts.get("reply_to_domain") or ""
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        checks.append(
            make_check(
                check_id="header.reply_to.mismatch",
                category="headers",
                status="info",
                severity="info",
                message="Reply-To domain differs from From domain",
                impact=-5,
                evidence={"from_domain": from_domain, "reply_to_domain": reply_to_domain},
            )
        )

    if header_facts.get("envelope_from_source") == "header-from-fallback":
        checks.append(
            make_check(
                check_id="header.envelope_from.inferred",
                category="headers",
                status="warn",
                severity="warn",
                message=(
                    "Envelope sender (MAIL FROM) was inferred from the friendly From header; "
                    "SPF/DMARC alignment may be wrong. Use Return-Path or SMTP capture instead."
                ),
                impact=-10,
                evidence={
                    "envelope_from_source": "header-from-fallback",
                    "from_domain": from_domain,
                },
                fix=(
                    "Ensure capture records SMTP MAIL FROM (X-Mailtest-Envelope-From from the "
                    "bridge or Postfix pipe $sender), or that Return-Path is present in the MIME."
                ),
            )
        )

    return_path_domain = header_facts.get("return_path_domain") or ""
    if return_path_domain and from_domain and return_path_domain != from_domain:
        checks.append(
            make_check(
                check_id="header.return_path.mismatch",
                category="headers",
                status="info",
                severity="info",
                message="Return-Path domain differs from From domain",
                impact=-5,
                evidence={"from_domain": from_domain, "return_path_domain": return_path_domain},
            )
        )

    return checks


def run_all_checks(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    checks.extend(run_auth_checks(analysis.get("auth_results") or {}, analysis.get("auth_details") or {}))
    checks.extend(run_header_checks(analysis.get("header_facts") or {}))
    checks.extend(run_content_checks(analysis))
    return checks
