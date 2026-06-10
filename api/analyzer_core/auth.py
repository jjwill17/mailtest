from __future__ import annotations

from typing import Any, Dict, List, Tuple
import ipaddress
import re

from .parsing import extract_envelope_from, extract_sender_ip

AUTHRES_RE = re.compile(
    r"(spf|dkim|dmarc)=(pass|fail|softfail|none|neutral|temperror|permerror)",
    re.IGNORECASE,
)
DKIM_DOMAIN_RE = re.compile(r"\bd=([^;\s]+)", re.IGNORECASE)
DKIM_SELECTOR_RE = re.compile(r"\bs=([^;\s]+)", re.IGNORECASE)
HEADER_FROM_AR_RE = re.compile(r"(?i)header\.from=(@?)([^\s;)]+)")
_DMARC1_START_RE = re.compile(r"^\s*v=DMARC1\b", re.IGNORECASE)
_DMARC_AR_CLAUSE_RE = re.compile(
    r"dmarc=(pass|fail|none|softfail|neutral|permerror|temperror)\s*\(([^)]*)\)",
    re.IGNORECASE,
)
_AR_DMARC_P_RE = re.compile(r"\bp=([a-z][a-z0-9_-]*)", re.IGNORECASE)
_AR_DMARC_SP_RE = re.compile(r"\bsp=([a-z][a-z0-9_-]*)", re.IGNORECASE)
_AR_DMARC_ADKIM_RE = re.compile(r"\badkim=([sr])", re.IGNORECASE)
_AR_DMARC_ASPF_RE = re.compile(r"\baspf=([sr])", re.IGNORECASE)
_PUBLIC_DNS = ("8.8.8.8", "1.1.1.1")
SPF_LOOKUP_TOKEN_RE = re.compile(r"\b(include|a|mx|ptr|exists|redirect)\b", re.IGNORECASE)
ANY_IP_RE = re.compile(r"(?<![:\w])((?:\d{1,3}\.){3}\d{1,3})(?![:\w])")
X_SES_OUTGOING_IP_RE = re.compile(r"\b\d{4}\.\d{2}\.\d{2}-(\d{1,3}(?:\.\d{1,3}){3})\b")
_TOP_RECEIVED_HOP_RE = re.compile(r"(?is)\bfrom\s+(\S+)\s+\(\s*([^)]*)\)\s+by\b")

# Outbound MTA hostnames whose organizational domain we use when MAIL FROM was not
# captured (no Return-Path / X-Mailtest-Envelope-From) but the top Received hop matches.
_KNOWN_ESP_SUFFIXES: Tuple[str, ...] = (
    "sparkpostmail.com",
    "sendgrid.net",
    "amazonses.com",
    "mailgun.org",
    "mailgun.us",
    "mcsv.net",
    "mandrillapp.com",
    "postmarkapp.com",
    "socketlabs.com",
    "smtp2go.com",
    "mailchimp.com",
    "constantcontact.com",
    "hubspotemail.net",
)


def domain_aligns(child: str, parent: str) -> bool:
    child = (child or "").lower().strip(".")
    parent = (parent or "").lower().strip(".")
    return bool(child and parent and (child == parent or child.endswith("." + parent)))


def parse_auth_results(headers: Dict[str, str]) -> Dict[str, Any]:
    raw_candidates = [
        headers.get("authentication-results"),
        headers.get("auth-results"),
        headers.get("authentication-results-original"),
        headers.get("arc-authentication-results"),
    ]
    raw = "\n".join(v for v in raw_candidates if v)
    if not raw:
        return {"raw": None, "spf": "none", "dkim": "none", "dmarc": "none"}

    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for mech, res in AUTHRES_RE.findall(raw):
        mech = mech.lower()
        res = res.lower()
        if mech in results:
            results[mech] = res
    return {"raw": raw, **results}


def _is_public_ip(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip_obj.is_global


def _choose_sender_ip(headers: Dict[str, str]) -> str:
    # SES provides a very reliable hint: X-SES-Outgoing: YYYY.MM.DD-a.b.c.d
    x_ses_outgoing = headers.get("x-ses-outgoing") or ""
    m = X_SES_OUTGOING_IP_RE.search(x_ses_outgoing)
    if m and _is_public_ip(m.group(1)):
        return m.group(1)

    received_blob = headers.get("received") or ""
    candidates = [m.group(1) for m in ANY_IP_RE.finditer(received_blob)]
    for ip in candidates:
        if _is_public_ip(ip):
            return ip

    # Fallback to original extraction behavior.
    return extract_sender_ip(headers)


def _envelope_from_authoritative(headers: Dict[str, str], header_facts: Dict[str, Any]) -> bool:
    if "x-mailtest-envelope-from" in headers:
        return True
    if (header_facts.get("return_path_addr") or "").strip():
        return True
    if (header_facts.get("envelope_from_source") or "") == "authentication-results":
        return True
    return False


def _top_hop_helo_and_ip(received_blob: str) -> Tuple[str, str]:
    blob = (received_blob or "").strip()
    if not blob:
        return "", ""
    m = _TOP_RECEIVED_HOP_RE.search(blob)
    if not m:
        return "", ""
    helo = m.group(1).strip().strip("[]")
    inner = m.group(2)
    ipm = re.search(r"\[((?:\d{1,3}\.){3}\d{1,3})\]", inner)
    if ipm:
        return helo, ipm.group(1)
    ipm2 = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", inner)
    if ipm2:
        return helo, ipm2.group(1)
    return helo, ""


def _esp_registrable_domain(helo_hostname: str) -> str | None:
    h = (helo_hostname or "").lower().strip()
    if not h or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", h):
        return None
    for suf in _KNOWN_ESP_SUFFIXES:
        s = suf.lower()
        if h == s or h.endswith("." + s):
            return s
    return None


def _infrastructure_spf_result(sender_ip: str, helo: str) -> Tuple[str | None, str | None]:
    esp_dom = _esp_registrable_domain(helo)
    if not esp_dom:
        return None, None
    try:
        import spf  # pyspf

        spf_result, _ = spf.check2(i=sender_ip, s=f"postmaster@{esp_dom}", h=helo)
        if isinstance(spf_result, str):
            norm = spf_result.lower()
            if norm in ("pass", "fail", "softfail", "neutral", "temperror", "permerror"):
                return norm, esp_dom
    except Exception:
        return None, None
    return None, None


def _strip_mailtest_prefixed_headers(raw_message: str) -> str:
    """
    Compatibility path for older stored messages where synthetic X-Mailtest-* headers
    were prepended before ingestion. Removing them can recover DKIM verification.
    """
    lines = (raw_message or "").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.lower().startswith("x-mailtest-"):
            i += 1
            continue
        break
    if i == 0:
        return raw_message
    return "\n".join(lines[i:])


def _build_dkim_payload_candidates(raw_message: str, raw_message_bytes: bytes | None) -> List[tuple[str, bytes]]:
    source_bytes = raw_message_bytes or raw_message.encode("utf-8", errors="replace")
    stripped_bytes = _strip_mailtest_prefixed_headers(raw_message).encode("utf-8", errors="replace")
    candidates: List[tuple[str, bytes]] = [
        ("raw", source_bytes),
        ("normalized", source_bytes.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")),
        ("stripped", stripped_bytes),
        ("stripped_normalized", stripped_bytes.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")),
    ]
    deduped: List[tuple[str, bytes]] = []
    seen: set[bytes] = set()
    for mode, payload in candidates:
        if payload in seen:
            continue
        seen.add(payload)
        deduped.append((mode, payload))
    return deduped


def _extract_dkim_signatures(headers: Dict[str, str], default_result: str = "none") -> List[Dict[str, Any]]:
    dkim_blob = headers.get("dkim-signature") or ""
    if not dkim_blob:
        return []

    # Duplicate DKIM-Signature headers are collapsed with newlines by extract_headers.
    # This split is best-effort and keeps parser simple.
    chunks = [c.strip() for c in dkim_blob.splitlines() if c.strip()]
    signatures: List[Dict[str, Any]] = []
    for idx, chunk in enumerate(chunks):
        d_match = DKIM_DOMAIN_RE.search(chunk)
        s_match = DKIM_SELECTOR_RE.search(chunk)
        signatures.append(
            {
                "index": idx,
                "domain": (d_match.group(1).strip().lower() if d_match else ""),
                "selector": (s_match.group(1).strip().lower() if s_match else ""),
                "result": default_result,
            }
        )
    return signatures


def _evaluate_dkim_signatures(
    *,
    headers: Dict[str, str],
    raw_message: str,
    raw_message_bytes: bytes | None,
    default_result: str = "none",
) -> List[Dict[str, Any]]:
    signatures = _extract_dkim_signatures(headers, default_result=default_result)
    if not signatures:
        return []

    try:
        import dkim
    except Exception as exc:
        for sig in signatures:
            sig["result"] = "fail"
            sig["reason"] = f"dkimpy unavailable: {exc}"
        return signatures

    payload_candidates = _build_dkim_payload_candidates(raw_message, raw_message_bytes)
    for sig in signatures:
        idx = int(sig.get("index", 0))
        last_reason = "verification returned false"
        last_mode = None
        for mode, payload in payload_candidates:
            last_mode = mode
            try:
                verifier = dkim.DKIM(payload)
                ok = bool(verifier.verify(idx=idx))
                if ok:
                    sig["result"] = "pass"
                    sig["reason"] = None
                    sig["mode"] = mode
                    break
                last_reason = "verification returned false"
            except Exception as exc:
                last_reason = str(exc) or exc.__class__.__name__
        if sig.get("result") != "pass":
            sig["result"] = "fail"
            sig["mode"] = last_mode
            sig["reason"] = last_reason
    return signatures


def fallback_auth_results(
    *,
    raw_message: str,
    raw_message_bytes: bytes | None,
    headers: Dict[str, str],
    header_facts: Dict[str, Any],
    auth_results: Dict[str, Any],
) -> Dict[str, Any]:
    results = {
        "raw": auth_results.get("raw"),
        "spf": auth_results.get("spf", "none"),
        "dkim": auth_results.get("dkim", "none"),
        "dmarc": auth_results.get("dmarc", "none"),
    }

    if results["spf"] == "none":
        received_spf = (headers.get("received-spf") or "").lower()
        if " pass" in received_spf or received_spf.startswith("pass"):
            results["spf"] = "pass"
        elif " fail" in received_spf or received_spf.startswith("fail"):
            results["spf"] = "fail"
        elif " softfail" in received_spf:
            results["spf"] = "softfail"

    sender_ip = _choose_sender_ip(headers)
    envelope_from = extract_envelope_from(headers, header_facts)
    envelope_domain = envelope_from.rsplit("@", 1)[-1].lower() if "@" in envelope_from else ""

    envelope_pyspf_ran = False
    if results["spf"] == "none" and sender_ip and envelope_from:
        envelope_pyspf_ran = True
        try:
            import spf  # pyspf

            spf_result, _ = spf.check2(i=sender_ip, s=envelope_from, h=envelope_domain or "localhost")
            if isinstance(spf_result, str):
                spf_norm = spf_result.lower()
                if spf_norm in ("pass", "fail", "softfail", "neutral", "temperror", "permerror"):
                    results["spf"] = spf_norm
        except Exception:
            pass

    # Without Return-Path / X-Mailtest-Envelope-From we often guess MAIL FROM from the
    # Header From. ESP-delivered mail then soft-fails the brand domain's SPF even though
    # the connecting IP is authorized for the outbound MTA (e.g. sparkpostmail.com).
    if (
        envelope_pyspf_ran
        and results["spf"] in ("softfail", "fail", "neutral", "permerror", "temperror")
        and sender_ip
        and not _envelope_from_authoritative(headers, header_facts)
    ):
        helo, hop_ip = _top_hop_helo_and_ip(headers.get("received") or "")
        if hop_ip == sender_ip:
            infra_res, infra_dom = _infrastructure_spf_result(sender_ip, helo)
            if infra_res == "pass" and infra_dom:
                results["spf"] = "pass"
                results["spf_uses_infrastructure"] = True
                results["spf_infrastructure_domain"] = infra_dom

    evaluated_dkim_signatures = _evaluate_dkim_signatures(
        headers=headers,
        raw_message=raw_message,
        raw_message_bytes=raw_message_bytes,
        default_result=results.get("dkim", "none"),
    )
    dkim_domains = [sig.get("domain", "").strip().lower() for sig in evaluated_dkim_signatures if sig.get("domain")]

    if results["dkim"] == "none" and evaluated_dkim_signatures:
        results["dkim"] = "pass" if any(sig.get("result") == "pass" for sig in evaluated_dkim_signatures) else "fail"

    if results["dmarc"] == "none":
        from_domain = (header_facts.get("from_domain") or "").lower()
        spf_aligned = (
            results["spf"] == "pass"
            and not results.get("spf_uses_infrastructure")
            and domain_aligns(envelope_domain, from_domain)
        )
        dkim_aligned = results["dkim"] == "pass" and any(domain_aligns(d, from_domain) for d in dkim_domains)
        if from_domain and (spf_aligned or dkim_aligned):
            results["dmarc"] = "pass"
        elif results["spf"] in ("fail", "softfail", "permerror") and results["dkim"] == "fail":
            results["dmarc"] = "fail"

    return results


def _estimate_spf_lookups(spf_record: str) -> int:
    if not spf_record:
        return 0
    return len(SPF_LOOKUP_TOKEN_RE.findall(spf_record))


def _lookup_txt_record(domain: str, prefix: str) -> Tuple[str, str | None]:
    if not domain:
        return "", None
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        # Keep auth enrichment responsive during bulk reanalysis.
        resolver.timeout = 0.8
        resolver.lifetime = 1.6
        answers = resolver.resolve(domain, "TXT")
        for ans in answers:
            txt = "".join(part.decode() if isinstance(part, bytes) else str(part) for part in ans.strings)
            if txt.lower().startswith(prefix.lower()):
                return txt, None
        return "", None
    except Exception as exc:
        return "", str(exc)


def _to_ascii_dns_domain(domain: str) -> str:
    """IDNA/punycode each label for resolver queries (visible From may use U-labels)."""
    d = (domain or "").lower().strip(".")
    if not d:
        return ""
    out: List[str] = []
    for label in d.split("."):
        if not label:
            continue
        try:
            out.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            out.append(label)
    return ".".join(out)


def _normalize_dmarc_lookup_root(raw: str) -> str:
    s = (raw or "").strip().strip("<>").strip('"').strip("'")
    s = s.rstrip(")>];")
    s = s.lower().rstrip(".")
    if "@" in s:
        s = s.rsplit("@", 1)[-1].rstrip(".")
    return s


def _dmarc_suffix_chain(from_domain: str) -> List[str]:
    """
    Hostnames to try under _dmarc.<name> per RFC 7489 §6.6.1 (parent walk, stop before TLD-only).
    """
    d = (from_domain or "").lower().strip(".")
    if not d:
        return []
    labels = d.split(".")
    if len(labels) < 2:
        return [d]
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _resolve_dmarc_txt_with_resolver(dmarc_fqdn: str, nameservers: Tuple[str, ...] | None) -> Tuple[str, str | None]:
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 5.0
    if nameservers:
        resolver.nameservers = list(nameservers)
    answers = resolver.resolve(dmarc_fqdn, "TXT")
    for ans in answers:
        txt = "".join(part.decode() if isinstance(part, bytes) else str(part) for part in ans.strings)
        cleaned = txt.replace("\x00", "").strip()
        if _DMARC1_START_RE.match(cleaned):
            return cleaned, None
    return "", None


def _lookup_dmarc_txt_at(dmarc_fqdn: str) -> Tuple[str, str | None]:
    """
    Query _dmarc.* with relaxed TXT matching. Tries the system resolver, then public DNS
    (many container/stub resolvers time out or fail TXT for _dmarc).
    """
    if not dmarc_fqdn:
        return "", None
    last_err: str | None = None
    for ns in (None, _PUBLIC_DNS):
        try:
            rec, _ = _resolve_dmarc_txt_with_resolver(dmarc_fqdn, ns)
            if rec:
                return rec, None
        except Exception as exc:
            last_err = str(exc)
    return "", last_err


def _auth_results_header_from_domains(headers: Dict[str, str]) -> List[str]:
    roots: List[str] = []
    for key in (
        "authentication-results",
        "authentication-results-original",
        "auth-results",
        "arc-authentication-results",
    ):
        blob = headers.get(key) or ""
        for m in HEADER_FROM_AR_RE.finditer(blob):
            dom = _normalize_dmarc_lookup_root(m.group(2))
            if dom and dom not in roots:
                roots.append(dom)
    return roots


def _infer_dmarc_from_authentication_results(headers: Dict[str, str]) -> Dict[str, Any] | None:
    """
    When DNS lookup fails (common in containers), reuse the receiver's DMARC verdict from
    Authentication-Results so we do not warn about a missing record the MTA already applied.
    """
    blobs = [
        headers.get("authentication-results") or "",
        headers.get("authentication-results-original") or "",
        headers.get("arc-authentication-results") or "",
    ]
    raw = "\n".join(blobs)
    if not raw.strip():
        return None
    inner = ""
    for m in _DMARC_AR_CLAUSE_RE.finditer(raw):
        if m.group(1).lower() == "pass":
            inner = m.group(2)
            break
    if not inner:
        return None
    pm = _AR_DMARC_P_RE.search(inner)
    policy = pm.group(1).lower() if pm else ""
    spm = _AR_DMARC_SP_RE.search(inner)
    sp = spm.group(1).lower() if spm else ""
    adkm = _AR_DMARC_ADKIM_RE.search(inner)
    aspm = _AR_DMARC_ASPF_RE.search(inner)
    adkim = (adkm.group(1).lower() if adkm else "") or "r"
    aspf = (aspm.group(1).lower() if aspm else "") or "r"
    parts = ["v=DMARC1"]
    if policy:
        parts.append(f"p={policy}")
    if sp:
        parts.append(f"sp={sp}")
    if adkim != "r":
        parts.append(f"adkim={adkim}")
    if aspf != "r":
        parts.append(f"aspf={aspf}")
    synthetic = "; ".join(parts)
    hf_dom = ""
    for hm in HEADER_FROM_AR_RE.finditer(raw):
        hf_dom = _normalize_dmarc_lookup_root(hm.group(2))
        if hf_dom:
            break
    return {
        "record": synthetic,
        "policy": policy or None,
        "adkim": adkim,
        "aspf": aspf,
        "record_domain": hf_dom or None,
        "record_source": "authentication-results",
    }


def _dmarc_lookup_root_domains(headers: Dict[str, str], header_facts: Dict[str, Any]) -> List[str]:
    """Ordered unique roots: Header From domain, from_addr if needed, then Authentication-Results header.from."""
    ordered: List[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        dom = _normalize_dmarc_lookup_root(raw)
        if not dom or dom in seen:
            return
        seen.add(dom)
        ordered.append(dom)

    add(header_facts.get("from_domain") or "")
    from_addr = (header_facts.get("from_addr") or "").strip()
    if "@" in from_addr:
        add(from_addr)
    for dom in _auth_results_header_from_domains(headers):
        add(dom)
    return ordered


def _lookup_dmarc_record(headers: Dict[str, str], header_facts: Dict[str, Any]) -> Tuple[str, str | None, str | None]:
    """
    Returns (record, lookup_error, record_domain) where record_domain is the suffix
    that produced the TXT record (for display), or None if none found.
    """
    roots = _dmarc_lookup_root_domains(headers, header_facts)
    if not roots:
        return "", None, None
    last_err: str | None = None
    tried: set[str] = set()
    for root in roots:
        for suffix in _dmarc_suffix_chain(root):
            ascii_suffix = _to_ascii_dns_domain(suffix)
            if not ascii_suffix:
                continue
            q = f"_dmarc.{ascii_suffix}"
            if q in tried:
                continue
            tried.add(q)
            rec, err = _lookup_dmarc_txt_at(q)
            if rec:
                return rec, None, suffix
            last_err = err
    return "", last_err, None


def build_auth_details(
    *,
    raw_message: str,
    raw_message_bytes: bytes | None,
    headers: Dict[str, str],
    header_facts: Dict[str, Any],
    auth_results: Dict[str, Any],
) -> Dict[str, Any]:
    from_domain = (header_facts.get("from_domain") or "").lower()
    envelope_from = extract_envelope_from(headers, header_facts)
    envelope_domain = envelope_from.rsplit("@", 1)[-1].lower() if "@" in envelope_from else ""
    sender_ip = _choose_sender_ip(headers)

    spf_domain = envelope_domain or from_domain
    spf_record, spf_lookup_error = _lookup_txt_record(spf_domain, "v=spf1")
    spf_lookup_estimate = _estimate_spf_lookups(spf_record)
    infra_dom = auth_results.get("spf_infrastructure_domain")
    infra_record = None
    infra_lookup_error = None
    if auth_results.get("spf_uses_infrastructure") and isinstance(infra_dom, str) and infra_dom:
        infra_record, infra_lookup_error = _lookup_txt_record(infra_dom, "v=spf1")

    dkim_signatures = _evaluate_dkim_signatures(
        headers=headers,
        raw_message=raw_message,
        raw_message_bytes=raw_message_bytes,
        default_result=auth_results.get("dkim", "none"),
    )
    dkim_domains = [sig["domain"] for sig in dkim_signatures if sig.get("domain")]

    dmarc_record, dmarc_lookup_error, dmarc_record_domain = _lookup_dmarc_record(headers, header_facts)
    dmarc_policy = ""
    dmarc_adkim = "r"
    dmarc_aspf = "r"
    dmarc_record_source = "dns"
    if dmarc_record:
        for token in dmarc_record.split(";"):
            token = token.strip()
            tl = token.lower()
            if tl.startswith("p="):
                dmarc_policy = token.split("=", 1)[-1].strip().lower()
            elif tl.startswith("adkim="):
                dmarc_adkim = token.split("=", 1)[-1].strip().lower() or "r"
            elif tl.startswith("aspf="):
                dmarc_aspf = token.split("=", 1)[-1].strip().lower() or "r"
    elif inferred := _infer_dmarc_from_authentication_results(headers):
        dmarc_record = inferred["record"]
        dmarc_record_domain = inferred.get("record_domain")
        ipol = inferred.get("policy")
        dmarc_policy = (ipol or "").lower() if isinstance(ipol, str) else ""
        dmarc_adkim = str(inferred.get("adkim") or "r")
        dmarc_aspf = str(inferred.get("aspf") or "r")
        dmarc_record_source = "authentication-results"

    spf_uses_infra = bool(auth_results.get("spf_uses_infrastructure"))
    spf_aligned = (
        auth_results.get("spf") == "pass"
        and not spf_uses_infra
        and domain_aligns(envelope_domain, from_domain)
    )
    dkim_aligned = auth_results.get("dkim") == "pass" and any(domain_aligns(d, from_domain) for d in dkim_domains)

    return {
        "spf": {
            "domain": spf_domain,
            "envelope_from": envelope_from,
            "envelope_from_source": header_facts.get("envelope_from_source"),
            "sender_ip": sender_ip,
            "record": spf_record or None,
            "lookup_estimate": spf_lookup_estimate,
            "lookup_error": spf_lookup_error,
            "result": auth_results.get("spf", "none"),
            "pass_via": "infrastructure" if spf_uses_infra else "envelope",
            "infrastructure_domain": infra_dom if spf_uses_infra else None,
            "infrastructure_record": infra_record or None,
            "infrastructure_lookup_error": infra_lookup_error,
        },
        "dkim": {
            "signatures": dkim_signatures,
            "result": auth_results.get("dkim", "none"),
        },
        "dmarc": {
            "from_domain": from_domain,
            "record": dmarc_record or None,
            "record_domain": dmarc_record_domain,
            "record_source": dmarc_record_source,
            "policy": dmarc_policy or None,
            "adkim": dmarc_adkim,
            "aspf": dmarc_aspf,
            "lookup_error": dmarc_lookup_error,
            "result": auth_results.get("dmarc", "none"),
        },
        "alignment": {
            "from_domain": from_domain,
            "envelope_domain": envelope_domain,
            "dkim_domains": dkim_domains,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "dmarc_aligned": spf_aligned or dkim_aligned,
        },
    }
