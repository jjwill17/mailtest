"""SSRF-safe HTTP redirect chain tracer.

This module powers the `/util/trace` endpoint surfaced in each test's
"Links & images" expander. Given a URL extracted from an analyzed email,
it manually follows up to N redirects and returns the chain so the user
can see where the link ultimately lands.

Design constraints:
  * stdlib only — no new dependencies.
  * Manual redirect handling (we don't want urllib auto-following because
    we need to enforce SSRF rules at every hop).
  * Pre-flight DNS check on each hop and reject targets that resolve to
    private / loopback / link-local / reserved IPs so the VPS can't be
    coerced into hitting internal services (Docker network, WireGuard
    peers, cloud metadata 169.254.169.254, etc.).
  * Body is never read — we always issue HEAD first, then fall back to a
    GET that discards the body. This keeps the work cheap and avoids the
    project becoming an open URL fetcher.
  * Strict timeouts at both the per-hop and total-trace level.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

MAX_HOPS = 12
PER_HOP_TIMEOUT = 5.0
TOTAL_BUDGET_SECONDS = 20.0
USER_AGENT = "MailtestRedirectTracer/1.0 (+https://mailtest.justfortesting.xyz)"
ALLOWED_SCHEMES = {"http", "https"}


class TraceError(ValueError):
    """Raised when the input URL is unusable or violates SSRF rules."""


@dataclass
class Hop:
    step: int
    method: str
    url: str
    status: int | None
    reason: str | None
    redirect_location: str | None
    set_cookie: bool
    elapsed_ms: int
    error: str | None = None
    # When False, this hop was reached only after disabling TLS certificate
    # verification (the server presented an incomplete / untrusted chain).
    # We still resolve DNS and enforce the SSRF policy in this branch, but
    # we cannot vouch for the identity of the TLS peer. The UI surfaces a
    # visible warning so the user knows their downstream chain is broken.
    tls_verified: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise TraceError("URL is required")
    parsed = urlsplit(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlsplit(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise TraceError(f"Only http/https URLs can be traced (got {parsed.scheme!r})")
    if not parsed.hostname:
        raise TraceError("URL is missing a hostname")
    return url


def _ip_is_public(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # global_ excludes private/loopback/link-local/reserved/multicast and
    # the carrier-grade NAT 100.64.0.0/10 range. Belt-and-suspenders:
    # also reject the IMDS literal 169.254.169.254 even though it would
    # already be caught by is_link_local.
    if not ip.is_global:
        return False
    if str(ip) in {"169.254.169.254", "fd00:ec2::254"}:
        return False
    return True


def _check_host_safety(host: str) -> None:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise TraceError(f"DNS lookup failed for {host}: {exc}") from exc
    seen: set[str] = set()
    for family, _socktype, _proto, _canon, sockaddr in infos:
        if family == socket.AF_INET:
            ip = sockaddr[0]
        elif family == socket.AF_INET6:
            ip = sockaddr[0].split("%", 1)[0]
        else:
            continue
        seen.add(ip)
    if not seen:
        raise TraceError(f"No usable A/AAAA records for {host}")
    for ip in seen:
        if not _ip_is_public(ip):
            raise TraceError(
                f"Refusing to trace {host}: resolves to non-public address {ip}"
            )


def _open_connection(parsed, *, insecure: bool = False) -> http.client.HTTPConnection:
    host = parsed.hostname
    port = parsed.port
    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(
            host, port=port or 443, timeout=PER_HOP_TIMEOUT, context=ctx
        )
    return http.client.HTTPConnection(host, port=port or 80, timeout=PER_HOP_TIMEOUT)


def _request_one(url: str, *, method: str, insecure: bool = False) -> tuple[int, str, dict[str, str]]:
    """Issue a single request without following redirects. Returns (status, reason, headers)."""
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    conn = _open_connection(parsed, insecure=insecure)
    try:
        conn.request(
            method,
            path,
            headers={
                "Host": parsed.netloc,
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.8",
            },
        )
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        # Drain a tiny amount to release the socket cleanly, but don't
        # store the body. http.client requires reading before close to
        # avoid ResourceWarning on some Python builds.
        try:
            resp.read(1)
        except Exception:
            pass
        return resp.status, resp.reason or "", headers
    finally:
        conn.close()


def trace_url(input_url: str) -> dict[str, Any]:
    """Follow HTTP redirects up to MAX_HOPS and return the structured chain.

    Each hop entry contains: step, method, url, status, reason,
    redirect_location, set_cookie, elapsed_ms, error.
    """
    import time

    start_url = _normalize_url(input_url)
    hops: list[Hop] = []
    current_url = start_url
    total_start = time.monotonic()
    redirected = False

    for step in range(1, MAX_HOPS + 1):
        if time.monotonic() - total_start > TOTAL_BUDGET_SECONDS:
            hops.append(
                Hop(
                    step=step,
                    method="-",
                    url=current_url,
                    status=None,
                    reason=None,
                    redirect_location=None,
                    set_cookie=False,
                    elapsed_ms=0,
                    error="Total time budget exceeded",
                )
            )
            break

        parsed = urlsplit(current_url)
        try:
            _check_host_safety(parsed.hostname)
        except TraceError as exc:
            hops.append(
                Hop(
                    step=step,
                    method="-",
                    url=current_url,
                    status=None,
                    reason=None,
                    redirect_location=None,
                    set_cookie=False,
                    elapsed_ms=0,
                    error=str(exc),
                )
            )
            break

        hop_started = time.monotonic()
        # Use GET instead of HEAD: many affiliate/tracker servers return 200
        # to HEAD but issue redirects only on GET (this is what wheregoes.com
        # does too). The body is never read — we drain 1 byte and close the
        # socket immediately — so this stays cheap.
        method = "GET"
        tls_verified = True
        try:
            try:
                status, reason, headers = _request_one(current_url, method=method)
            except ssl.SSLCertVerificationError:
                # Server presents a misconfigured chain (e.g. missing
                # intermediate CA, no AIA chasing in Python). Drop to an
                # unverified TLS handshake so we can still surface where the
                # redirect goes — the UI flags this hop with a warning, and
                # the SSRF DNS check above already ran on this hop.
                tls_verified = False
                status, reason, headers = _request_one(
                    current_url, method=method, insecure=True
                )
        except (socket.timeout, TimeoutError) as exc:
            hops.append(
                Hop(
                    step=step,
                    method=method,
                    url=current_url,
                    status=None,
                    reason=None,
                    redirect_location=None,
                    set_cookie=False,
                    elapsed_ms=int((time.monotonic() - hop_started) * 1000),
                    error=f"Timeout after {PER_HOP_TIMEOUT:.0f}s",
                )
            )
            break
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            hops.append(
                Hop(
                    step=step,
                    method=method,
                    url=current_url,
                    status=None,
                    reason=None,
                    redirect_location=None,
                    set_cookie=False,
                    elapsed_ms=int((time.monotonic() - hop_started) * 1000),
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            break

        elapsed_ms = int((time.monotonic() - hop_started) * 1000)
        location = headers.get("location")
        set_cookie = "set-cookie" in headers
        is_redirect = status in {301, 302, 303, 307, 308} and bool(location)

        hops.append(
            Hop(
                step=step,
                method=method,
                url=current_url,
                status=status,
                reason=reason,
                redirect_location=urljoin(current_url, location) if is_redirect else None,
                set_cookie=set_cookie,
                elapsed_ms=elapsed_ms,
                tls_verified=tls_verified,
            )
        )

        if not is_redirect:
            break

        redirected = True
        next_url = urljoin(current_url, location)
        next_parsed = urlsplit(next_url)
        if next_parsed.scheme.lower() not in ALLOWED_SCHEMES:
            hops.append(
                Hop(
                    step=step + 1,
                    method="-",
                    url=next_url,
                    status=None,
                    reason=None,
                    redirect_location=None,
                    set_cookie=False,
                    elapsed_ms=0,
                    error=f"Refusing to follow non-http(s) redirect ({next_parsed.scheme!r})",
                )
            )
            break

        current_url = next_url
    else:
        # Loop completed without breaking — we hit MAX_HOPS while still
        # being redirected.
        hops.append(
            Hop(
                step=MAX_HOPS + 1,
                method="-",
                url=current_url,
                status=None,
                reason=None,
                redirect_location=None,
                set_cookie=False,
                elapsed_ms=0,
                error=f"Aborting: more than {MAX_HOPS} redirects",
            )
        )

    final = hops[-1]
    return {
        "input_url": start_url,
        "hop_count": len(hops),
        "redirected": redirected,
        "final_url": final.url,
        "final_status": final.status,
        "total_elapsed_ms": int((time.monotonic() - total_start) * 1000),
        "any_tls_unverified": any(not h.tls_verified for h in hops),
        "hops": [h.to_dict() for h in hops],
    }
