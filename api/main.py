from analyzer import analyze_message
from analyzer_core.parsing import apply_smtp_session_metadata
from fastapi import FastAPI, Depends, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_
from sqlalchemy import text
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import Base, engine, get_db
from models import TestEmail
from demo_mode import (
    enforce_ingest_size,
    limiter,
    require_writable,
    should_redact,
)
from ingest_throttle import enforce_ingest_throttle
from redirect_trace import TraceError, trace_url
from redact import (
    REDACTED_EXPORT_RAW,
    redact_deliverability,
    redact_export_payload,
)
import io
import json
import os
import zipfile
import base64
import hashlib

templates = Jinja2Templates(directory="templates")

# Branding / demo-page copy (all overridable via env vars)
DEMO_INBOUND_ADDRESS = os.environ.get(
    "DEMO_INBOUND_ADDRESS", "demo@mailtest.justfortesting.xyz"
)
OWNER_NAME = os.environ.get("OWNER_NAME", "Justin Willmore")
OWNER_URL = os.environ.get(
    "OWNER_URL", "https://www.linkedin.com/in/justin-willmore-7bb87950/"
).strip()

# The address itself is only delivered to the browser as base64 inside a
# data-* attribute, and the page requires a click to reveal it. That keeps
# naive email harvesters (regex for `[\w.+-]+@[\w.-]+`) from scooping it off
# the rendered HTML.
_DEMO_INBOUND_ADDRESS_B64 = base64.b64encode(
    DEMO_INBOUND_ADDRESS.encode("ascii")
).decode("ascii")


def _branding_context() -> dict:
    """Shared template context for page-level branding/instructions."""
    return {
        "demo_inbound_address_b64": _DEMO_INBOUND_ADDRESS_B64,
        "owner_name": OWNER_NAME,
        "owner_url": OWNER_URL,
    }
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.mount("/static", StaticFiles(directory="static"), name="static")

Base.metadata.create_all(bind=engine)


def _ensure_optional_columns() -> None:
    # Lightweight compatibility migration for existing local databases.
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE test_emails ADD COLUMN IF NOT EXISTS raw_message_b64 TEXT"))
        conn.execute(text("ALTER TABLE test_emails ADD COLUMN IF NOT EXISTS source TEXT"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_test_emails_source ON test_emails (source)"))


_ensure_optional_columns()


class IngestRequest(BaseModel):
    subject: str | None = None
    raw_message: str
    raw_message_b64: str | None = None
    raw_sha256: str | None = None
    source: str = "manual"  # manual, smtp, webhook
    # SMTP MAIL FROM / client IP from the inbound MTA session (VPS or bridge).
    smtp_envelope_from: str | None = None
    smtp_client_ip: str | None = None


class DeliverabilityResult(BaseModel):
    score: int
    grade: str
    warnings: list[str]
    reasons: list[dict] | None = None
    facts: dict | None = None


class IngestResponse(BaseModel):
    id: int
    deliverability: DeliverabilityResult | None = None
    total_links: int | None = None
    total_images: int | None = None


class TestAnalysisResponse(BaseModel):
    id: int
    subject: str | None = None
    created_at: str | None = None
    deliverability: DeliverabilityResult | None = None


class BackfillResponse(BaseModel):
    total: int
    updated: int


class BulkActionRequest(BaseModel):
    ids: list[int] = []
    all_matching: bool = False
    q: str | None = None
    domain: str | None = None
    source: str | None = None


class BulkActionResponse(BaseModel):
    requested: int
    updated: int = 0
    deleted: int = 0


def _export_payload_for_test(test: TestEmail) -> dict:
    return {
        "id": test.id,
        "subject": test.subject,
        "created_at": test.created_at.isoformat() if test.created_at else None,
        "raw_message": test.raw_message,
        "raw_message_b64": test.raw_message_b64,
        "headers": test.parsed_headers or {},
        "mime_tree": test.mime_tree or [],
        "auth_results": test.auth_results or {},
        "links": test.links or [],
        "images": test.images or [],
        "deliverability": test.deliverability or {},
    }


SIMULATOR_SOURCES = {
    "smtp-complaint-simulator",
    "postfix-pipe-complaint-simulator",
    "simulator-arf",
}


def _source_label(source: str | None) -> str | None:
    """Return a short human label for the badge, or None if the row should show nothing."""
    s = (source or "").strip().lower()
    if not s:
        return None
    if s == "simulator-arf":
        return "ARF"
    if s.endswith("complaint-simulator"):
        return "Complaint sim"
    if s == "smtp":
        return "SMTP"
    if s == "postfix-pipe":
        return "Postfix pipe"
    if s == "manual":
        return "Manual"
    return s


def _apply_test_filters(query, *, q: str | None, domain: str | None, source: str | None = None):
    q_norm = (q or "").strip()
    domain_norm = (domain or "").strip().lower().lstrip("@")
    source_norm = (source or "").strip().lower()

    if q_norm:
        like = f"%{q_norm}%"
        query = query.filter(
            or_(
                TestEmail.subject.ilike(like),
                TestEmail.parsed_headers["from"].astext.ilike(like),
            )
        )

    if domain_norm:
        at_like = f"%@{domain_norm}%"
        any_like = f"%{domain_norm}%"
        query = query.filter(
            or_(
                TestEmail.parsed_headers["from"].astext.ilike(at_like),
                TestEmail.parsed_headers["return-path"].astext.ilike(at_like),
                TestEmail.parsed_headers["from"].astext.ilike(any_like),
                TestEmail.parsed_headers["return-path"].astext.ilike(any_like),
            )
        )

    if source_norm:
        if source_norm == "simulator":
            query = query.filter(TestEmail.source.in_(sorted(SIMULATOR_SOURCES)))
        elif source_norm == "complaint":
            query = query.filter(TestEmail.source.ilike("%complaint-simulator%"))
        elif source_norm == "arf":
            query = query.filter(TestEmail.source == "simulator-arf")
        else:
            query = query.filter(TestEmail.source == source_norm)

    return query


def _resolve_bulk_targets(payload: BulkActionRequest, db: Session):
    if payload.all_matching:
        q = (payload.q or "").strip()
        domain = (payload.domain or "").strip()
        source = (getattr(payload, "source", None) or "").strip()
        query = db.query(TestEmail)
        query = _apply_test_filters(query, q=q, domain=domain, source=source)
        tests = query.order_by(TestEmail.id.asc()).all()
        return tests, len(tests)

    ids = [int(i) for i in payload.ids if isinstance(i, int) or (isinstance(i, str) and str(i).isdigit())]
    if not ids:
        return [], 0
    tests = db.query(TestEmail).filter(TestEmail.id.in_(ids)).order_by(TestEmail.id.asc()).all()
    return tests, len(ids)


@app.get("/")
def read_root():
    return {"status": "ok", "message": "mailtest API stub"}

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/robots.txt", include_in_schema=False)
def robots_txt() -> Response:
    # Tell well-behaved crawlers (Google, Bing, etc.) to skip the demo.
    # This is not a security control, but it does keep the demo address
    # off search-engine indices and "site:" queries.
    body = "User-agent: *\nDisallow: /\n"
    return Response(content=body, media_type="text/plain")


@app.get("/util/trace")
@limiter.limit("20/minute")
def util_trace(request: Request, url: str = Query(..., min_length=1, max_length=4096)) -> JSONResponse:
    """Follow HTTP redirects for a URL extracted from an analyzed email.

    SSRF-protected: each hop's hostname is DNS-resolved and rejected if any
    address is private/loopback/link-local/reserved. Body is never read; this
    is metadata-only so we don't accidentally become an open URL fetcher.

    `request` is required by slowapi for keying the limiter, even though the
    handler doesn't read from it directly.
    """
    try:
        result = trace_url(url)
    except TraceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse(content=result)


@app.get("/admin/ping", dependencies=[Depends(require_writable)])
def admin_ping() -> dict:
    """Cheap key-validator for the UI's admin-unlock button.

    Gated by the same dependency as destructive endpoints, so a 200 here
    guarantees the destructive endpoints would accept the same key. In
    non-demo deployments this always succeeds (require_writable is a no-op
    when DEMO_MODE=false), which is fine — admin mode is only meaningful
    when demo mode is on.
    """
    return {"status": "ok"}

@app.post("/ingest", dependencies=[Depends(enforce_ingest_throttle)])
def ingest_email(
    request: Request,
    payload: IngestRequest,
    db: Session = Depends(get_db),
) -> IngestResponse:
    enforce_ingest_size(payload.raw_message, payload.raw_message_b64)
    if payload.raw_sha256:
        provided_hash = payload.raw_sha256.strip().lower()
        if payload.raw_message_b64:
            try:
                raw_bytes = base64.b64decode(payload.raw_message_b64, validate=True)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid raw_message_b64 for checksum verification")
        else:
            raw_bytes = payload.raw_message.encode("utf-8", errors="replace")

        actual_hash = hashlib.sha256(raw_bytes).hexdigest().lower()
        if actual_hash != provided_hash:
            raise HTTPException(
                status_code=400,
                detail="raw_sha256 checksum mismatch (payload bytes changed in transit)",
            )

    raw_for_analysis = apply_smtp_session_metadata(
        payload.raw_message,
        envelope_from=payload.smtp_envelope_from,
        client_ip=payload.smtp_client_ip,
    )
    analysis = analyze_message(raw_for_analysis, payload.raw_message_b64)
    parsed_subject = (analysis.get("subject") or "").strip()
    chosen_subject = parsed_subject or payload.subject

    test = TestEmail(
        subject=chosen_subject,
        raw_message=raw_for_analysis,
        raw_message_b64=payload.raw_message_b64,
        parsed_headers=analysis["headers"],      # dict
        mime_tree=analysis["mime_tree"],         # list/dict
        auth_results=analysis["auth_results"],   # dict
        links=analysis.get("links"),
        images=analysis.get("images"),
        deliverability=analysis.get("deliverability"),
        source=(payload.source or "manual").strip() or "manual",
    )
    db.add(test)
    db.commit()
    db.refresh(test)
    return IngestResponse(
        id=test.id,
        deliverability=test.deliverability,
        total_links=analysis.get("total_links"),
        total_images=analysis.get("total_images"),
    )



@app.get("/tests")
def list_tests(
    q: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    source: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    db: Session = Depends(get_db),
):
    base = db.query(TestEmail)
    base = _apply_test_filters(base, q=q, domain=domain, source=source)
    tests = (
        base.order_by(TestEmail.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return [
        {
            "id": t.id,
            "subject": t.subject,
            "created_at": t.created_at.isoformat(),
            "source": t.source,
        }
        for t in tests
    ]


@app.get("/tests/{test_id}")
def get_test(
    test_id: int,
    db: Session = Depends(get_db),
    x_admin_key: str | None = Header(default=None),
):
    test = db.query(TestEmail).filter(TestEmail.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Not found")

    raw = test.raw_message
    if should_redact(x_admin_key):
        raw = REDACTED_EXPORT_RAW

    return {
        "id": test.id,
        "subject": test.subject,
        "created_at": test.created_at.isoformat(),
        "raw_message": raw,
    }


@app.get("/tests/{test_id}/analysis")
def get_test_analysis(
    test_id: int,
    db: Session = Depends(get_db),
    x_admin_key: str | None = Header(default=None),
) -> TestAnalysisResponse:
    test = db.query(TestEmail).filter(TestEmail.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Not found")

    deliverability = test.deliverability or None
    if should_redact(x_admin_key):
        deliverability = redact_deliverability(deliverability)

    return TestAnalysisResponse(
        id=test.id,
        subject=test.subject,
        created_at=test.created_at.isoformat() if test.created_at else None,
        deliverability=deliverability,
    )


@app.get(
    "/admin/tests/{test_id}/raw",
    dependencies=[Depends(require_writable)],
)
def admin_get_test_raw(test_id: int, db: Session = Depends(get_db)) -> dict:
    """Admin-only: return unredacted raw message + parsed headers.

    Used by the detail-page UI to progressively reveal the Headers /
    Raw sections after the visitor unlocks Admin mode in the browser,
    without requiring a full page reload.
    """
    test = db.query(TestEmail).filter(TestEmail.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Not found")

    return {
        "id": test.id,
        "raw_message": test.raw_message or "",
        "parsed_headers": test.parsed_headers or {},
    }


@app.post("/tests/{test_id}/reanalyze", dependencies=[Depends(require_writable)])
def reanalyze_test(test_id: int, db: Session = Depends(get_db)) -> TestAnalysisResponse:
    test = db.query(TestEmail).filter(TestEmail.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Not found")

    analysis = analyze_message(test.raw_message, test.raw_message_b64)
    parsed_subject = (analysis.get("subject") or "").strip()
    if parsed_subject:
        test.subject = parsed_subject
    test.parsed_headers = analysis.get("headers")
    test.mime_tree = analysis.get("mime_tree")
    test.auth_results = analysis.get("auth_results")
    test.links = analysis.get("links")
    test.images = analysis.get("images")
    test.deliverability = analysis.get("deliverability")
    db.add(test)
    db.commit()
    db.refresh(test)

    return TestAnalysisResponse(
        id=test.id,
        subject=test.subject,
        created_at=test.created_at.isoformat() if test.created_at else None,
        deliverability=test.deliverability or None,
    )


@app.post("/tests/backfill/reanalyze-all", dependencies=[Depends(require_writable)])
def backfill_reanalyze_all(db: Session = Depends(get_db)) -> BackfillResponse:
    tests = db.query(TestEmail).all()
    updated = 0

    for test in tests:
        analysis = analyze_message(test.raw_message, test.raw_message_b64)
        parsed_subject = (analysis.get("subject") or "").strip()
        if parsed_subject:
            test.subject = parsed_subject
        test.parsed_headers = analysis.get("headers")
        test.mime_tree = analysis.get("mime_tree")
        test.auth_results = analysis.get("auth_results")
        test.links = analysis.get("links")
        test.images = analysis.get("images")
        test.deliverability = analysis.get("deliverability")
        db.add(test)
        updated += 1

    db.commit()
    return BackfillResponse(total=len(tests), updated=updated)


@app.post("/bulk/tests/reanalyze", dependencies=[Depends(require_writable)])
def bulk_reanalyze_tests(payload: BulkActionRequest, db: Session = Depends(get_db)) -> BulkActionResponse:
    tests, requested = _resolve_bulk_targets(payload, db)
    if not tests:
        return BulkActionResponse(requested=0, updated=0)
    updated = 0
    for test in tests:
        analysis = analyze_message(test.raw_message, test.raw_message_b64)
        parsed_subject = (analysis.get("subject") or "").strip()
        if parsed_subject:
            test.subject = parsed_subject
        test.parsed_headers = analysis.get("headers")
        test.mime_tree = analysis.get("mime_tree")
        test.auth_results = analysis.get("auth_results")
        test.links = analysis.get("links")
        test.images = analysis.get("images")
        test.deliverability = analysis.get("deliverability")
        db.add(test)
        updated += 1

    db.commit()
    return BulkActionResponse(requested=requested, updated=updated)


@app.post("/bulk/tests/delete", dependencies=[Depends(require_writable)])
def bulk_delete_tests(payload: BulkActionRequest, db: Session = Depends(get_db)) -> BulkActionResponse:
    tests, requested = _resolve_bulk_targets(payload, db)
    if not tests:
        return BulkActionResponse(requested=0, deleted=0)
    deleted = len(tests)
    for test in tests:
        db.delete(test)
    db.commit()
    return BulkActionResponse(requested=requested, deleted=deleted)


@app.post("/bulk/tests/export")
def bulk_export_tests(
    payload: BulkActionRequest,
    db: Session = Depends(get_db),
    x_admin_key: str | None = Header(default=None),
):
    tests, requested = _resolve_bulk_targets(payload, db)
    if requested == 0:
        raise HTTPException(status_code=400, detail="No test IDs provided")
    if not tests:
        raise HTTPException(status_code=404, detail="No matching tests found")

    redact = should_redact(x_admin_key)

    def _maybe_redact(p: dict) -> dict:
        return redact_export_payload(p) if redact else p

    if len(tests) == 1:
        payload_data = _maybe_redact(_export_payload_for_test(tests[0]))
        return JSONResponse(
            content=payload_data,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="email-{tests[0].id}.json"'
            },
        )

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for test in tests:
            payload_data = _maybe_redact(_export_payload_for_test(test))
            file_name = f"email-{test.id}.json"
            zf.writestr(file_name, json.dumps(payload_data, indent=2))

    zip_buffer.seek(0)
    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="email-tests-export.zip"'},
    )


# HTML UI endpoints
@app.get("/ui/tests", response_class=HTMLResponse)
def ui_tests(
    request: Request,
    q: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    source: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    db: Session = Depends(get_db),
):
    base = db.query(TestEmail)
    base = _apply_test_filters(base, q=q, domain=domain, source=source)
    total_count = base.count()
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    page = min(page, total_pages)

    tests = (
        base.order_by(TestEmail.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    source_filter = (source or "").strip().lower()
    return templates.TemplateResponse(
        request,
        "tests.html",
        {
            "tests": tests,
            "q": q or "",
            "domain": domain or "",
            "source_filter": source_filter,
            "source_label": _source_label,
            "page": page,
            "page_size": page_size,
            "total_count": total_count,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1,
            "next_page": page + 1,
            **_branding_context(),
        },
    )


@app.get("/ui/tests/{test_id}", response_class=HTMLResponse)
def ui_test(
    test_id: int,
    request: Request,
    db: Session = Depends(get_db),
    x_admin_key: str | None = Header(default=None),
):
    test = db.query(TestEmail).filter(TestEmail.id == test_id).first()
    if not test:
        return HTMLResponse("<h1>Test not found</h1>", status_code=404)

    test.parsed_headers = test.parsed_headers or {}
    test.mime_tree = test.mime_tree or []
    test.auth_results = test.auth_results or {}

    demo_viewer = should_redact(x_admin_key)
    # Always pass deliverability via a separate template variable so the
    # template never references the ORM-attached value directly. This lets
    # us hand the demo viewer a deep-copied, redacted version while the
    # DB row itself is never mutated.
    deliverability = redact_deliverability(test.deliverability) if demo_viewer else (test.deliverability or {})

    return templates.TemplateResponse(
        request,
        "test.html",
        {
            "test": test,
            "deliverability": deliverability,
            "demo_viewer": demo_viewer,
            **_branding_context(),
        },
    )


@app.get("/export/{test_id}")
def export_test(
    test_id: int,
    db: Session = Depends(get_db),
    x_admin_key: str | None = Header(default=None),
):
    test = db.query(TestEmail).filter(TestEmail.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Not found")

    payload = _export_payload_for_test(test)
    if should_redact(x_admin_key):
        payload = redact_export_payload(payload)

    return JSONResponse(
        content=payload,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="email-{test.id}.json"'
        },
    )


@app.get("/debug/{test_id}", dependencies=[Depends(require_writable)])
def debug_test(test_id: int, db: Session = Depends(get_db)):
    test = db.query(TestEmail).filter(TestEmail.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Not found")

    # Ensure fields exist for debug
    test.parsed_headers = test.parsed_headers or {}
    test.mime_tree = test.mime_tree or []
    test.auth_results = test.auth_results or {}

    html_parts = [p for p in test.mime_tree if "text/html" in p.get("content_type", "")]

    return {
        "test_id": test.id,
        "total_parts": len(test.mime_tree),
        "html_parts_count": len(html_parts),
        "first_html_preview": html_parts[0].get("payload", "")[:1000] if html_parts else "NO HTML PARTS",
        "all_parts_summary": [
            {"index": p["index"], "content_type": p["content_type"], "size": p["size"], "is_body": p["is_body"]}
            for p in test.mime_tree[:5]
        ],
    }
