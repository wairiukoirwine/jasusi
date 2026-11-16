"""Scan endpoints: /v1/scan/sms, /v1/scan/email, /v1/scan/url."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from app.core.security import Caller, rate_limit
from app.db.models import Scan, ScanIOC
from app.db.session import get_db
from app.engine.pipeline import ScanOutcome, ScanPipeline
from app.extract.iocs import defang, mask_email, mask_phone
from app.schemas.scan import (
    DetectorScores,
    EmailScanRequest,
    IocsOut,
    ScanResponse,
    SmsScanRequest,
    UrlScanRequest,
)

router = APIRouter(prefix="/scan", tags=["scan"])


def get_pipeline(request: Request) -> ScanPipeline:
    return request.app.state.pipeline


def _store(db: Session, outcome: ScanOutcome) -> str:
    """Persist the scan with hashed content and masked IOCs. Raw text is never written."""
    scan = Scan(
        channel=outcome.channel,
        content_hash=outcome.content_hash,
        risk_score=outcome.risk_score,
        verdict=outcome.verdict,
        category=outcome.category,
        model_version=outcome.model_version,
        latency_ms=outcome.latency_ms,
    )
    scan.iocs = (
        [ScanIOC(type="url", value_masked=defang(u)[:300]) for u in outcome.iocs.urls]
        + [ScanIOC(type="phone", value_masked=mask_phone(p)) for p in outcome.iocs.phones]
        + [ScanIOC(type="paybill", value_masked=p) for p in outcome.iocs.paybills]
        + [ScanIOC(type="email", value_masked=mask_email(e)[:300]) for e in outcome.iocs.emails]
    )
    db.add(scan)
    db.commit()
    return scan.id


async def _respond(db: Session, outcome: ScanOutcome) -> ScanResponse:
    scan_id = await run_in_threadpool(_store, db, outcome)
    return ScanResponse(
        scan_id=scan_id,
        verdict=outcome.verdict,
        risk_score=outcome.risk_score,
        category=outcome.category,
        reasons=outcome.reasons,
        iocs=IocsOut(
            urls=outcome.iocs.urls,
            phones=[mask_phone(p) for p in outcome.iocs.phones],
            paybills=outcome.iocs.paybills,
            emails=[mask_email(e) for e in outcome.iocs.emails],
        ),
        detectors=DetectorScores(
            text=outcome.text_score, url=outcome.url_score, intel=outcome.intel_score
        ),
        intel_unavailable=outcome.intel_unavailable,
        model_version=outcome.model_version,
        latency_ms=outcome.latency_ms,
    )


Pipeline = Annotated[ScanPipeline, Depends(get_pipeline)]
Db = Annotated[Session, Depends(get_db)]
Limited = Annotated[Caller, Depends(rate_limit)]


@router.post("/sms", response_model=ScanResponse)
async def scan_sms(body: SmsScanRequest, pipeline: Pipeline, db: Db, _: Limited) -> ScanResponse:
    """Check an SMS. Optional `sender` is the sender ID shown on the phone."""
    return await _respond(db, await pipeline.scan("sms", text=body.text, sender=body.sender))


@router.post("/email", response_model=ScanResponse)
async def scan_email(
    body: EmailScanRequest, pipeline: Pipeline, db: Db, _: Limited
) -> ScanResponse:
    """Check an e-mail (subject + body). Uses the same text model as SMS."""
    text = f"{body.subject}\n{body.body}".strip()
    return await _respond(db, await pipeline.scan("email", text=text))


@router.post("/url", response_model=ScanResponse)
async def scan_url(body: UrlScanRequest, pipeline: Pipeline, db: Db, _: Limited) -> ScanResponse:
    """Check a single link. The link is analysed as text and is never opened."""
    return await _respond(db, await pipeline.scan("url", text=None, url=body.url))
