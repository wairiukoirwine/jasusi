"""Request and response models for the scan, feedback and stats endpoints."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.core.config import get_settings

Verdict = Literal["SAFE", "SUSPICIOUS", "SCAM"]


def _clean(value: str) -> str:
    value = value.replace("\x00", "").strip()
    if not value:
        raise ValueError("must not be empty")
    return value


class SmsScanRequest(BaseModel):
    text: str = Field(description="The SMS text to check")
    sender: str | None = Field(default=None, max_length=40, description="Sender ID or number")

    @field_validator("text")
    @classmethod
    def _text(cls, v: str) -> str:
        v = _clean(v)
        if len(v) > get_settings().max_sms_chars:
            raise ValueError(f"SMS text must be at most {get_settings().max_sms_chars} characters")
        return v


class EmailScanRequest(BaseModel):
    subject: str = Field(default="", max_length=998)
    body: str
    sender: str | None = Field(default=None, max_length=320)

    @field_validator("body")
    @classmethod
    def _body(cls, v: str) -> str:
        v = _clean(v)
        if len(v.encode()) > get_settings().max_email_bytes:
            raise ValueError(f"E-mail body must be at most {get_settings().max_email_bytes} bytes")
        return v


class UrlScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = _clean(v)
        if len(v) > get_settings().max_url_chars or any(c.isspace() for c in v):
            raise ValueError("URL is too long or contains whitespace")
        if "." not in v:
            raise ValueError("That does not look like a URL")
        return v


class IocsOut(BaseModel):
    urls: list[str] = []
    phones: list[str] = []
    paybills: list[str] = []
    emails: list[str] = []


class DetectorScores(BaseModel):
    text: float | None = None
    url: float | None = None
    intel: float | None = None


class ScanResponse(BaseModel):
    scan_id: str
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    category: str
    reasons: list[str] = Field(min_length=1)
    iocs: IocsOut
    detectors: DetectorScores
    intel_unavailable: bool
    model_version: str
    latency_ms: int


class FeedbackRequest(BaseModel):
    scan_id: str = Field(min_length=36, max_length=36)
    user_label: Literal["scam", "legit", "unsure"]
    comment: str | None = Field(default=None, max_length=500)
    consent_raw_text: bool = False
    raw_text: str | None = Field(default=None, max_length=50_000)


class FeedbackResponse(BaseModel):
    status: Literal["recorded"]
    raw_text_stored: bool


class CountItem(BaseModel):
    name: str
    count: int


class DayCount(BaseModel):
    date: str
    total: int
    scam: int
    suspicious: int
    safe: int


class RecentScan(BaseModel):
    scan_id: str
    created_at: str
    channel: str
    verdict: Verdict
    risk_score: int
    category: str


class RecentIoc(BaseModel):
    type: str
    value_masked: str
    count: int
    last_seen: str


class FeedbackSummary(BaseModel):
    total: int
    agree: int
    disagree: int
    unsure: int


class StatsResponse(BaseModel):
    days: int
    total_scans: int
    verdicts: list[CountItem]
    channels: list[CountItem]
    categories: list[CountItem]
    daily: list[DayCount]
    recent_scans: list[RecentScan]
    recent_iocs: list[RecentIoc]
    feedback: FeedbackSummary
    avg_latency_ms: float
