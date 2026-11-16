"""Analyst dashboard data: volumes, verdict split, categories, recent IOCs, feedback."""

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import Caller, rate_limit
from app.db.models import Feedback, Scan, ScanIOC
from app.db.session import get_db
from app.schemas.scan import (
    CountItem,
    DayCount,
    FeedbackSummary,
    RecentIoc,
    RecentScan,
    StatsResponse,
)

router = APIRouter(prefix="/stats", tags=["stats"])


def _counts(counter: Counter) -> list[CountItem]:
    return [CountItem(name=k, count=v) for k, v in counter.most_common()]


@router.get("/summary", response_model=StatsResponse)
def summary(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[Caller, Depends(rate_limit)],
    days: Annotated[int, Query(ge=1, le=90)] = 14,
) -> StatsResponse:
    """Aggregates over the last `days` days. Contains no message text and no unmasked IOCs."""
    since = datetime.now(UTC) - timedelta(days=days)
    scans = db.execute(
        select(Scan.id, Scan.created_at, Scan.channel, Scan.verdict, Scan.risk_score, Scan.category,
               Scan.latency_ms)
        .where(Scan.created_at >= since)
        .order_by(Scan.created_at.desc())
    ).all()  # fmt: skip

    daily: dict[str, Counter] = defaultdict(Counter)
    for row in scans:
        daily[row.created_at.date().isoformat()][row.verdict] += 1
    today = datetime.now(UTC).date()
    day_rows = []
    for offset in range(days - 1, -1, -1):
        key = (today - timedelta(days=offset)).isoformat()
        c = daily.get(key, Counter())
        day_rows.append(
            DayCount(
                date=key,
                total=sum(c.values()),
                scam=c["SCAM"],
                suspicious=c["SUSPICIOUS"],
                safe=c["SAFE"],
            )
        )

    ioc_rows = db.execute(
        select(ScanIOC.type, ScanIOC.value_masked, func.count().label("n"),
               func.max(Scan.created_at).label("last_seen"))
        .join(Scan, Scan.id == ScanIOC.scan_id)
        .where(Scan.created_at >= since, Scan.verdict != "SAFE")
        .group_by(ScanIOC.type, ScanIOC.value_masked)
        .order_by(func.max(Scan.created_at).desc())
        .limit(15)
    ).all()  # fmt: skip

    feedback_rows = db.execute(
        select(Feedback.user_label, Scan.verdict)
        .join(Scan, Scan.id == Feedback.scan_id)
        .where(Feedback.created_at >= since)
    ).all()
    agree = sum(
        (label == "scam") == (verdict != "SAFE")
        for label, verdict in feedback_rows
        if label != "unsure"
    )
    unsure = sum(label == "unsure" for label, _ in feedback_rows)

    def iso(dt: datetime) -> str:
        return dt.isoformat(timespec="seconds") if isinstance(dt, datetime) else str(dt)

    return StatsResponse(
        days=days,
        total_scans=len(scans),
        verdicts=_counts(Counter(r.verdict for r in scans)),
        channels=_counts(Counter(r.channel for r in scans)),
        categories=_counts(Counter(r.category for r in scans if r.verdict != "SAFE")),
        daily=day_rows,
        recent_scans=[
            RecentScan(scan_id=r.id, created_at=iso(r.created_at), channel=r.channel,
                       verdict=r.verdict, risk_score=r.risk_score, category=r.category)
            for r in scans[:12]
        ],  # fmt: skip
        recent_iocs=[
            RecentIoc(
                type=r.type, value_masked=r.value_masked, count=r.n, last_seen=iso(r.last_seen)
            )
            for r in ioc_rows
        ],
        feedback=FeedbackSummary(
            total=len(feedback_rows),
            agree=agree,
            disagree=len(feedback_rows) - agree - unsure,
            unsure=unsure,
        ),
        avg_latency_ms=round(sum(r.latency_ms for r in scans) / len(scans), 1) if scans else 0.0,
    )
