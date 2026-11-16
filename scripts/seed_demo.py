"""Fill a database with DEMO scans so the dashboard has something to show.

Every row comes from running a fictional example message through the real scan pipeline
(so verdicts are genuine model output), but the timestamps are spread over the past two
weeks and the volumes are invented. Use a separate database file and never present these
numbers as usage data.

Usage:  DATABASE_URL=sqlite:///./demo.db python scripts/seed_demo.py
"""

import asyncio
import os
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.cache import MemoryCache  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.models import Feedback, Scan, ScanIOC  # noqa: E402
from app.db.session import make_session_factory  # noqa: E402
from app.extract.iocs import defang, mask_email, mask_phone  # noqa: E402
from app.main import build_pipeline  # noqa: E402

EXAMPLES: list[tuple[str, str, int]] = [  # (channel, content, relative frequency)
    ("sms", "Hello, nimekutumia Ksh 3,500 kimakosa kwa MPESA. Tafadhali nirudishie kwa 0700000101 haraka.", 9),
    ("sms", "KRA: Your iTax account has been suspended. Verify your PIN immediately at http://kra-itax-verify.xyz/login", 6),
    ("sms", "Congratulations! You have won Ksh 50,000 in the Safaricom promotion. Send Ksh 500 registration fee to 0700000102 to claim.", 5),
    ("sms", "Hey mum, simu yangu imeharibika. Hii ni namba yangu mpya. Nitumie 2000 kwa 0700000103 nitakueleza.", 4),
    ("sms", "Your loan of Ksh 35,000 has been approved. Pay Ksh 350 processing fee to Till 891234 to receive funds now.", 5),
    ("sms", "Dear applicant, you qualified for a job at the airport. Pay Ksh 1,200 for medical via paybill 522522 today.", 4),
    ("sms", "Your Equity account is locked due to unusual activity. Confirm your password at equity-secure-login.top", 4),
    ("sms", "Uko wapi? Tukutane saa kumi kwa stage.", 8),
    ("sms", "TKB7Q2M4XZ Confirmed. Ksh2,450.00 sent to ALICE NDUNGU 0700000104 on 9/11/26 at 2:15 PM. New M-PESA balance is Ksh4,310.50.", 9),
    ("sms", "Your OTP is 482913. Do not share this code with anyone.", 6),
    ("sms", "Lecturer amesema CAT ni Friday, soma chapter 4 na 5.", 5),
    ("sms", "Mzee, lipa deni yangu leo ama nikuje kwako. Tuma kwa 0700000105.", 2),
    ("url", "http://safaricom-rewards.top/claim?id=8821", 5),
    ("url", "bit.ly/3xYz12", 3),
    ("url", "https://www.kra.go.ke", 3),
    ("url", "http://mpesa-agent-bonus.xyz/register", 3),
    ("email", "Subject: Invoice overdue\nYour account will be suspended. Verify your password at http://secure-billing-update.click/login within 24 hours.", 3),
    ("email", "Subject: Minutes\nHi team, attached are the minutes from Monday's meeting. Regards, Joy", 3),
]  # fmt: skip


async def main() -> None:
    url = os.environ.get("DATABASE_URL", "sqlite:///./demo.db")
    settings = Settings(database_url=url)
    pipeline = build_pipeline(settings, MemoryCache())
    factory = make_session_factory(url)
    rng = random.Random(7)  # noqa: S311 - demo data, not security
    now = datetime.now(UTC)
    weights = [w for _, _, w in EXAMPLES]
    total = 0
    with factory() as db:
        for day in range(13, -1, -1):
            for _ in range(rng.randint(6, 16) + (13 - day) // 2):
                channel, content, _ = rng.choices(EXAMPLES, weights=weights)[0]
                if channel == "url":
                    outcome = await pipeline.scan("url", text=None, url=content)
                else:
                    outcome = await pipeline.scan(channel, text=content)
                when = now - timedelta(days=day, minutes=rng.randint(0, 600))
                scan = Scan(
                    channel=channel, content_hash=outcome.content_hash, risk_score=outcome.risk_score,
                    verdict=outcome.verdict, category=outcome.category,
                    model_version=outcome.model_version, latency_ms=outcome.latency_ms + rng.randint(2, 9),
                    created_at=min(when, now),
                )  # fmt: skip
                scan.iocs = (
                    [ScanIOC(type="url", value_masked=defang(u)) for u in outcome.iocs.urls]
                    + [
                        ScanIOC(type="phone", value_masked=mask_phone(p))
                        for p in outcome.iocs.phones
                    ]
                    + [ScanIOC(type="paybill", value_masked=p) for p in outcome.iocs.paybills]
                    + [
                        ScanIOC(type="email", value_masked=mask_email(e))
                        for e in outcome.iocs.emails
                    ]
                )
                db.add(scan)
                db.flush()
                if rng.random() < 0.25:
                    flagged = outcome.verdict != "SAFE"
                    agrees = rng.random() < 0.88
                    label = "scam" if flagged == agrees else "legit"
                    db.add(Feedback(scan_id=scan.id, user_label=label, created_at=scan.created_at))
                total += 1
        db.commit()
    await pipeline.intel.aclose()
    print(f"Seeded {total} demo scans into {url}")


if __name__ == "__main__":
    asyncio.run(main())
