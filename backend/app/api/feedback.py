"""Feedback endpoint: "Was this correct?" plus optional, consented donation of the message."""

import logging
from typing import Annotated

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.security import Caller, rate_limit
from app.db.models import Feedback, Scan
from app.db.session import get_db
from app.extract.anonymise import anonymise
from app.schemas.scan import FeedbackRequest, FeedbackResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["feedback"])


def _encrypt_donation(raw_text: str, settings: Settings) -> bytes | None:
    """Anonymise then encrypt donated text. Without a configured key nothing is stored."""
    if not settings.feedback_encryption_key:
        return None
    try:
        return Fernet(settings.feedback_encryption_key.encode()).encrypt(
            anonymise(raw_text).encode()
        )
    except Exception:  # noqa: BLE001 - a bad key must not store plaintext or fail the request
        logger.error("FEEDBACK_ENCRYPTION_KEY is invalid; donated text was not stored")
        return None


@router.post("/feedback", response_model=FeedbackResponse)
def submit_feedback(
    body: FeedbackRequest,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    _: Annotated[Caller, Depends(rate_limit)],
) -> FeedbackResponse:
    """Record whether the user thinks the verdict was right.

    Raw text is kept only if `consent_raw_text` is true, and then only anonymised and encrypted.
    """
    if db.get(Scan, body.scan_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown scan_id")
    encrypted = None
    if body.consent_raw_text and body.raw_text:
        encrypted = _encrypt_donation(body.raw_text, settings)
    db.add(
        Feedback(
            scan_id=body.scan_id,
            user_label=body.user_label,
            comment=body.comment,
            consent_raw_text=body.consent_raw_text and encrypted is not None,
            raw_text_encrypted=encrypted,
        )
    )
    db.commit()
    return FeedbackResponse(status="recorded", raw_text_stored=encrypted is not None)
