"""API keys and rate limiting.

API keys are random 32-byte tokens shown once at creation; only their SHA-256 is stored.
(They are high-entropy secrets, so a fast hash is appropriate, unlike for passwords.)

Create a key:  python -m app.core.security create --owner "Demo SACCO"
"""

import argparse
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.cache import Cache
from app.core.config import Settings, get_settings
from app.db.models import ApiKey
from app.db.session import get_db

KEY_PREFIX = "jsk_"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_api_key(db: Session, owner: str, tier: str = "free") -> str:
    """Create and store a key; the plaintext is returned once and never stored."""
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    db.add(ApiKey(owner=owner, hashed_key=hash_key(key), tier=tier))
    db.commit()
    return key


@dataclass(frozen=True)
class Caller:
    """Who is calling: an API key id, or an anonymous client address."""

    identity: str
    api_key_id: int | None = None


def get_cache(request: Request) -> Cache:
    return request.app.state.cache


def get_caller(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
    x_api_key: Annotated[str | None, Header()] = None,
) -> Caller:
    """Authenticate. Keys are optional in development and required when REQUIRE_API_KEY=true."""
    if x_api_key:
        row = db.scalar(select(ApiKey).where(ApiKey.hashed_key == hash_key(x_api_key)))
        if row is None or row.revoked:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked API key")
        return Caller(identity=f"key:{row.id}", api_key_id=row.id)
    if settings.require_api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-API-Key header")
    host = request.client.host if request.client else "unknown"
    return Caller(identity=f"ip:{host}")


async def rate_limit(
    caller: Annotated[Caller, Depends(get_caller)],
    cache: Annotated[Cache, Depends(get_cache)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Caller:
    """Fixed one-minute window per caller. Returns the caller so routes need one dependency."""
    window = int(time.time() // 60)
    count = await cache.incr(f"rl:{caller.identity}:{window}", ttl=70)
    if count > settings.rate_limit_per_minute:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Rate limit exceeded. Try again in a minute.",
            headers={"Retry-After": str(60 - int(time.time() % 60))},
        )
    return caller


def _cli() -> None:
    from app.db.session import make_session_factory

    parser = argparse.ArgumentParser(description="Manage JASUSI API keys")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create", help="create a key and print it once")
    create.add_argument("--owner", required=True)
    create.add_argument("--tier", default="free")
    args = parser.parse_args()
    with make_session_factory(get_settings().database_url)() as db:
        key = create_api_key(db, args.owner, args.tier)
    print(f"API key for {args.owner} (shown once, store it safely):\n{key}")


if __name__ == "__main__":
    _cli()
