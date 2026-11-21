import hashlib
import secrets

from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import APIKey

TIER_CONFIG: dict[str, tuple[int, int]] = {
    "free": (5, 60),
    "pro": (20, 60),
}


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    raw_key = f"sk_live_{secrets.token_urlsafe(24)}"
    return raw_key, raw_key[:14], hash_api_key(raw_key)


async def verify_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header.")

    key_hash = hash_api_key(x_api_key)
    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active.is_(True))
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(status_code=403, detail="Invalid or inactive API key.")

    return api_key