from dataclasses import dataclass
import hashlib
import json
import secrets

from fastapi import Header, HTTPException, Request
from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models import APIKey

TIER_CONFIG: dict[str, tuple[int, int]] = {
    "free": (5, 60),
    "pro": (20, 60),
}
KEY_CACHE_TTL_SECONDS = 60


@dataclass
class AuthKeyContext:
    id: int
    name: str
    tier: str
    rate_limit: int
    window_seconds: int


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    raw_key = f"sk_live_{secrets.token_urlsafe(24)}"
    return raw_key, raw_key[:14], hash_api_key(raw_key)


async def cache_api_key(redis_client, key_hash: str, ctx: AuthKeyContext) -> None:
    if redis_client is None:
        return
    await redis_client.set(
        f"apikey:{key_hash}",
        json.dumps(ctx.__dict__),
        ex=KEY_CACHE_TTL_SECONDS,
    )


async def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> AuthKeyContext:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header.")

    key_hash = hash_api_key(x_api_key)
    redis_client = getattr(request.app.state, "redis", None)

    if redis_client is not None:
        cached = await redis_client.get(f"apikey:{key_hash}")
        if cached:
            return AuthKeyContext(**json.loads(cached))

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(APIKey).where(
                APIKey.key_hash == key_hash, APIKey.is_active.is_(True)
            )
        )
        api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(status_code=403, detail="Invalid or inactive API key.")

    ctx = AuthKeyContext(
        id=api_key.id,
        name=api_key.name,
        tier=api_key.tier,
        rate_limit=api_key.rate_limit,
        window_seconds=api_key.window_seconds,
    )
    await cache_api_key(redis_client, key_hash, ctx)
    return ctx