from contextlib import asynccontextmanager
import time
from typing import Literal

from fastapi import BackgroundTasks, Depends, FastAPI, Request, Response
from pydantic import BaseModel
import redis.asyncio as redis
from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import TIER_CONFIG, generate_api_key, verify_api_key
from app.config import settings
from app.database import AsyncSessionLocal, Base, engine, get_db
from app.models import APIKey, RequestLog
from app.rate_limiter import SlidingWindowRateLimiter

redis_client: redis.Redis | None = None
limiter: SlidingWindowRateLimiter | None = None


class CreateKeyRequest(BaseModel):
    name: str
    tier: Literal["free", "pro"] = "free"


async def write_request_log(
    api_key_id: int | None,
    client_ip: str,
    endpoint: str,
    status_code: int,
    allowed: bool,
    latency_ms: float,
) -> None:
    async with AsyncSessionLocal() as session:
        session.add(
            RequestLog(
                api_key_id=api_key_id,
                client_ip=client_ip,
                endpoint=endpoint,
                status_code=status_code,
                allowed=allowed,
                latency_ms=round(latency_ms, 2),
            )
        )
        await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client, limiter
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    limiter = SlidingWindowRateLimiter(
        redis_client=redis_client,
        max_requests=settings.rate_limit_max_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )
    yield
    await redis_client.aclose()
    await engine.dispose()


app = FastAPI(title="Sentinel API", version="0.2.0", lifespan=lifespan)


@app.get("/health")
async def health(db: AsyncSession = Depends(get_db)):
    redis_ok = await redis_client.ping()
    await db.execute(text("SELECT 1"))
    return {"status": "ok", "redis_connected": redis_ok, "postgres_connected": True}


@app.post("/api/v1/keys", status_code=201)
async def create_api_key(payload: CreateKeyRequest, db: AsyncSession = Depends(get_db)):
    raw_key, prefix, key_hash = generate_api_key()
    rate_limit, window_seconds = TIER_CONFIG[payload.tier]

    new_key = APIKey(
        name=payload.name,
        key_prefix=prefix,
        key_hash=key_hash,
        tier=payload.tier,
        rate_limit=rate_limit,
        window_seconds=window_seconds,
    )
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)

    return {
        "id": new_key.id,
        "name": new_key.name,
        "tier": new_key.tier,
        "rate_limit": new_key.rate_limit,
        "window_seconds": new_key.window_seconds,
        "api_key": raw_key,
        "warning": "Store this key now; it will not be shown again.",
    }


@app.get("/api/v1/resource")
async def protected_resource(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    api_key: APIKey = Depends(verify_api_key),
):
    started = time.perf_counter()
    client_ip = request.client.host if request.client else "unknown"

    allowed, remaining = await limiter.check_limit(
        client_id=f"key:{api_key.id}",
        max_requests=api_key.rate_limit,
        window_seconds=api_key.window_seconds,
    )

    latency_ms = (time.perf_counter() - started) * 1000
    response.headers["X-RateLimit-Limit"] = str(api_key.rate_limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)

    status_code = 200 if allowed else 429
    background_tasks.add_task(
        write_request_log,
        api_key.id,
        client_ip,
        request.url.path,
        status_code,
        allowed,
        latency_ms,
    )

    if not allowed:
        response.status_code = 429
        response.headers["Retry-After"] = str(api_key.window_seconds)
        return {
            "detail": "Rate limit exceeded for your API key tier.",
            "tier": api_key.tier,
            "retry_after_seconds": api_key.window_seconds,
        }

    return {
        "message": "Request allowed",
        "key_name": api_key.name,
        "tier": api_key.tier,
        "remaining_quota": remaining,
    }


@app.get("/api/v1/logs")
async def recent_logs(limit: int = 20, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(RequestLog).order_by(desc(RequestLog.created_at)).limit(limit)
    )
    logs = result.scalars().all()
    return [
        {
            "id": log.id,
            "api_key_id": log.api_key_id,
            "client_ip": log.client_ip,
            "endpoint": log.endpoint,
            "status_code": log.status_code,
            "allowed": log.allowed,
            "latency_ms": log.latency_ms,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]