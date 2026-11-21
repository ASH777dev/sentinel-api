from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Response
import redis.asyncio as redis

from app.config import settings
from app.rate_limiter import SlidingWindowRateLimiter

redis_client: redis.Redis | None = None
limiter: SlidingWindowRateLimiter | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client, limiter
    redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    limiter = SlidingWindowRateLimiter(
        redis_client=redis_client,
        max_requests=settings.rate_limit_max_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )
    yield
    await redis_client.aclose()


app = FastAPI(title="Sentinel API", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health():
    pong = await redis_client.ping()
    return {"status": "ok", "redis_connected": pong}


@app.get("/api/v1/resource")
async def protected_resource(request: Request, response: Response):
    client_ip = request.client.host if request.client else "unknown"
    allowed, remaining = await limiter.check_limit(client_ip)

    response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_max_requests)
    response.headers["X-RateLimit-Remaining"] = str(remaining)

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Try again later.",
            headers={"Retry-After": str(settings.rate_limit_window_seconds)},
        )

    return {
        "message": "Request allowed",
        "client": client_ip,
        "remaining_quota": remaining,
    }