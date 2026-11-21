from contextlib import asynccontextmanager
from datetime import datetime, timezone
import time
from typing import Literal

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import redis.asyncio as redis
from sqlalchemy import case, desc, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.anomaly import AnomalyDetector
from app.auth import TIER_CONFIG, generate_api_key, verify_api_key
from app.config import settings
from app.database import AsyncSessionLocal, Base, engine, get_db
from app.models import APIKey, AnomalyAlert, RequestLog
from app.rate_limiter import SlidingWindowRateLimiter
from app.telemetry import ConnectionManager

redis_client: redis.Redis | None = None
limiter: SlidingWindowRateLimiter | None = None
detector: AnomalyDetector | None = None
telemetry_manager = ConnectionManager()


class CreateKeyRequest(BaseModel):
    name: str
    tier: Literal["free", "pro"] = "free"


async def process_request_telemetry(
    api_key_id: int,
    key_name: str,
    tier: str,
    client_ip: str,
    endpoint: str,
    status_code: int,
    allowed: bool,
    latency_ms: float,
) -> None:
    rounded_latency = round(latency_ms, 2)
    now_iso = datetime.now(timezone.utc).isoformat()

    triggered_alerts = await detector.evaluate(api_key_id=api_key_id, allowed=allowed)

    async with AsyncSessionLocal() as session:
        session.add(
            RequestLog(
                api_key_id=api_key_id,
                client_ip=client_ip,
                endpoint=endpoint,
                status_code=status_code,
                allowed=allowed,
                latency_ms=rounded_latency,
            )
        )
        for alert in triggered_alerts:
            session.add(
                AnomalyAlert(
                    api_key_id=api_key_id,
                    client_ip=client_ip,
                    alert_type=alert["alert_type"],
                    severity=alert["severity"],
                    details=alert["details"],
                )
            )
        await session.commit()

    await telemetry_manager.broadcast(
        {
            "type": "request",
            "api_key_id": api_key_id,
            "key_name": key_name,
            "tier": tier,
            "client_ip": client_ip,
            "endpoint": endpoint,
            "status_code": status_code,
            "allowed": allowed,
            "latency_ms": rounded_latency,
            "timestamp": now_iso,
        }
    )

    for alert in triggered_alerts:
        await telemetry_manager.broadcast(
            {
                "type": "anomaly",
                "api_key_id": api_key_id,
                "key_name": key_name,
                "client_ip": client_ip,
                "alert_type": alert["alert_type"],
                "severity": alert["severity"],
                "details": alert["details"],
                "timestamp": now_iso,
            }
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client, limiter, detector
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    redis_client = redis.from_url(
        settings.redis_url,
        decode_responses=True,
        health_check_interval=30,
        socket_keepalive=True,
        retry_on_timeout=True,
    )
    limiter = SlidingWindowRateLimiter(
        redis_client=redis_client,
        max_requests=settings.rate_limit_max_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )
    detector = AnomalyDetector(redis_client=redis_client)
    yield
    await redis_client.aclose()
    await engine.dispose()


app = FastAPI(title="Sentinel API", version="0.3.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health(db: AsyncSession = Depends(get_db)):
    redis_ok = await redis_client.ping()
    await db.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "redis_connected": redis_ok,
        "postgres_connected": True,
        "active_ws_clients": len(telemetry_manager.active_connections),
    }


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
        process_request_telemetry,
        api_key.id,
        api_key.name,
        api_key.tier,
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


@app.get("/api/v1/alerts")
async def recent_alerts(limit: int = 20, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AnomalyAlert).order_by(desc(AnomalyAlert.created_at)).limit(limit)
    )
    alerts = result.scalars().all()
    return [
        {
            "id": alert.id,
            "api_key_id": alert.api_key_id,
            "client_ip": alert.client_ip,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "details": alert.details,
            "resolved": alert.resolved,
            "created_at": alert.created_at.isoformat(),
        }
        for alert in alerts
    ]


@app.get("/api/v1/stats")
async def traffic_stats(db: AsyncSession = Depends(get_db)):
    log_row = (
        await db.execute(
            select(
                func.count(RequestLog.id).label("total"),
                func.sum(case((RequestLog.allowed.is_(False), 1), else_=0)).label("blocked"),
                func.avg(RequestLog.latency_ms).label("avg_latency"),
            )
        )
    ).one()

    total_alerts = (
        await db.execute(select(func.count(AnomalyAlert.id)))
    ).scalar_one()

    total = int(log_row.total or 0)
    blocked = int(log_row.blocked or 0)
    block_rate = round((blocked / total) * 100, 2) if total else 0.0

    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "block_rate_percent": block_rate,
        "avg_latency_ms": round(float(log_row.avg_latency or 0.0), 2),
        "total_alerts": int(total_alerts),
        "active_ws_clients": len(telemetry_manager.active_connections),
    }


@app.websocket("/ws/telemetry")
async def telemetry_stream(websocket: WebSocket):
    await telemetry_manager.connect(websocket)
    try:
        await websocket.send_json(
            {"type": "connected", "message": "Sentinel telemetry stream active"}
        )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        telemetry_manager.disconnect(websocket)