import time
import uuid
import redis.asyncio as redis


class AnomalyDetector:
    def __init__(
        self,
        redis_client: redis.Redis,
        burst_threshold: int = 5,
        burst_window_seconds: int = 3,
        abuse_threshold: int = 3,
        abuse_window_seconds: int = 60,
        cooldown_seconds: int = 30,
    ):
        self.redis = redis_client
        self.burst_threshold = burst_threshold
        self.burst_window_seconds = burst_window_seconds
        self.abuse_threshold = abuse_threshold
        self.abuse_window_seconds = abuse_window_seconds
        self.cooldown_seconds = cooldown_seconds

    async def _track_window(self, key: str, window_seconds: int) -> int:
        now = time.time()
        member = f"{now}:{uuid.uuid4().hex[:8]}"
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(key, 0, now - window_seconds)
            pipe.zadd(key, {member: now})
            pipe.zcard(key)
            pipe.expire(key, window_seconds + 5)
            results = await pipe.execute()
        return int(results[2])

    async def _acquire_cooldown(self, api_key_id: int, alert_type: str) -> bool:
        cooldown_key = f"anom:cd:{api_key_id}:{alert_type}"
        acquired = await self.redis.set(
            cooldown_key, "1", nx=True, ex=self.cooldown_seconds
        )
        return bool(acquired)

    async def evaluate(self, api_key_id: int, allowed: bool) -> list[dict]:
        alerts: list[dict] = []

        # Rule 1: Velocity spike (rapid burst within a 3-second micro-window)
        burst_count = await self._track_window(
            f"anom:vel:{api_key_id}", self.burst_window_seconds
        )
        if burst_count >= self.burst_threshold:
            if await self._acquire_cooldown(api_key_id, "VELOCITY_SPIKE"):
                alerts.append(
                    {
                        "alert_type": "VELOCITY_SPIKE",
                        "severity": "MEDIUM",
                        "details": (
                            f"Detected {burst_count} requests within "
                            f"{self.burst_window_seconds}s from API key #{api_key_id}."
                        ),
                    }
                )

        # Rule 2: Repeated rate-limit abuse (3+ blocked 429s within 60 seconds)
        if not allowed:
            blocked_count = await self._track_window(
                f"anom:429:{api_key_id}", self.abuse_window_seconds
            )
            if blocked_count >= self.abuse_threshold:
                if await self._acquire_cooldown(api_key_id, "RATE_LIMIT_ABUSE"):
                    alerts.append(
                        {
                            "alert_type": "RATE_LIMIT_ABUSE",
                            "severity": "HIGH",
                            "details": (
                                f"Triggered {blocked_count} blocked (429) responses within "
                                f"{self.abuse_window_seconds}s from API key #{api_key_id}."
                            ),
                        }
                    )

        return alerts