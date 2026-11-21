import time
import uuid
import redis.asyncio as redis

SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local current_count = redis.call('ZCARD', key)

if current_count < limit then
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, window)
    return {1, limit - current_count - 1}
else
    return {0, 0}
end
"""


class SlidingWindowRateLimiter:
    def __init__(self, redis_client: redis.Redis, max_requests: int, window_seconds: int):
        self.redis = redis_client
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._script = self.redis.register_script(SLIDING_WINDOW_LUA)

    async def check_limit(self, client_id: str) -> tuple[bool, int]:
        key = f"rl:{client_id}"
        now = time.time()
        member = f"{now}:{uuid.uuid4().hex[:8]}"

        allowed, remaining = await self._script(
            keys=[key],
            args=[now, self.window_seconds, self.max_requests, member],
        )
        return bool(allowed), int(remaining)