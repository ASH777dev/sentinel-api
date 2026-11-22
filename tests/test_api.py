import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.anomaly import AnomalyDetector
from app.auth import TIER_CONFIG, generate_api_key, hash_api_key, verify_api_key
from app.main import app
from app.rate_limiter import SlidingWindowRateLimiter


def test_api_key_generation_and_hashing():
    raw_key, prefix, key_hash = generate_api_key()
    assert raw_key.startswith("sk_live_")
    assert prefix == raw_key[:14]
    assert len(key_hash) == 64
    assert hash_api_key(raw_key) == key_hash


def test_tier_config_limits():
    assert TIER_CONFIG["free"] == (5, 60)
    assert TIER_CONFIG["pro"] == (20, 60)


def test_missing_api_key_raises_401():
    dummy_request = MagicMock()
    with pytest.raises(HTTPException) as exc:
        asyncio.run(verify_api_key(request=dummy_request, x_api_key=None))
    assert exc.value.status_code == 401


def test_sliding_window_limiter_uses_atomic_script():
    fake_script = AsyncMock(return_value=[1, 4])
    fake_redis = MagicMock()
    fake_redis.register_script.return_value = fake_script

    limiter = SlidingWindowRateLimiter(fake_redis, max_requests=5, window_seconds=60)
    allowed, remaining = asyncio.run(
        limiter.check_limit("key:1", max_requests=5, window_seconds=60)
    )

    assert allowed is True
    assert remaining == 4
    fake_script.assert_awaited_once()
    call_kwargs = fake_script.call_args.kwargs
    assert call_kwargs["keys"] == ["rl:key:1"]


def test_anomaly_detector_flags_abuse_and_deduplicates():
    fake_pipe = MagicMock()
    fake_pipe.__aenter__ = AsyncMock(return_value=fake_pipe)
    fake_pipe.__aexit__ = AsyncMock(return_value=None)
    # First call: velocity window count = 5; second call: 429 window count = 3
    fake_pipe.execute = AsyncMock(
        side_effect=[
            [0, 1, 5, True],
            [0, 1, 3, True],
            [0, 1, 6, True],
            [0, 1, 4, True],
        ]
    )

    fake_redis = MagicMock()
    fake_redis.pipeline.return_value = fake_pipe
    # First two cooldown locks succeed; next two are suppressed by deduplication
    fake_redis.set = AsyncMock(side_effect=[True, True, False, False])

    detector = AnomalyDetector(fake_redis)
    first_alerts = asyncio.run(detector.evaluate(api_key_id=1, allowed=False))
    second_alerts = asyncio.run(detector.evaluate(api_key_id=1, allowed=False))

    alert_types = {a["alert_type"] for a in first_alerts}
    assert alert_types == {"VELOCITY_SPIKE", "RATE_LIMIT_ABUSE"}
    assert second_alerts == []


def test_openapi_routes_registered():
    paths = app.openapi()["paths"]
    for expected in (
        "/health",
        "/api/v1/keys",
        "/api/v1/resource",
        "/api/v1/logs",
        "/api/v1/alerts",
        "/api/v1/stats",
    ):
        assert expected in paths