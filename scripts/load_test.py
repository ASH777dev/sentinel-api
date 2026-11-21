import asyncio
import statistics
import sys
import time
import httpx

BASE_URL = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
TOTAL_REQUESTS = 60
CONCURRENCY = 15


def percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    idx = max(0, min(len(sorted_values) - 1, int(round((pct / 100) * len(sorted_values))) - 1))
    return sorted_values[idx]


async def run_benchmark() -> None:
    limits = httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=CONCURRENCY)
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0, limits=limits) as client:
        key_res = await client.post(
            "/api/v1/keys",
            json={"name": f"loadtest-{int(time.time())}", "tier": "pro"},
        )
        key_res.raise_for_status()
        api_key = key_res.json()["api_key"]
        expected_limit = key_res.json()["rate_limit"]

        semaphore = asyncio.Semaphore(CONCURRENCY)
        statuses: dict[int, int] = {}
        latencies_ms: list[float] = []

        async def hit_endpoint() -> None:
            async with semaphore:
                t0 = time.perf_counter()
                resp = await client.get("/api/v1/resource", headers={"X-API-Key": api_key})
                elapsed = (time.perf_counter() - t0) * 1000
                latencies_ms.append(elapsed)
                statuses[resp.status_code] = statuses.get(resp.status_code, 0) + 1

        started = time.perf_counter()
        await asyncio.gather(*(hit_endpoint() for _ in range(TOTAL_REQUESTS)))
        total_sec = time.perf_counter() - started

    latencies_ms.sort()
    ok_count = statuses.get(200, 0)
    blocked_count = statuses.get(429, 0)
    err_count = sum(v for k, v in statuses.items() if k >= 500)

    print(f"\n=== Sentinel API Benchmark ({BASE_URL}) ===")
    print(f"Total Requests : {TOTAL_REQUESTS} (Concurrency: {CONCURRENCY})")
    print(f"Elapsed Time   : {total_sec:.2f}s | Throughput: {TOTAL_REQUESTS / total_sec:.2f} req/s")
    print(f"200 OK         : {ok_count} (Expected: {expected_limit})")
    print(f"429 Blocked    : {blocked_count} (Expected: {TOTAL_REQUESTS - expected_limit})")
    print(f"5xx Errors     : {err_count}")
    print(
        f"Latency (ms)   : p50={statistics.median(latencies_ms):.1f} | "
        f"p95={percentile(latencies_ms, 95):.1f} | p99={percentile(latencies_ms, 99):.1f}"
    )
    atomic_pass = ok_count == expected_limit and err_count == 0
    print(f"Atomicity Test : {'PASSED' if atomic_pass else 'CHECK RESULTS'}\n")


if __name__ == "__main__":
    asyncio.run(run_benchmark())