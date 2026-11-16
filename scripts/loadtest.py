"""Small load test for the scan API: N requests at a fixed concurrency, latency percentiles.

Start a server with a high rate limit first, e.g.
  RATE_LIMIT_PER_MINUTE=1000000 DATABASE_URL=sqlite:///./loadtest.db \
    uvicorn app.main:app --app-dir backend --port 8001
Then:  python scripts/loadtest.py --base http://127.0.0.1:8001 --requests 2000 --concurrency 20
"""

import argparse
import asyncio
import statistics
import time

import httpx

MESSAGES = [
    (
        "/v1/scan/sms",
        {"text": "Nimekutumia Ksh 3,500 kimakosa. Tafadhali rudisha haraka kwa 0700000101"},
    ),
    ("/v1/scan/sms", {"text": "Uko wapi? Tukutane saa kumi kwa stage."}),
    (
        "/v1/scan/sms",
        {"text": "KRA: account suspended. Verify at http://kra-itax-verify.xyz/login now"},
    ),
    ("/v1/scan/url", {"url": "http://safaricom-rewards.top/claim?id=8821"}),
    (
        "/v1/scan/email",
        {"subject": "Minutes", "body": "Hi team, minutes from Monday attached. Regards"},
    ),
]


async def run(base: str, total: int, concurrency: int) -> None:
    latencies: list[float] = []
    errors = 0
    queue: asyncio.Queue[int] = asyncio.Queue()
    for i in range(total):
        queue.put_nowait(i)

    async def worker(client: httpx.AsyncClient) -> None:
        nonlocal errors
        while True:
            try:
                i = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            path, body = MESSAGES[i % len(MESSAGES)]
            start = time.perf_counter()
            try:
                response = await client.post(base + path, json=body)
                if response.status_code != 200:
                    errors += 1
            except httpx.HTTPError:
                errors += 1
            latencies.append((time.perf_counter() - start) * 1000)

    started = time.perf_counter()
    async with httpx.AsyncClient(timeout=30) as client:
        await asyncio.gather(*(worker(client) for _ in range(concurrency)))
    elapsed = time.perf_counter() - started
    q = statistics.quantiles(latencies, n=100)
    print(f"requests={total} concurrency={concurrency} errors={errors} "
          f"throughput={total / elapsed:.0f} req/s")  # fmt: skip
    print(f"latency ms: p50={q[49]:.1f} p95={q[94]:.1f} p99={q[98]:.1f} max={max(latencies):.1f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--base", default="http://127.0.0.1:8001")
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--concurrency", type=int, default=20)
    args = parser.parse_args()
    asyncio.run(run(args.base, args.requests, args.concurrency))
