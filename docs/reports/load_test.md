# Load test — 2026-11-16

`scripts/loadtest.py`, 1,000 requests per run, mixed SMS / e-mail / link scans, trained models loaded,
threat intel off. One Uvicorn worker, SQLite, in-memory cache, on a 4-core cloud container
(server and load generator on the same machine).

| Concurrency | Errors | Throughput | p50 | p95 | p99 |
|---|---|---|---|---|---|
| 1 | 0 | 73 req/s | 11.2 ms | 22.5 ms | 30.1 ms |
| 5 | 0 | 82 req/s | 57.0 ms | 95.5 ms | 150.2 ms |
| 20 | 0 | 87 req/s | 163.0 ms | 644.8 ms | 1474.3 ms |

## Reading this
- The PRD target (p95 < 300 ms for a scan without intel) is met for single requests and at 5 concurrent
  clients, and **missed at 20 concurrent clients on one worker**.
- Throughput is flat at about 80–90 req/s: one worker is CPU-bound, so extra clients only queue.
  The next steps are more workers (`uvicorn --workers 4`), Postgres instead of SQLite, and then
  re-running this test. That has not been done yet.
- Not a production benchmark: no network latency, no Redis/Postgres, no threat-intel calls.
