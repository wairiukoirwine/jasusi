# JASUSI — Security review (OWASP API Security Top 10, 2023)

Self-assessment of the code in this repository on 2026-11-16. "Tested" means an automated test
covers it. Nothing here has been reviewed by a third party or penetration-tested.

| Risk | Status | What is in place | Gap |
|---|---|---|---|
| API1 Broken object-level authorisation | Partly | Scans are only addressable by random UUID; `/feedback` needs that UUID | Any caller holding a scan id can post feedback for it; there is no per-owner check |
| API2 Broken authentication | Done for keys (tested) | Random 32-byte API keys, only SHA-256 stored, revocation flag, 401 on bad key | No key rotation or expiry; keys are optional unless `REQUIRE_API_KEY=true` |
| API3 Object property-level authorisation | Done | Explicit Pydantic response models; stats return masked IOCs only (tested) | — |
| API4 Unrestricted resource consumption | Done (tested) | Per-caller rate limit, SMS ≤ 2,000 chars, e-mail ≤ 50 KB, body ≤ 64 KB, ≤ 5 links per scan, 3 s intel timeout | In-memory limiter is per process; use Redis with more than one worker |
| API5 Broken function-level authorisation | Partly | `/stats` requires a key when keys are required (tested) | No separate analyst role: any valid key can read stats |
| API6 Sensitive business flows | Not applicable yet | — | Feedback could be spammed to skew retraining; feedback is not used for training yet |
| API7 Server-side request forgery | Done by design | The backend never fetches a submitted URL; intel calls go to fixed provider hosts, and only the registered domain is sent to RDAP | — |
| API8 Security misconfiguration | Partly | CORS allowlist, `nosniff` / `no-referrer` / frame-deny headers, non-root container, ports bound to localhost in compose | No TLS termination or HSTS in this repo (belongs to the reverse proxy); interactive docs at `/docs` are open |
| API9 Improper inventory management | Done | One versioned prefix (`/v1`), OpenAPI generated from code | — |
| API10 Unsafe consumption of APIs | Done (tested) | Intel responses parsed defensively, provider errors fail open, no redirects followed to provider-supplied locations except RDAP's registry redirect | Provider integrations are tested against mocks only, never against the live services |

## Privacy controls (Kenya DPA 2019)
- Scan content is never stored: SHA-256 fingerprint only (tested).
- IOCs are stored masked (phones, e-mails) or defanged (links) (tested).
- Donated text is stored only with consent, anonymised, and encrypted with a key from the
  environment; without a key nothing is stored (tested).
- The anonymiser masks phones, e-mails and IDs by pattern; **names are masked by context rules and
  some will be missed**.
- Logs contain no message text, links or keys.

## Dependency scanning
`pip-audit` and `npm audit --audit-level=high` run in CI. Both reported no known vulnerabilities on
2026-11-16.

## Not done
Input fuzzing, a penetration test, secrets scanning in CI, and a threat model review.
