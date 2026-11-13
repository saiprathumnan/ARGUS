# Testing

```bash
cd backend
../.venv/bin/python -m pytest                 # 92 tests, about 20 seconds, SQLite in a temp directory
ARGUS_TEST_DATABASE_URL=postgresql+psycopg2://USER:PASS@127.0.0.1:5432/argus_test ../.venv/bin/python -m pytest   # same suite on PostgreSQL
../.venv/bin/python scripts/evaluate_models.py [--phishing-data DIR]   # recompute model metrics and compare with stored figures
```

Tests run the pipeline inline, offline, with no LLM. Nothing is mocked inside the pipeline itself; only
outbound HTTP (intel providers) and the LLM are replaced by local fakes.

Last recorded result in the build environment: **92 passed** on SQLite and on PostgreSQL 16.

## What is covered

| File | Scope |
|---|---|
| `tests/test_unit.py` (19) | URL parser and look-alike logic, IOC extraction and defanging, email parser and detectors, event normalisation (ECS, Windows, Sysmon), auth-log parser, duplicate fingerprinting, brute-force thresholds and windows, PowerShell decoding, YARA rules, ML feature extraction, model sanity, screenshot similarity, Sigma evaluator |
| `tests/test_integration.py` (33) | The 11 scenarios end to end against ground truth, agent execution and structured outputs, cross-source correlation chain, no relationship from look-alike strings, timeline time-basis labels, ATT&CK mappings, rule generation / validation / testing, re-runs, verifier rejection of fabricated findings, tamper detection, conflicting intel, prompt-injection containment, LLM failure fallback, intel adapters (parsing, cache, 429, 500, no keys), the confirmation bar, API / search / history / audit, provenance, cascade delete, concurrent analyses, UTC timestamps |
| `tests/test_security.py` (40) | SSRF (25 blocked destination forms, rebinding-style answers, redirect to metadata, pinning), no network when disabled, filename sanitisation and traversal, content sniffing, malformed and oversized uploads, invalid input, SQL injection strings, authentication, rate limit, secret leakage, production key requirement, HTML escaping |

## Scenarios and ground truth

`backend/data/samples/scenarios.json` is the ground truth: each scenario lists its evidence, the expected
verdict and the detectors that must fire. `scripts/generate_samples.py` regenerates every file
deterministically. All hosts are RFC 5737 / RFC 2606 documentation values; nothing is live or harmful.

| Required scenario | Scenario id | Expected verdict |
|---|---|---|
| Suspicious phishing email | `phishing-email` | suspicious |
| Benign email | `benign-email` | benign |
| Suspicious URL | `suspicious-url` | suspicious |
| Benign URL | `benign-url` | benign |
| Brute-force authentication logs | `ssh-brute-force` | suspicious |
| Suspicious PowerShell event | `suspicious-powershell` | suspicious |
| Unusual outbound network traffic | `unusual-outbound` | suspicious |
| Harmless YARA test fixture | `yara-fixture` | benign (rule matches; classified as a self-test) |
| Website screenshot similarity | `screenshot-lookalike` | suspicious |
| Conflicting or insufficient evidence | `insufficient-evidence` | insufficient evidence |
| Cross-source correlation (extra) | `phishing-to-c2` | suspicious |

None of the bundled scenarios yields `malicious`: with sample intelligence and heuristics alone that would
be an over-claim. `test_confirmed_malicious_requires_two_independent_non_sample_bases` shows the path that
does confirm (a non-sample reputation source agreeing with observed beaconing).

The labelled corpus for rule testing is in `backend/data/samples/labelled/` (499 benign and 62 attack events
after normalisation) plus `benign_files/` for YARA false-positive checks.

## Frontend

There are no frontend unit tests. The UI is checked by a scripted headless-Chrome flow,
`frontend/scripts/ui-flow.cjs`, which: creates a case through the form with a URL and two uploaded files,
watches it run to completion, exercises a rejected upload, uses the command palette and keyboard
navigation, selects / isolates / filters / time-scrubs the 3D graph, plays the timeline and switches to 2D,
opens the laboratory tabs, renders the dossier to a real PDF, checks the missing-case and 404 states, checks
for horizontal overflow at 390 px, and loads with reduced motion. It prints any browser console error; the
last run printed none. `npm run typecheck` and `npm run build` must pass.

## Not tested

- Real VirusTotal / AbuseIPDB / OTX responses, real LLM endpoints, real outbound fetches.
- Docker images and Compose.
- Captures or logs larger than the bundled samples (performance at the documented caps is unmeasured).
- Browsers other than headless Chrome (software WebGL); real-GPU frame rates were not measured.
- Screen-reader behaviour beyond semantic roles and labels.
