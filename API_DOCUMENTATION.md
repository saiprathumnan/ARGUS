# API

Base path `/api`. JSON in and out. When `ARGUS_API_KEY` is set, send `X-API-Key` on every call except
`/api/health`. Interactive OpenAPI docs: `/api/docs` (not in production mode). Errors are
`{"detail": "..."}` with a meaningful status (400, 401, 404, 409, 413, 422, 429).

## System

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness + database check |
| GET | `/system` | Capabilities: evidence kinds, limits, intel providers, LLM role, model metrics, reference pages. Never returns secrets |
| GET | `/audit?limit=` | Audit log, newest first |
| GET | `/search?q=` | Search investigations, indicators, evidence (name / hash / id) and findings |

## Investigations

| Method | Path | Purpose |
|---|---|---|
| POST | `/investigations` | `{title, description?}` → summary |
| GET | `/investigations?q=&status=&verdict=&limit=` | History with filters |
| GET | `/investigations/{id}` | Summary, evidence list, agent executions, finding statistics |
| DELETE | `/investigations/{id}` | Delete with all derived data (409 while running) |
| POST | `/investigations/{id}/start` | Queue analysis (202). On a completed or failed case, rebuilds all derived data from the preserved originals |

Summary fields: `id, title, status (created|running|completed|failed), stage, verdict, verdict_confidence,
error, created_at, started_at, completed_at, counts{evidence, indicators, events, findings, relationships, rules}`.

## Evidence

| Method | Path | Body |
|---|---|---|
| POST | `/investigations/{id}/evidence/url` | `{"url": "..."}` |
| POST | `/investigations/{id}/evidence/file` | multipart: `file`, `kind` (`auto` or a kind), `source_url` (screenshots only) |
| POST | `/investigations/{id}/evidence/text` | `{"kind": "email_headers|json_events|auth_log", "content": "...", "name"?}` |
| GET | `/investigations/{id}/evidence/{evidence_id}` | Provenance, metadata, indicators, events, relationships, findings |

Kinds: `url, eml, email_headers, json_events, auth_log, pcap, file, pdf, screenshot`. The kind is detected
from content; a declared kind that contradicts the content is rejected (422). Identical evidence (same
SHA-256 and kind) in one case is rejected (409).

## Results

| Method | Path | Returns |
|---|---|---|
| GET | `/investigations/{id}/events?after=` | Activity stream since event id `after`, plus current status / stage |
| GET | `/investigations/{id}/agents/{execution_id}` | One agent execution with its full structured output |
| GET | `/investigations/{id}/findings` | All findings with basis, classification, confidence, evidence / event ids, verification status and notes |
| GET | `/investigations/{id}/indicators?type=&q=` | De-duplicated indicators with sources, severity and reputation |
| GET | `/investigations/{id}/graph` | `{nodes, edges, time_range, counts}`. Every edge has `basis`, `confidence`, `evidence_ids`, `explanation` |
| GET | `/investigations/{id}/timeline` | Ordered entries with `time_basis`, layers, inferred attack sequence, inconsistencies |
| GET | `/investigations/{id}/mitre` | Technique mappings, each linked to a finding with a rationale |
| GET | `/investigations/{id}/rules` | Sigma / YARA rules with versions, validation and test results |
| GET | `/investigations/{id}/intel` | Reputation records with source, reliability, query time, cache flag |
| GET | `/investigations/{id}/report` | Latest report content |
| GET | `/investigations/{id}/report/export?format=html|md|json` | Standalone print-ready HTML, Markdown or JSON |
| GET | `/reports` | All generated reports |

## Samples

| Method | Path | Purpose |
|---|---|---|
| GET | `/samples` | Bundled synthetic scenarios with expected verdicts |
| POST | `/samples/{scenario_id}` | Create an investigation loaded with that scenario's evidence (source `bundled_sample_dataset`) |

## Finding object

```json
{
  "id": "FND-…", "detector": "auth.password_spraying", "title": "46 failed logins from 198.51.100.23 across 8 accounts",
  "severity": "high", "classification": "suspicious", "basis": "deterministic", "confidence": 0.85,
  "evidence_ids": ["EVD-…"], "event_ids": ["EVT-…"], "indicators": ["198.51.100.23", "root"],
  "details": {"failures": 46, "accounts": ["admin", "deploy"], "window_seconds": 153.0, "source_ip": "198.51.100.23"},
  "produced_by": "detection_engine", "verification_status": "verified",
  "verification_notes": "recounted 46 cited failure events from 198.51.100.23"
}
```

`basis`: `deterministic | signature | ml_model | threat_intel | visual_similarity | correlation`.
`verification_status`: `unverified | verified | downgraded | rejected`.
