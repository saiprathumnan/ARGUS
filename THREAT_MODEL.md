# Threat model

ARGUS deliberately ingests hostile material. This document states what is defended, how, and what is not.

## Assets

1. The host and network ARGUS runs on.
2. Integrity of evidence and of conclusions drawn from it.
3. Secrets: API key, threat-intel keys, LLM key.
4. Confidentiality of submitted evidence.

## Trust boundaries

```
analyst browser ──► Next.js server ──(API key)──► FastAPI backend ──► database, evidence store
                                                        │
                           untrusted: every byte of submitted evidence
                           semi-trusted: intel providers, optional LLM
```

Everything inside an uploaded file, a URL, an email, a log line or a screenshot is attacker-controlled.

## Threats and mitigations

| # | Threat | Mitigation | Verified by |
|---|---|---|---|
| T1 | **SSRF** through a submitted URL or a redirect, reaching loopback, private ranges or cloud metadata | Fetching is off by default. When enabled: http/https only, ports 80/443/8080/8443, no credentials in URL, hostname resolved and **every** address must be public, decimal/hex/octal IP forms normalised, connection pinned to the validated IP (no second lookup), redirects followed manually and re-validated, size / time / redirect caps | `test_ssrf_*` (25 blocked forms, rebinding-style answers, redirect to metadata), `test_backend_never_fetches_when_network_disabled` |
| T2 | **Malicious file execution** | Files are only ever read as bytes. Stored under a generated name with mode 0400, never opened with a handler, unpacked or rendered. PCAPs are parsed, never replayed. Encoded PowerShell is decoded as text, never run | `test_verifier_detects_evidence_tampering` (asserts no write/execute bits), code review of `analysis/` |
| T3 | **Path traversal** via filename or identifiers | Client filename is metadata only; storage path is built from validated server-generated ids and checked to be inside the storage root | `test_filename_sanitisation_and_traversal`, `test_traversal_filename_upload_is_stored_under_generated_path` |
| T4 | **Type confusion / malformed uploads** | Kind decided by content sniffing; declared kind must agree; size cap enforced while reading; a parser failure marks one item failed without aborting the case | `test_content_sniffing_beats_extension`, `test_malformed_uploads_fail_safely`, `test_oversize_upload_rejected` |
| T5 | **Prompt injection** from evidence into the LLM | No LLM by default. When enabled it never sees raw evidence, never classifies, and its output is verified sentence by sentence against finding ids and known indicators. The verdict is computed without it | `test_prompt_injection_cannot_change_verdict_or_inject_claims` (a fake model that obeys the injection and hallucinates) |
| T6 | **Fabricated or unsupported conclusions** (from a bug, a compromised component or a model) | Verifier rejects findings with missing evidence, foreign indicators, inflated counts; downgrades over-claims | `test_verifier_rejects_fabricated_and_unsupported_findings` |
| T7 | **Evidence tampering at rest** | SHA-256 at ingestion; Verifier re-hashes before accepting findings; mismatch rejects every finding citing that item | `test_verifier_detects_evidence_tampering` |
| T8 | **SQL injection** | SQLAlchemy bound parameters everywhere; no string-built SQL | `test_sql_injection_strings_are_data` |
| T9 | **XSS / HTML injection** through evidence text in the UI or report | React escapes by default, no `dangerouslySetInnerHTML`; HTML export uses Jinja2 autoescape | `test_html_report_escapes_evidence_content` |
| T10 | **Unauthenticated access** | API key (constant-time compare) on all routes but health; mandatory in production mode; key kept server-side by the frontend proxy | `test_authentication_enforced_when_key_configured`, `test_production_requires_api_key` |
| T11 | **Secret leakage** | Keys only in server environment; `/system` reports provider status without values; nothing key-bearing is logged | `test_secrets_never_leave_the_backend` |
| T12 | **Resource exhaustion** | Upload size cap, evidence-per-case cap, packet / event / string caps, YARA timeout, bounded worker pool, per-client rate limit | `test_rate_limit`, `test_oversize_upload_rejected`, `test_concurrent_investigations_do_not_interfere` |
| T13 | **Poisoned threat intel or misleading reputation** | Stored with source and reliability; classified `unverified_intel`; cannot confirm alone; conflicts with evidence are surfaced | `test_confirmed_malicious_requires_two_independent_non_sample_bases`, `test_verifier_surfaces_conflicting_intel` |
| T14 | **Automated response abuse** | ARGUS takes no response action. Rules are never deployed (`deployed` has no setter). Recommended actions are text marked "requires human approval" | `test_detection_rules_generated_validated_and_tested` |

## Residual risks (not mitigated)

- **Parser vulnerabilities.** Scapy, OpenCV / Pillow, yara-python and Python's email parser process hostile
  bytes in the backend process. There is no per-parser sandbox. Run the backend in the provided hardened
  container (non-root, read-only root filesystem, no capabilities) or a VM, and keep dependencies patched.
- **Single shared API key**; no per-user identity, so the audit log records `api-key`, not a person.
- **Rate limiting is in-memory and per process**; it resets on restart and is not shared across replicas.
- **Evidence at rest is not encrypted** by ARGUS. Use disk encryption.
- **DNS pinning covers ARGUS's own fetch only.** If live fetching is enabled, the destination still sees
  the backend's egress IP; use an isolated egress for real investigations.
- **No TLS termination** is provided; put a reverse proxy in front for anything beyond localhost.
- **The proxy trusts whoever reaches the frontend.** In Compose it binds to 127.0.0.1. Add authentication
  at the reverse proxy before exposing it.
