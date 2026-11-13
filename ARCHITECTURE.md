# Architecture

## Layout

```
backend/app/
  api/routes.py          HTTP layer only: validation, auth-agnostic handlers, serialisation
  main.py                app factory, middleware (API key, rate limit, body size, security headers)
  config.py              environment-based settings
  db.py, models.py       engine/session, relational schema
  security/              ssrf.py (safe fetch), uploads.py (validation, sniffing, read-only storage)
  ingestion/             base.py (common schema + pipeline registry), pipelines.py (one function per kind), store.py
  analysis/              url.py, email.py, logs.py, network.py, file.py, ioc.py   (deterministic detection engine)
  ml/                    features.py, train_*.py, phishing.py, anomaly.py, synthetic_traffic.py
  vision/similarity.py   screenshot comparison
  intel/                 providers.py (offline bundle, VirusTotal, AbuseIPDB, OTX), service.py (cache, rate limits)
  correlation/engine.py  entity resolution, edge merging, cross-source chains, graph
  agents/                orchestrator.py, agents.py, verifier.py, llm.py
  mitre/mapping.py       ATT&CK mapping rules
  rules/                 generator.py (Sigma/YARA + validation), sigma_eval.py (test evaluator)
  reports/               generator.py (dossier content), export.py (HTML, Markdown)
backend/data/            models, YARA rules, sample intel, reference screenshots, sample + labelled datasets
frontend/src/
  app/                   routes: / · /new · /i/[id] · /i/[id]/{universe,evidence,timeline,lab,dossier} · /history · /reports · /settings
  app/api/[...path]/     server-side proxy to the backend
  components/three/      IntelligenceCore, EvidenceUniverse, Graph2D, TemporalScene (each a lazy chunk)
  components/            shell (nav, command palette), GraphView, Inspector, ui kit
  lib/                   api client + hooks, case state, graph layout/filtering, formatting, types
```

## Data model

Fourteen tables. Provenance runs in one direction and is never broken:

```
investigations ─┬─ evidence ─┬─ indicators
                │            └─ security_events
                ├─ findings          (evidence_ids, event_ids, indicator_values, basis, classification, verification_status)
                ├─ relationships     (source, target, relation, basis, confidence, evidence_ids, event_ids)
                ├─ intel_records     (source, reliability, verdict, queried_at, from_cache)        intel_cache
                ├─ agent_executions  (agent, task, status, attempt, structured output)
                ├─ pipeline_events   (append-only activity stream)
                ├─ mitre_mappings ── findings
                ├─ detection_rules   (rule_key, version, content, validation, finding_ids, evidence_ids, deployed=false)
                └─ reports           (versioned JSON content)
audit_logs
```

All timestamps are UTC. Original evidence lives on disk under a server-generated path, read-only; the
database stores its SHA-256 and metadata, not a second copy of the bytes.

### Common event schema

Every pipeline normalises into `security_events`: `timestamp, category, action, outcome, src_ip, dst_ip,
dst_port, protocol, domain, url, user, host, summary, data{}, record_ref, fingerprint`. `record_ref` points
back into the original (line number, packet number, record index). Detectors and the Sigma tester work on
this schema only, which is why a rule generated from an auth log can be tested against a JSON corpus.

## Request flow

1. `POST /evidence/*` validates, sniffs the kind from content, hashes, stores read-only, writes an audit row.
2. `POST /start` hands the investigation to a bounded worker pool (`ARGUS_WORKERS`).
3. Each agent runs in its own transaction and records an `agent_executions` row plus `pipeline_events`.
4. The frontend polls `/investigations/{id}`, `/events?after=` and refetches graph/findings when counts change.

## Decisions

**ADR-001. SQLite by default, PostgreSQL for deployment.** Zero-setup local runs matter for a tool people
try on a laptop; Compose uses PostgreSQL. The suite runs on both (`ARGUS_TEST_DATABASE_URL`). Running it on
PostgreSQL caught a real defect (an over-long string that SQLite silently accepted), which is why string
columns are now clipped before insert.

**ADR-002. The verdict is computed, never generated.** `compute_verdict` is a pure function of verified
findings: any verified `confirmed_malicious` → malicious; otherwise evidence-based `suspicious` at medium+
severity → suspicious; only weak signals → insufficient evidence; only clean checks → benign. Conflicts
reduce confidence. No model output is an input.

**ADR-003. A fixed custom orchestrator, not an agent framework.** A forensic process should run the same
steps in the same order every time and leave a record. The orchestrator is about 200 lines: plan, dispatch,
per-agent transaction, failure handling (required vs optional agents), one verifier-requested follow-up
loop. A framework would add dependencies and nondeterminism without adding capability here.

**ADR-004. An independent verifier gates everything.** Findings start `unverified`. The Verifier re-reads
the database and the preserved bytes: evidence exists and still hashes correctly, cited events exist and
belong to the cited evidence, every named indicator is present in that evidence, countable claims are
recounted, YARA and URL results are recomputed, and classification policy is enforced. During development
it rejected one of ARGUS's own detections (a DNS finding naming a parent domain that was never extracted
as an indicator), which was then fixed at the source.

**ADR-005. `confirmed_malicious` needs two independent bases or a malicious-class signature.** ML,
reputation and visual similarity are each capped below confirmation. Bundled sample intelligence has
reliability `sample` and never counts toward confirmation.

**ADR-006. Phishing model: leakage controls over headline accuracy.** Exact duplicates removed after
canonicalisation; train/test split grouped by registered domain (0 shared domains); scheme and leading
`www.` stripped because in this corpus they are collection artefacts (1.8% of phishing URLs vs 37% of
legitimate ones are HTTPS, which reflects 2017, not phishing). The honest result is 0.915 accuracy; a
random split of the same data scores higher and would be misleading.

**ADR-007. Anomaly model: Isolation Forest on a documented synthetic baseline.** Unsupervised, because
labelled attacks are scarce and benign-only training matches reality. No redistributable PCAP corpus was
available, so the baseline is generated, with realistic confounders (NTP, software update polling, services
on non-standard ports). Generated flows pass through the same feature code as real captures. The decision
threshold is set on a separate benign validation set (target FPR 2%), never on the test set. Its findings
are `low` severity and say plainly that the baseline is synthetic.

**ADR-008. A built-in Sigma evaluator for testing.** pySigma validates syntax but does not execute rules.
To report true/false positives without a SIEM, ARGUS evaluates the Sigma subset it generates against
normalised events. Unsupported fields for a log source are flagged. This tests rule logic, not field
mappings of a specific SIEM.

**ADR-009. The browser never talks to the backend.** A Next.js route handler proxies `/api/*` and attaches
the API key from the server environment, so no secret or backend address ships in client JavaScript.

**ADR-010. 3D that stays out of the way.** Instanced meshes per entity type, one line-segment buffer for
all edges, a procedural environment map instead of HDR downloads, additive point halos instead of a
post-processing bloom pass, no text meshes (HTML labels for a bounded set of nodes). Every scene is a lazy
chunk; first-load JavaScript for the workspace is about 150 kB and the 3D code is fetched only when a graph
is shown. Each 3D view has a 2D equivalent that is used automatically without WebGL. Reduced-motion
disables autorotation, damping and animated camera moves and switches rendering to on-demand.

**ADR-011. No network by default.** Live URL fetching and external intelligence are opt-in. With defaults,
the backend opens no outbound connection; a test asserts this by making any socket creation fail.

**ADR-012. "Internal address" is defined explicitly.** Python's `ipaddress.is_private` also covers
documentation ranges (RFC 5737), which the sample data uses for internet hosts. Analysis uses an explicit
list (RFC 1918, loopback, link-local, CGNAT, ULA, multicast). The SSRF guard is stricter and keeps
`is_private` semantics plus extra ranges.

**ADR-013. Submission time is not incident time.** Events and indicators that only carry the moment an
analyst submitted something are kept off the incident timeline and the graph's time range when real
timestamps exist; otherwise they are shown and labelled `submission time`.

**ADR-014. Evidence text is data.** The optional LLM receives only structured findings produced by ARGUS,
with an instruction that embedded text is untrusted; raw evidence bodies are never sent. Whatever the model
returns is parsed as JSON and verified sentence by sentence.

## What "inferred" means in ARGUS

- **Relationship basis**: `observed` (seen in evidence: a DNS answer, a captured flow), `derived`
  (structural identity: a URL and its host), `inferred` (heuristic). Cross-source chains use only observed
  and derived edges.
- **Timeline time basis**: `confirmed` (timestamp recorded in the evidence), `inferred` (e.g. syslog lines
  with no year), `submission_time`.
- **Attack sequence**: always labelled an inferred hypothesis; it orders verified findings by time and
  claims no causality.
