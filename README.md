# ARGUS

**Autonomous Digital Investigation & Threat Intelligence Engine**

ARGUS takes suspicious digital artefacts (emails, URLs, logs, packet captures, files, screenshots), extracts
indicators, runs deterministic detections and two trained models over them, correlates what the artefacts
share, has a set of specialised agents investigate, re-checks every conclusion against the preserved
evidence, and writes a forensic report with ATT&CK mappings and tested detection rules.

![Investigation workspace during a live analysis](docs/screenshots/workspace-live.png)

## 1. What it is

An investigation engine with a workstation UI. It is not a chatbot, not an LLM wrapper, not a SIEM. The
default configuration uses **no language model at all** and makes **no network connections**.

## 2. Why it exists

Triage tools tend to either dump indicators without connecting them, or let a language model narrate a
conclusion nobody can audit. ARGUS is built around one rule: **a claim is only reported if it points at
evidence, and an independent step has re-derived it from that evidence.** It separates five outcomes that
are usually blurred together:

| Classification | Meaning | What can produce it |
|---|---|---|
| `confirmed_malicious` | Two independent bases agree, or a malicious-class signature matched | Signature, or real threat intel **plus** observed behaviour on the same indicator |
| `suspicious` | Evidence-backed indicator of malicious activity | Deterministic detectors, correlation, ML (capped here) |
| `benign` | A check ran and found nothing | Deterministic checks |
| `insufficient_evidence` | Weak or ambiguous signal | Any detector |
| `unverified_intel` | Third-party reputation says so; nothing in the evidence does | Threat-intel lookups |

An ML score, a reputation hit or visual similarity can never confirm maliciousness on its own. This is
enforced by the Verifier and covered by tests.

## 3. How it works

```
submit evidence ─► hash + store original (read-only)
                    │
  ORCHESTRATOR ─────┤ plan from the evidence kinds present
                    ▼
  EVIDENCE ANALYST      parse → normalise to one event schema → deterministic detections + ML
  NETWORK ANALYST       flows, external destinations, connection sequences      (skipped if no network data)
  THREAT INTEL ANALYST  reputation lookups with source, reliability, query time
  FORENSICS ANALYST     entity resolution, evidence graph, cross-source chains, timeline, attack-sequence hypothesis
  VERIFIER              re-hash evidence, re-count events, re-run YARA / URL analysis, enforce classification policy,
                        surface conflicts, may request follow-up analysis
  ORCHESTRATOR          verdict (deterministic), ATT&CK mapping, Sigma/YARA rule generation + testing
  REPORT GENERATOR      dossier from verified findings only
```

Every stage writes real progress events to the database; the UI (including the 3D core and the activity
stream) only ever displays those.

## 4. Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md). In short: FastAPI + SQLAlchemy backend with a 14-table relational
schema, a Next.js frontend that reaches the backend through a server-side proxy, PostgreSQL in Docker and
SQLite for zero-setup local runs.

## 5. Technology stack

| Layer | Used |
|---|---|
| Backend | Python 3.13, FastAPI, Pydantic v2, SQLAlchemy 2 |
| Database | PostgreSQL 16 (compose) / SQLite (local default). Test suite passes on both |
| Security analysis | Scapy (PCAP), yara-python, pySigma, custom URL / email / log detectors |
| ML | scikit-learn: Random Forest (phishing URLs), Isolation Forest (network flows) |
| Vision | OpenCV: pHash, dHash, HSV histograms, ORB keypoints |
| Frontend | Next.js 14, TypeScript, Tailwind, Three.js + React Three Fiber + Drei, GSAP, Framer Motion, React Flow |
| Infra | Docker, Docker Compose, env-based configuration |

Deliberately **not** used: Wazuh or any SIEM, an agent framework, PyTorch, pgvector, Recharts. None was needed
(ARCHITECTURE.md records why).

## 6. Installation

Quick local run (details and Docker in [SETUP.md](SETUP.md)):

```bash
# backend
cd backend && python -m venv ../.venv && ../.venv/bin/pip install -r requirements.txt
../.venv/bin/uvicorn app.main:app --port 8000

# frontend (second terminal)
cd frontend && npm install && npm run build && npm start      # http://localhost:3000
```

Trained models, YARA rules, reference screenshots and sample datasets are included, so it works offline
immediately.

## 7. Usage

1. **New Investigation**: title the case, drop files / add a URL / paste text, launch.
2. **Investigation Workspace**: watch stages, agents and the activity stream update live; click any entity.
3. **Evidence Universe**: 3D graph (2D alternative one click away). Filter by type and severity, scrub time,
   isolate an entity, expand clusters, walk between connected entities. Every edge shows its supporting evidence.
4. **Evidence Explorer**: provenance, hashes, extracted metadata, indicators, events, relationships.
5. **Temporal Reconstruction**: play or scrub the incident; inferred items are drawn hollow and labelled.
6. **Detection Laboratory**: generated Sigma / YARA rules with validation and test results, ATT&CK mapping,
   model evaluation.
7. **Forensic Dossier**: print or save as PDF, or export HTML / Markdown / JSON.

`⌘K` / `Ctrl K` searches indicators, evidence, findings and cases across all investigations. `?` lists shortcuts.

API example:

```bash
ID=$(curl -s -X POST localhost:8000/api/investigations -H 'content-type: application/json' -d '{"title":"demo"}' | jq -r .id)
curl -s -X POST localhost:8000/api/investigations/$ID/evidence/file -F file=@backend/data/samples/phishing_email.eml
curl -s -X POST localhost:8000/api/investigations/$ID/start
curl -s localhost:8000/api/investigations/$ID/report | jq .content.verdict
```

## 8. Demo

The landing page lists **bundled sample scenarios**. Each creates a real investigation from synthetic,
harmless evidence and runs the full pipeline. Start with *Phishing email to workstation beaconing*: an email,
a packet capture and endpoint events that share infrastructure.

| | |
|---|---|
| ![Evidence Universe](docs/screenshots/universe.png) | ![Temporal Reconstruction](docs/screenshots/timeline.png) |
| ![Detection Laboratory](docs/screenshots/lab.png) | ![Forensic Dossier](docs/screenshots/dossier.png) |

## 9. Limitations

Read these before trusting an output.

**Not implemented**
- Windows `.evtx` binary logs (JSON / NDJSON exports of Windows and Sysmon events are supported).
- Zeek log ingestion (network analysis is Scapy over PCAP only).
- MISP, WHOIS and DNS intelligence integrations.
- Dynamic / sandboxed execution. All file analysis is static.
- Screenshot capture by ARGUS, logo detection, OCR. Vision compares uploaded screenshots with a reference library.
- Users and roles. Authentication is one shared API key.

**Implemented but not exercised against the real thing in the build environment**
- VirusTotal, AbuseIPDB and OTX adapters: tested with mocked HTTP responses only.
- OpenAI-compatible and Anthropic narrative providers: tested with fake providers only.
- Live URL fetching through the SSRF guard: guard logic is tested; no real site was fetched.
- Dockerfiles and `docker-compose.yml`: written, not built (no Docker daemon was available).

**Model caveats**
- Phishing URL classifier: accuracy 0.915, precision 0.891, recall 0.924, ROC AUC 0.969 on a held-out,
  domain-disjoint split of a 2017-18 public corpus. Lexical features only. Expect lower accuracy on today's URLs.
- Network anomaly model: trained and evaluated on **synthetic** traffic (precision 0.63, recall 0.71, ROC AUC 0.98
  on a synthetic hold-out). Those numbers say nothing about a real network until it is retrained on your captures.
- Bundled threat intelligence is fictional sample data and is labelled as such everywhere it appears.

**Other**
- Large inputs are capped: 25 MB per upload, 300,000 packets per capture, 20,000 events per log, and the timeline
  thins beyond 1,500 events (events tied to findings are always kept).
- The Sigma tester is a built-in evaluator for the subset of Sigma that ARGUS generates, not a SIEM backend.
- ATT&CK mappings cover a curated subset of 30 techniques.
- No automated frontend unit tests; the UI is covered by a scripted headless-browser flow (`frontend/scripts/ui-flow.cjs`).

## 10. Future development

`.evtx` and Zeek ingestion; MISP and passive-DNS adapters; isolated detonation for files and URLs; retraining
the anomaly model on real baselines with a feedback loop from analyst verdicts; per-user accounts and case
sharing; Sigma correlation rules for threshold detections; STIX 2.1 export.

---

Documentation: [ARCHITECTURE](ARCHITECTURE.md) · [API](API_DOCUMENTATION.md) · [Threat model](THREAT_MODEL.md) ·
[Setup](SETUP.md) · [Testing](TESTING.md) · [Contributing](CONTRIBUTING.md)
