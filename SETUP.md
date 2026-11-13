# Setup

## Requirements

- Python 3.11+ (developed on 3.13), Node.js 20+ (developed on 22)
- Optional: PostgreSQL 14+, Docker + Docker Compose

## Local run (SQLite, no external services)

```bash
git clone <repo> argus && cd argus

# backend
python -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
cd backend && ../.venv/bin/uvicorn app.main:app --port 8000
# first start imports the analysis libraries and loads the models (a few seconds)

# frontend, in another terminal
cd frontend
npm install
npm run build && npm start            # production build on http://localhost:3000
# or: npm run dev
```

Open http://localhost:3000. The header shows `ENGINE ONLINE` when the frontend can reach the backend.
Interactive API docs are at http://localhost:8000/api/docs (disabled in production mode).

The database (`backend/argus.db`) and evidence store (`backend/storage/`) are created on first start.

## Local run with PostgreSQL

```bash
createdb argus
export ARGUS_DATABASE_URL=postgresql+psycopg2://USER:PASSWORD@127.0.0.1:5432/argus
cd backend && ../.venv/bin/uvicorn app.main:app --port 8000
```

Tables are created on start. There is no migration tool yet; a schema change means recreating the database.

## Docker Compose

```bash
cp .env.example .env        # set POSTGRES_PASSWORD and ARGUS_API_KEY
docker compose up --build   # frontend on http://127.0.0.1:3000
```

The backend is not published to the host; the browser talks only to the frontend, which proxies `/api` and
attaches the API key server-side. The backend container runs as a non-root user with a read-only root
filesystem and all capabilities dropped.

> These container files were written but could not be built in the development environment (no Docker
> daemon). Treat the first `docker compose up` as their test.

## Configuration

All backend settings are environment variables with the `ARGUS_` prefix (or a `.env` file in `backend/`).

| Variable | Default | Effect |
|---|---|---|
| `ARGUS_ENV` | `local` | `production` disables `/api/docs` and **requires** `ARGUS_API_KEY` |
| `ARGUS_API_KEY` | unset | When set, every `/api` call except `/api/health` needs `X-API-Key` |
| `ARGUS_DATABASE_URL` | SQLite file | SQLAlchemy URL |
| `ARGUS_STORAGE_DIR` | `backend/storage` | Where original evidence is preserved |
| `ARGUS_CORS_ORIGINS` | `http://localhost:3000,...` | Only needed if a browser calls the backend directly |
| `ARGUS_MAX_UPLOAD_BYTES` | 26214400 | Per-file limit |
| `ARGUS_RATE_LIMIT_PER_MINUTE` | 240 | Per client address, in memory |
| `ARGUS_WORKERS` | 2 | Investigations analysed at once; others queue |
| `ARGUS_ALLOW_NETWORK_FETCH` | `false` | Fetch submitted URLs through the SSRF guard |
| `ARGUS_INTEL_OFFLINE` | `true` | Only the bundled sample intelligence is consulted |
| `ARGUS_VIRUSTOTAL_API_KEY`, `ARGUS_ABUSEIPDB_API_KEY`, `ARGUS_OTX_API_KEY` | unset | Enable a provider (needs `ARGUS_INTEL_OFFLINE=false`) |
| `ARGUS_INTEL_CACHE_TTL_SECONDS` | 86400 | Reputation cache lifetime |
| `ARGUS_LLM_PROVIDER` | `none` | `openai_compatible` (OpenAI, Ollama `/v1`, LM Studio) or `anthropic` |
| `ARGUS_LLM_BASE_URL`, `ARGUS_LLM_MODEL`, `ARGUS_LLM_API_KEY` | Ollama defaults | Narrative model |

Frontend (server-side only): `ARGUS_BACKEND_URL` (default `http://127.0.0.1:8000`), `ARGUS_API_KEY`.

### Using a local model for the report narrative (Ollama)

```bash
export ARGUS_LLM_PROVIDER=openai_compatible ARGUS_LLM_BASE_URL=http://localhost:11434/v1 ARGUS_LLM_MODEL=llama3.1
```

The model only rephrases verified findings. Each sentence it returns must cite finding IDs and is checked;
unsupported sentences are dropped and listed in the report's `llm_audit`. The verdict never involves the model.

## Data you may want to regenerate

```bash
cd backend
python scripts/generate_samples.py                       # sample scenarios, labelled corpus, reference screenshots
python -m app.ml.train_anomaly [--pcap-dir DIR]          # retrain on your own benign captures
scripts/fetch_datasets.sh ./datasets                     # public phishing corpus (not redistributed here)
python -m app.ml.train_phishing --data ./datasets/pdd/input
python scripts/evaluate_models.py --phishing-data ./datasets/pdd/input   # recompute every published metric
```

Add your own YARA rules as `backend/data/yara/*.yar` (set `argus_class` in `meta`), and reference pages for
visual comparison in `backend/data/references/` (`references.json` lists each image and its legitimate domains).
