import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_tmp = tempfile.mkdtemp(prefix="argus-test-")
os.environ.update({"ARGUS_DATABASE_URL": os.environ.get("ARGUS_TEST_DATABASE_URL", f"sqlite:///{_tmp}/test.db"),  # set ARGUS_TEST_DATABASE_URL to run the suite on PostgreSQL
                   "ARGUS_STORAGE_DIR": f"{_tmp}/storage", "ARGUS_RUN_INLINE": "true", "ARGUS_INTEL_OFFLINE": "true",
                   "ARGUS_ALLOW_NETWORK_FETCH": "false", "ARGUS_RATE_LIMIT_PER_MINUTE": "100000", "ARGUS_LLM_PROVIDER": "none", "ARGUS_ENV": "local"})
os.environ.pop("ARGUS_API_KEY", None)

SAMPLES = ROOT / "data" / "samples"


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def scenario_runs(client):
    """Run every bundled scenario once end-to-end and cache {scenario_id: investigation detail}."""
    cache = {}

    def run(sid: str) -> dict:
        if sid not in cache:
            inv = client.post(f"/api/samples/{sid}").json()
            r = client.post(f"/api/investigations/{inv['id']}/start")
            assert r.status_code == 202, r.text
            cache[sid] = client.get(f"/api/investigations/{inv['id']}").json()
        return cache[sid]
    return run


@pytest.fixture
def new_investigation(client):
    def make(title="test"):
        return client.post("/api/investigations", json={"title": title}).json()["id"]
    return make
