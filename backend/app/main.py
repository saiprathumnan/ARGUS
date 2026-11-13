"""ARGUS API."""
import hmac
import re
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.routes import router
from .config import get_settings
from .db import init_db

_hits: dict[str, deque] = defaultdict(deque)
_SECRET = re.compile(r"(api[_-]?key|authorization|x-api-key|token)", re.I)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from .agents.orchestrator import warm_up
    warm_up()
    yield


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title="ARGUS", version="1.0.0", description="Autonomous Digital Investigation & Threat Intelligence Engine", lifespan=lifespan,
                  docs_url="/api/docs" if s.env != "production" else None, redoc_url=None, openapi_url="/api/openapi.json" if s.env != "production" else None)
    app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in s.cors_origins.split(",") if o.strip()], allow_credentials=False,
                       allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "X-API-Key"])

    @app.middleware("http")
    async def guard(request: Request, call_next):
        s = get_settings()
        path = request.url.path
        client = request.client.host if request.client else "unknown"
        if path.startswith("/api") and request.method != "OPTIONS":
            now = time.monotonic()
            q = _hits[client]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= s.rate_limit_per_minute:
                return JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": "30"})
            q.append(now)
            if s.api_key and path != "/api/health":
                supplied = request.headers.get("x-api-key", "")
                if not hmac.compare_digest(supplied.encode(), s.api_key.encode()):
                    return JSONResponse({"detail": "invalid or missing API key"}, status_code=401)
            cl = request.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > s.max_upload_bytes + 64 * 1024:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    app.include_router(router, prefix="/api")
    return app


app = create_app()
