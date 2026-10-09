"""SecureLink FastAPI application: API + the built React frontend on one HTTPS origin."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from . import config
from .db import connect, init_db
from .routes import admin, auth, files, messages, sessions
from .security.netguard import netguard_middleware


@asynccontextmanager
async def lifespan(app):
    init_db()
    yield


app = FastAPI(title="SecureLink", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.middleware("http")(netguard_middleware)

for module in (auth, sessions, messages, files, admin):
    app.include_router(module.router)


@app.get("/health")
def health():
    """Health check (SR-05): confirms the database answers."""
    conn = connect()
    try:
        conn.execute("SELECT 1").fetchone()
        return {"status": "ok", "tls": config.TLS_ENABLED}
    finally:
        conn.close()


if config.FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=config.FRONTEND_DIST, html=True), name="frontend")
else:
    @app.get("/", response_class=HTMLResponse)
    def frontend_missing():
        return "<h1>SecureLink API is running</h1><p>Build the frontend: <code>cd frontend && npm run build</code></p>"
