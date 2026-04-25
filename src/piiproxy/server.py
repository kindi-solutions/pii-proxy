from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from .config import Settings, load_settings
from .dashboard import render_dashboard
from .request_logger import REQUEST_DEBUG_LOG, log_request_pair
from .sanitizer import Sanitizer

logger = logging.getLogger(__name__)

settings: Settings = load_settings()
sanitizer: Sanitizer | None = None
http_client: httpx.AsyncClient | None = None

# Hop-by-hop headers that must NOT be forwarded (per RFC 7230).
# All other headers pass through to upstream.
HEADERS_TO_SKIP = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global http_client, sanitizer, settings
    settings = load_settings()
    http_client = httpx.AsyncClient(
        base_url=settings.upstream.base_url,
        timeout=httpx.Timeout(settings.upstream.timeout_seconds, connect=30.0),
    )
    if settings.sanitization.enabled:
        sanitizer = Sanitizer(settings)
        logger.info("PII sanitizer enabled with entities: %s", settings.sanitization.entities)
    else:
        logger.info("PII sanitizer disabled")
    yield
    await http_client.aclose()


app = FastAPI(title="pii-proxy", lifespan=lifespan)


def _forward_headers(request: Request) -> dict[str, str]:
    """Forward all headers to upstream, except hop-by-hop headers."""
    return {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in HEADERS_TO_SKIP
    }


async def _stream_response(upstream_response: httpx.Response) -> AsyncGenerator[bytes, None]:
    """Stream SSE chunks from upstream response."""
    async for chunk in upstream_response.aiter_bytes():
        yield chunk


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    html = render_dashboard(settings.audit.log_file, REQUEST_DEBUG_LOG)
    return HTMLResponse(content=html)


@app.post("/v1/messages", response_model=None)
async def proxy_messages(request: Request) -> StreamingResponse | JSONResponse:
    assert http_client is not None

    body = await request.json()
    is_streaming = body.get("stream", False)

    incoming_body = body

    if sanitizer is not None:
        body = sanitizer.sanitize_request(body)

    headers = _forward_headers(request)
    serialized = json.dumps(body)

    log_request_pair(incoming_body, body)

    if is_streaming:
        upstream = await http_client.send(
            http_client.build_request(
                "POST",
                "/v1/messages",
                content=serialized.encode(),
                headers=headers,
            ),
            stream=True,
        )
        return StreamingResponse(
            _stream_response(upstream),
            status_code=upstream.status_code,
            media_type="text/event-stream",
            headers={
                k: v
                for k, v in upstream.headers.items()
                if k.lower() not in ("transfer-encoding", "content-encoding", "content-length")
            },
        )
    else:
        upstream = await http_client.post(
            "/v1/messages",
            content=serialized.encode(),
            headers=headers,
        )
        return JSONResponse(
            content=upstream.json(),
            status_code=upstream.status_code,
        )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"], response_model=None)
async def catch_all(request: Request, path: str) -> StreamingResponse | JSONResponse:
    """Forward any other API requests to upstream unchanged."""
    assert http_client is not None

    headers = _forward_headers(request)
    body = await request.body()

    if request.method in ("POST", "PUT", "PATCH") and body:
        upstream = await http_client.request(
            request.method,
            f"/{path}",
            content=body,
            headers=headers,
        )
    else:
        upstream = await http_client.request(
            request.method,
            f"/{path}",
            headers=headers,
        )

    return JSONResponse(
        content=upstream.json() if upstream.headers.get("content-type", "").startswith("application/json") else {"raw": upstream.text},
        status_code=upstream.status_code,
    )
