"""FastAPI application and public error handling."""

import json
import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .analysis import analyze
from .models import AnalyzeRequest

MAX_BODY_BYTES = 256 * 1024
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("conduitguard")
app = FastAPI(
    title="ConduitGuard API",
    version="1.0.0",
    description="Offline firewall policy validation and connectivity simulation.",
)


class BodyLimitMiddleware:
    """Pure ASGI limiter; buffers at most MAX_BODY_BYTES before app validation."""

    def __init__(self, application: Any):
        self.application = application

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.application(scope, receive, send)
            return
        length = next(
            (value.decode() for key, value in scope.get("headers", []) if key.lower() == b"content-length"), ""
        )
        if length.isdigit() and int(length) > MAX_BODY_BYTES:
            response = JSONResponse(
                status_code=413,
                content={"error": {"code": "request_too_large", "message": "Request body exceeds 256 KiB."}},
            )
            await response(scope, receive, send)
            return
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                response = JSONResponse(
                    status_code=413,
                    content={"error": {"code": "request_too_large", "message": "Request body exceeds 256 KiB."}},
                )
                await response(scope, receive, send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.application(scope, replay_receive, send)


app.add_middleware(BodyLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_: Request, exc: RequestValidationError):
    details = [
        {
            "loc": list(error.get("loc", [])),
            "msg": error.get("msg", "Invalid value"),
            "type": error.get("type", "validation_error"),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "Request does not match the API schema.",
                "details": details,
            }
        },
    )


@app.exception_handler(Exception)
async def unexpected_error_handler(_: Request, exc: Exception):
    logger.exception("Unhandled request error", exc_info=exc)
    return JSONResponse(
        status_code=500, content={"error": {"code": "internal_error", "message": "The request could not be processed."}}
    )


@app.get("/api/health")
def health():
    return {"status": "ok", "rules_version": "1.0.0"}


@app.get("/api/examples/demo")
def demo_example():
    return {
        "before": {
            "default_policy": "deny",
            "rules": [
                {
                    "id": "allow-https",
                    "source": "10.20.0.0/16",
                    "destination": "192.0.2.10",
                    "protocol": "tcp",
                    "port": 443,
                    "action": "allow",
                    "priority": 100,
                    "description": "HTTPS from app subnet",
                },
                {
                    "id": "allow-dns",
                    "source": "10.20.0.0/16",
                    "destination": "192.0.2.53",
                    "protocol": "udp",
                    "port": 53,
                    "action": "allow",
                    "priority": 100,
                    "description": "DNS resolver access",
                },
            ],
        },
        "after": {
            "default_policy": "deny",
            "rules": [
                {
                    "id": "allow-https",
                    "source": "10.20.0.0/16",
                    "destination": "192.0.2.10",
                    "protocol": "tcp",
                    "port": 443,
                    "action": "allow",
                    "priority": 100,
                    "description": "HTTPS from app subnet",
                },
                {
                    "id": "allow-dns",
                    "source": "10.20.0.0/16",
                    "destination": "192.0.2.53",
                    "protocol": "udp",
                    "port": 53,
                    "action": "allow",
                    "priority": 100,
                    "description": "DNS resolver access",
                },
                {
                    "id": "allow-admin",
                    "source": "*",
                    "destination": "192.0.2.10",
                    "protocol": "tcp",
                    "port": 22,
                    "action": "allow",
                    "priority": 100,
                    "description": "Temporary admin access",
                },
            ],
        },
        "probes": [
            {
                "label": "HTTPS from application subnet",
                "source": "10.20.1.8",
                "destination": "192.0.2.10",
                "protocol": "tcp",
                "port": 443,
            },
            {
                "label": "SSH from public address",
                "source": "198.51.100.25",
                "destination": "192.0.2.10",
                "protocol": "tcp",
                "port": 22,
            },
            {
                "label": "DNS from application subnet",
                "source": "10.20.1.8",
                "destination": "192.0.2.53",
                "protocol": "udp",
                "port": 53,
            },
        ],
    }


@app.post("/api/analyze")
def analyze_configuration(payload: AnalyzeRequest):
    return analyze(payload)


@app.post("/api/validate")
async def validate_configuration(request: Request):
    try:
        raw = await request.body()
        if not raw:
            return JSONResponse(
                status_code=400,
                content={"error": {"code": "empty_input", "message": "Configuration body must not be empty."}},
            )
        parsed = json.loads(raw)
        from .models import FirewallConfig

        config = FirewallConfig.model_validate(parsed)
        return {"valid": True, "rule_count": len(config.rules)}
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=400, content={"error": {"code": "invalid_json", "message": "Request body is not valid JSON."}}
        )
    except ValidationError as exc:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Configuration does not match the schema.",
                    "details": [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()],
                }
            },
        )
