"""
AgentShield Gateway — Faza 1 MVP (FastAPI).

OpenAI-compatible proxy:  POST /v1/chat/completions
Sorğu axını:
    Auth → Input Pipeline (Injection filter [LLM01] → Redaction+Vault [LLM06])
         → LLM Router → Output Pipeline (leak scan [LLM02] → De-tokenize)
         → Audit log

İşə salmaq:
    uvicorn agentshield.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import json
import time
import uuid
from collections import deque

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from pathlib import Path

from .config import settings, VALID_MODES
from .detectors import PIIDetector
from .injection import InjectionFilter
from .pipeline import GatewayBlocked, InputPipeline, OutputPipeline
from .router import UpstreamError, route
from .vault import TokenVault

app = FastAPI(
    title="AgentShield Gateway",
    version="0.1.0",
    description="AI Security Gateway — Faza 1 MVP (redaction, vault, injection filter)",
)

# ---------------------------------------------------------------------------
# Komponentlərin qurulması
# ---------------------------------------------------------------------------
detector = PIIDetector()
vault = TokenVault(settings.vault_db_path, settings.vault_key_file, settings.vault_key_b64)
injection_filter = InjectionFilter(settings.injection_block_threshold,
                                   settings.injection_warn_threshold)
input_pipeline = InputPipeline(detector, vault, injection_filter)
output_pipeline = OutputPipeline(detector, vault)

# ---------------------------------------------------------------------------
# Audit log — JSONL fayl + in-memory ring buffer.
# ƏSAS PRİNSİP: xam həssas dəyərlər HEÇ VAXT loga yazılmır — yalnız tiplər.
# ---------------------------------------------------------------------------
_events: deque = deque(maxlen=settings.audit_memory_size)


def audit(event: dict) -> None:
    event = {"ts": time.time(), **event}
    _events.append(event)
    try:
        with open(settings.audit_log_path, "a") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def check_auth(authorization: str | None) -> None:
    if not settings.gateway_api_keys:
        return  # dev rejimi — auth deaktivdir
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if token not in settings.gateway_api_keys:
        raise HTTPException(status_code=401, detail="Invalid AgentShield API key")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok", "service": "agentshield-gateway", "version": "0.1.0",
            "mode": settings.mode}


@app.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    authorization: str | None = Header(default=None),
    x_agentshield_mode: str | None = Header(default=None),
):
    t0 = time.perf_counter()
    check_auth(authorization)

    request_id = f"ags-{uuid.uuid4().hex[:12]}"
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")
    messages = payload.get("messages")
    if (not isinstance(messages, list) or not messages
            or any(not isinstance(m, dict) or m.get("role") not in
                   ("system", "user", "assistant", "tool") or
                   not isinstance(m.get("content", ""), str) for m in messages)):
        raise HTTPException(status_code=400,
                            detail="messages must be a non-empty list of text-only message objects")
    if payload.get("stream"):
        raise HTTPException(status_code=400,
                            detail="Streaming is not supported in this MVP")

    if x_agentshield_mode and not settings.allow_mode_override:
        raise HTTPException(status_code=403,
                            detail="Per-request mode overrides are disabled")
    mode = (x_agentshield_mode or settings.mode).lower()
    if mode not in VALID_MODES:
        raise HTTPException(status_code=400,
                            detail=f"Yanlış rejim: {mode}. Mümkün: {sorted(VALID_MODES)}")

    # -------------------- INPUT PIPELINE --------------------
    try:
        in_result = input_pipeline.process([dict(m) for m in messages], mode)
    except GatewayBlocked as b:
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        audit({
            "request_id": request_id, "event": "blocked", "reason": b.reason,
            "mode": mode, "details": b.details, "latency_ms": latency_ms,
        })
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "type": "agentshield_blocked",
                    "code": b.reason,
                    "message": "Sorğu AgentShield təhlükəsizlik siyasəti ilə bloklandı.",
                    "details": b.details,
                    "request_id": request_id,
                }
            },
            headers={"X-AgentShield-Action": "block",
                     "X-AgentShield-Reason": b.reason,
                     "X-AgentShield-Latency-Ms": str(latency_ms)},
        )

    # -------------------- LLM ROUTER --------------------
    upstream_payload = {**payload, "messages": in_result.messages, "stream": False}
    try:
        upstream_response, provider = await route(upstream_payload)
    except UpstreamError as e:
        # Do not leak upstream response bodies (they may echo sensitive prompts).
        audit({"request_id": request_id, "event": "upstream_error",
               "status": e.status})
        return JSONResponse(status_code=502, content={
            "error": {"type": "upstream_error", "status": e.status,
                      "message": "Upstream request failed", "request_id": request_id}
        })

    # -------------------- OUTPUT PIPELINE --------------------
    try:
        raw_text = upstream_response["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        raw_text = ""

    out_result = output_pipeline.process(raw_text, in_result.canary, in_result.allowed_tokens)
    try:
        upstream_response["choices"][0]["message"]["content"] = out_result.text
    except (KeyError, IndexError, TypeError):
        audit({"request_id": request_id, "event": "upstream_invalid_response"})
        return JSONResponse(status_code=502, content={"error": {
            "type": "upstream_error", "message": "Invalid upstream response",
            "request_id": request_id}})

    latency_ms = round((time.perf_counter() - t0) * 1000, 1)

    shield_meta = {
        "request_id": request_id,
        "mode": mode,
        "provider": provider,
        "input": {
            "detections": in_result.detections_summary,      # yalnız tiplər, dəyərlər yox
            "injection_score": in_result.injection.score if in_result.injection else 0.0,
            "injection_verdict": in_result.injection.verdict if in_result.injection else "allow",
            "matched_rules": [r["id"] for r in
                              (in_result.injection.matched_rules if in_result.injection else [])],
        },
        "output": {
            "detokenized": out_result.detokenized_count,
            "canary_leak": out_result.canary_leak,
            "redactions": out_result.output_redactions,
            "suspicious_urls": out_result.suspicious_urls,
        },
        "warnings": in_result.warnings,
        "gateway_latency_ms": latency_ms,
        "owasp_coverage": ["LLM01", "LLM02", "LLM06"],
    }
    upstream_response["agentshield"] = shield_meta

    audit({
        "request_id": request_id, "event": "completed", "mode": mode,
        "provider": provider,
        "input_detections": [d["type"] for d in in_result.detections_summary],
        "injection_score": shield_meta["input"]["injection_score"],
        "injection_verdict": shield_meta["input"]["injection_verdict"],
        "detokenized": out_result.detokenized_count,
        "canary_leak": out_result.canary_leak,
        "output_redactions": [r["type"] for r in out_result.output_redactions],
        "latency_ms": latency_ms,
    })

    return JSONResponse(
        content=upstream_response,
        headers={
            "X-AgentShield-Request-Id": request_id,
            "X-AgentShield-Action": "redact" if in_result.detections_summary else "pass",
            "X-AgentShield-Injection-Verdict": shield_meta["input"]["injection_verdict"],
            "X-AgentShield-Latency-Ms": str(latency_ms),
        },
    )


@app.get("/admin/events")
async def admin_events(authorization: str | None = Header(default=None), limit: int = 50):
    """Son audit hadisələri (sadə log görünüşü — Faza 1)."""
    check_auth(authorization)
    return {"events": list(_events)[-limit:]}


@app.get("/admin/vault/stats")
async def vault_stats(authorization: str | None = Header(default=None)):
    """Vault-da saxlanan tokenlərin tip üzrə sayı (dəyərlər göstərilmir)."""
    check_auth(authorization)
    return {"vault": vault.stats()}


@app.get("/dashboard", include_in_schema=False)
async def dashboard():
    """Serve the static prototype from the same origin for local demos."""
    path = Path(__file__).resolve().parents[2] / "dashboard" / "agentshield-soc-dashboard.html"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Dashboard is not installed")
    return FileResponse(path, media_type="text/html")
