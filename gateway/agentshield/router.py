"""
AgentShield — Multi-LLM Router.

Bir endpoint → istənilən provayder:
  * model "gpt-*" / "o*"     → OpenAI Chat Completions
  * model "claude-*"         → Anthropic Messages API (format konversiyası ilə)
  * model "mock*" və ya heç bir API açarı yoxdursa → lokal Mock provayder
    (açarsız end-to-end test üçün: redaction + vault round-trip yoxlanır).

Qeyd (Faza 1): streaming dəstəklənmir — stream=true gələrsə non-stream işlənir.
"""
from __future__ import annotations

import time
import uuid

import httpx

from .config import settings


class UpstreamError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"upstream {status}")
        self.status = status
        self.body = body


def _mock_response(model: str, messages: list[dict]) -> dict:
    """Açarsız test provayderi — son user mesajını (maskalanmış halda) əks etdirir."""
    last_user = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            c = m.get("content", "")
            last_user = c if isinstance(c, str) else str(c)
            break
    text = (
        "🧪 MOCK provayder cavabı (upstream açarı tələb olunmur).\n\n"
        "Gateway-dən mənə çatan (maskalanmış) mesaj bu idi:\n"
        f"«{last_user}»\n\n"
        "Bu tokenləri olduğu kimi geri qaytarıram — AgentShield output pipeline-ı "
        "onları vault-dan real dəyərlərlə əvəz etməlidir."
    )
    return {
        "id": f"chatcmpl-mock-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model or "agentshield-mock",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


async def _call_openai(payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=settings.upstream_timeout) as client:
        r = await client.post(
            f"{settings.openai_base_url}/chat/completions",
            headers={"Authorization": f"Bearer {settings.openai_api_key}"},
            json=payload,
        )
    if r.status_code != 200:
        raise UpstreamError(r.status_code, r.text[:500])
    return r.json()


async def _call_anthropic(payload: dict) -> dict:
    """OpenAI formatını Anthropic Messages API-yə çevir və cavabı geri konvertasiya et."""
    messages = payload.get("messages", [])
    system_parts = [m["content"] for m in messages
                    if m.get("role") == "system" and isinstance(m.get("content"), str)]
    conv = [m for m in messages if m.get("role") in ("user", "assistant")]

    body = {
        "model": payload.get("model"),
        "max_tokens": payload.get("max_tokens") or 1024,
        "messages": conv,
    }
    if system_parts:
        body["system"] = "\n".join(system_parts)
    if payload.get("temperature") is not None:
        body["temperature"] = payload["temperature"]

    async with httpx.AsyncClient(timeout=settings.upstream_timeout) as client:
        r = await client.post(
            f"{settings.anthropic_base_url}/v1/messages",
            headers={
                "x-api-key": settings.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=body,
        )
    if r.status_code != 200:
        raise UpstreamError(r.status_code, r.text[:500])
    data = r.json()

    text = "".join(b.get("text", "") for b in data.get("content", [])
                   if b.get("type") == "text")
    usage = data.get("usage", {})
    return {
        "id": data.get("id", f"chatcmpl-{uuid.uuid4().hex[:12]}"),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": data.get("model", payload.get("model")),
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": data.get("stop_reason", "stop"),
        }],
        "usage": {
            "prompt_tokens": usage.get("input_tokens", 0),
            "completion_tokens": usage.get("output_tokens", 0),
            "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
        },
    }


async def route(payload: dict) -> tuple[dict, str]:
    """Payload-u uyğun provayderə yönləndir. (cavab, provayder_adı) qaytarır."""
    model = (payload.get("model") or "").lower()

    if model.startswith("mock") or model == "":
        return _mock_response(payload.get("model", ""), payload.get("messages", [])), "mock"

    if model.startswith("claude"):
        if not settings.anthropic_api_key:
            raise UpstreamError(503, "Anthropic provider is not configured")
        return await _call_anthropic(payload), "anthropic"

    if not settings.openai_api_key:
        raise UpstreamError(503, "OpenAI provider is not configured")
    return await _call_openai(payload), "openai"
