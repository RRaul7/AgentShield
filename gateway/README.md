# AgentShield Gateway — Developer Notes

This folder contains the **Phase 1 Python/FastAPI security gateway**. Refer to the [root README](../README.md) for setup, configuration, endpoint examples, supported features, and security limitations.

## Modules

- `main.py` — API endpoints, input validation, request metadata and audit logging.
- `config.py` — environment-variable-based configuration.
- `detectors.py` — pattern-based PII and secret detection, plus validation helpers.
- `vault.py` — encrypted token storage, token resolution and request-scoped restoration.
- `injection.py` — heuristic prompt-injection screening.
- `pipeline.py` — input and output scanning, redaction and restoration.
- `router.py` — mock provider, OpenAI and Anthropic adapters.

## Local API

`POST /v1/chat/completions` uses an OpenAI-style non-streaming JSON shape. Supported message contents are plain-text strings. Use `"model": "mock"` to test without external credentials. `GET /health`, `GET /admin/events` and `GET /admin/vault/stats` support local diagnostics. `GET /dashboard` serves the prototype HTML when the repository layout is preserved.

## Threat-model highlights

- Redaction happens before provider routing, and only placeholders generated in the current request may be restored into its output.
- Gateway auth is **optional by default for local demonstration**, not an enterprise access-control implementation.
- Injection detection and PII recognition are best-effort heuristics, **not a complete DLP or prompt-injection defense**.
- If a provider is not configured, non-mock requests fail with an upstream error.
- The API rejects streaming and multimodal requests rather than silently modifying their shape.
- Authenticated deployments need a separate admin security model: an ordinary gateway Bearer token is not a sufficient RBAC boundary for SOC telemetry.

To run the tests: `python -m pytest -q` from this directory.
