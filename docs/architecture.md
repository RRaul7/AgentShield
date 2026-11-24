# Architecture — Current MVP

```text
Text-only API client
      |
      v
FastAPI /v1/chat/completions
  |-- optional gateway Bearer key check (local demo only)
  |-- input heuristic prompt-injection screen
  |-- PII / secret scan + block, redact, warn or log-only policy
  |-- AES-GCM token vault (SQLite; current-request restoration allowlist)
  |-- provider router: mock / OpenAI / Anthropic
  |-- output scan, canary check and token restoration
  `-- metadata-only audit ring buffer and JSONL log
      |
      +-- GET /admin/events --------> HTML SOC dashboard (polling)
      +-- GET /admin/vault/stats
```

### Current limitations

The gateway is a direct API proxy, **not** a transparent network interception proxy and not a browser extension. It does not intercept ChatGPT, Gemini, Grok or Claude web traffic. The SOC dashboard is a prototype, not a multi-tenant role-based security console. Real user and departmental identity must come from trusted enterprise authentication, not synthetic demo data.

### Data handling

PII/secret values are replaced with placeholders prior to routing in `redact` mode and kept encrypted in a local SQLite vault. Placeholders are resolved only when they belong to the same processed request. The vault has no retention policy, tenant separation, hardware-backed key management or enterprise disaster-recovery design. Metadata-only audit events include detection categories, verdicts and timing, not raw prompts by design.

### Future design decisions

The upcoming MITM interception prototype requires independent testing of host detection, TLS trust, correct payload parsing and fail-closed behavior. The partial patches supplied so far are not integrated into this FastAPI MVP. Browser compatibility, authenticated SOC access and organizational audit trust boundaries remain open engineering work.
