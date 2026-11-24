# AgentShield 🛡️

**An experimental AI Security Gateway with a SOC dashboard prototype.**

AgentShield is a proof-of-concept security layer between an application and an LLM provider. It demonstrates detection of selected personally identifiable information (PII), redaction with encrypted token storage, heuristic prompt-injection filtering, and privacy-conscious event metadata for security dashboards.

> **Status: early MVP / research prototype.** Not audited, not production-ready, and not a guarantee against data leakage or prompt injection. Do not route sensitive or regulated production traffic through this code.

## What works today

| Component | Capabilities | Status |
|---|---|---|
| FastAPI gateway | OpenAI-style `/v1/chat/completions`, mock provider, OpenAI and Anthropic adapters | MVP |
| PII and secret detection | Email, phone, payment-card Luhn, IBAN checks, Azerbaijan FIN in context, common key patterns | Heuristic |
| Redaction / token vault | AES-256-GCM encryption in local SQLite; request-scoped output restoration | MVP |
| Injection detector | Pattern-based AZ/EN checks, limited text normalization and encoded-input inspection | Heuristic |
| Output checks | Canary marker detection, selected high-risk secrets, suspicious URL indicators | MVP |
| SOC console | Synthetic live-looking demo, optional polling of `/admin/events` | Prototype |
| Unit tests | Detection, tokenization, filters, and selected gateway behavior | Included |

**Not implemented:** authentication/SSO for the dashboard, enterprise RBAC, real employee attribution, browser extension, transparent HTTPS/TLS interception, full agent tool-call control, compliance certification, streaming responses, ML-based semantic detection, deployment hardening, or a complete commercial SaaS product.

## Repository layout

```text
AgentShield/
├── gateway/
│   ├── agentshield/            # FastAPI service and security modules
│   ├── tests/                  # Python automated tests
│   ├── requirements.txt
│   └── test_client.py          # Local mock scenarios
├── dashboard/
│   └── agentshield-soc-dashboard.html
├── docs/
│   ├── architecture.md
│   ├── integration-notes.md
│   └── roadmap.md
├── .github/workflows/ci.yml
├── .env.example
├── .gitignore
└── README.md
```

## Quick start (local development)

Requires Python **3.11+**. The dashboard loads React, Tailwind, Babel, and fonts from external CDNs; an internet connection is needed for that page.

```bash
git clone https://github.com/RRaul7/AgentShield.git
cd AgentShield/gateway
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS / Linux: source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
uvicorn agentshield.main:app --host 127.0.0.1 --port 8000
```

In another terminal, test the mock provider:

```bash
curl -X POST http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"mock","messages":[{"role":"user","content":"My email is demo@example.com"}]}'
```

Open **http://127.0.0.1:8000/dashboard** to view the SOC console. Use **Demo** for synthetic events or select **Live** to poll real audit metadata (without real employee/department mapping). Interactive API documentation: **http://127.0.0.1:8000/docs**.

The gateway's audit event endpoint is `GET /admin/events`; the vault statistics endpoint is `GET /admin/vault/stats`. The demo uses metadata, not original prompts.

## Configuration

See [`.env.example`](.env.example). Settings are read from environment variables (this project does **not** automatically load `.env`). Set environment variables in your shell or use a development-only environment loader.

| Variable | Default | Purpose |
|---|---|---|
| `AGENTSHIELD_MODE` | `redact` | `block`, `redact`, `warn`, or `log-only` |
| `AGENTSHIELD_API_KEYS` | Empty | Comma-separated gateway Bearer tokens; **required for any non-local deployment** |
| `AGENTSHIELD_ALLOW_MODE_OVERRIDE` | `false` | Enable per-request `X-AgentShield-Mode` override (unsafe for untrusted callers) |
| `AGENTSHIELD_VAULT_DB` | `./agentshield_vault.db` | Local encrypted-value database |
| `AGENTSHIELD_VAULT_KEY` | Empty | Base64-encoded 32-byte key; otherwise a local key file is generated |
| `AGENTSHIELD_VAULT_KEY_FILE` | `./.agentshield_vault.key` | Path to locally generated key |
| `AGENTSHIELD_AUDIT_LOG` | `./agentshield_audit.jsonl` | Metadata-only audit file |
| `OPENAI_API_KEY` | Empty | Optional OpenAI provider access; do not commit |
| `ANTHROPIC_API_KEY` | Empty | Optional Anthropic provider access; do not commit |

**Only `model: "mock"` works without provider credentials.** Explicit real-provider model requests fail when provider credentials are missing, rather than pretending to be actual model responses. Streaming (`stream: true`) and multimodal message content are rejected; this MVP supports text-only, non-streaming requests.

The gateway has optional Bearer auth for local demonstrations only; it is not a full authentication/authorization system. The dashboard Live mode does not currently support adding protected API credentials.

## Security boundaries and known limitations

1. **Never expose this service directly to the public internet.** Use loopback (`127.0.0.1`) for testing. Production needs TLS, authentication, authorization, hardened persistence, access controls, key management, and deployment review.
2. **Token restoration is limited to placeholders created by the current request**, reducing accidental cross-request disclosure. Token records are still in a shared local store; this is not full tenant isolation or lifecycle management.
3. **Detection is not complete.** Regex and heuristic methods have false positives and false negatives. New tokens, languages, image attachments and encoded formats may evade detection. The gateway does not automatically protect traffic to the ChatGPT/Gemini/Claude websites.
4. **`warn` and `log-only` send sensitive data upstream without masking.** They are for controlled testing, never default enforcement.
5. **Canary markers are not comprehensive prompt-leak prevention.** Output inspection may miss leaks; suspicious URL flags are informational.
6. **Audit content is metadata-only by design**, but upstream systems and local filesystem permissions remain separate security considerations. Review retention before handling real data.
7. The HTML dashboard uses **CDN-hosted client scripts** and is **not hardened as an authenticated SOC portal**. Never treat demo identity data as factual organizational telemetry.

The supplied separate MITM proxy patch files and the unauthenticated raw-prompt capture `/test` endpoint are deliberately **excluded**. See [integration notes](docs/integration-notes.md) for why.

## Testing

```bash
cd gateway
python -m pytest -q
```

Use `python test_client.py` with the gateway running for optional local scenarios. To enable the test client's request-mode override scenario, set `AGENTSHIELD_ALLOW_MODE_OVERRIDE=true` **only in an isolated local environment**.

## Roadmap

See [docs/roadmap.md](docs/roadmap.md). Planned work is not presented as implemented functionality.

## License

No license has been selected. All rights remain with the respective copyright holders unless a license is added by the project owner.
