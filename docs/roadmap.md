# Development Roadmap

## Phase 1 — Published public MVP

- [x] OpenAI-compatible text-only FastAPI endpoint, mock/OpenAI/Anthropic routing
- [x] Pattern-based PII detection, token vault, request-scoped restoration
- [x] Heuristic injection screening, output inspection and audit metadata
- [x] Dashboard demo and basic event polling
- [x] Python tests and GitHub Actions CI

## Phase 2 — Reliability and access control

- [ ] Production-grade identity, RBAC and organization/tenant isolation
- [ ] Enforced policy administration and protected administrative endpoints
- [ ] Authenticated dashboard Live mode, trustworthy user/department metadata
- [ ] Vault lifecycle management, audit retention and key rotation
- [ ] Structured model API compatibility and stronger validation
- [ ] Explicit error budgets, observability and end-to-end security testing

## Phase 3 — Other access paths and integrations

- [ ] Integrate the full independently tested mitmproxy application, if supplied
- [ ] Support provider-specific payloads without corrupting web app requests
- [ ] Enterprise connectors / SIEM export and policy engine
- [ ] Browser extension with opt-in local inspection
- [ ] ML-based threat classification, controlled evaluation datasets

All items are planned engineering tasks, not claims of compliance or security certification.
