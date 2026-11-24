# Integration and Source Review

The public preview was assembled from the files provided by the project contributors.

| Input | Handling | Reason |
|---|---|---|
| `agentshield-mvp.zip` | Included under `gateway/` | Self-contained Python Phase 1 MVP |
| `agentshield-soc-dashboard.html` | Included under `dashboard/` | Frontend demo, adapted for non-fabricated Live identities |
| `files.zip` | Not included | Four partial replacements for a different MITM proxy app; the rest of its source is missing |
| `files1.zip` | Not included | Temporary `/test` raw prompt capture, unauthenticated and unsafe for a public/deployed app |
| AloFarm product prompt | Not included | Different project |

## Review notes

**Critical protections absent in the MITM patches:** Several original settings were insecure for a production environment, including a known admin password, broad admin listening interface, insecure upstream TLS verification and fail-open error handling. The partial patch set cannot be integrated responsibly until the complete application and tests are available.

**Gateway limitations:** Local-only development auth defaults, shared vault persistence, incomplete detection coverage, CDN dashboard scripts, no full tenant isolation, and no official compliance certification. The output placeholder restoration has been narrowed to the current request; upstream error bodies are not forwarded or logged; per-request policy override is disabled by default.

**Security boundaries:** The dashboard's synthetic departments and users apply only to Demo mode; Live data without trusted identity is labeled **Unassigned / unknown**, not assigned a fabricated employee identity.
