"""
AgentShield — Konfiqurasiya modulu.
Bütün parametrlər environment dəyişənləri ilə idarə olunur (12-factor).
"""
import os
from dataclasses import dataclass, field


def _env_list(name: str) -> list[str]:
    raw = os.getenv(name, "").strip()
    return [x.strip() for x in raw.split(",") if x.strip()]


@dataclass
class Settings:
    # --- Policy rejimi: block | redact | warn | log-only ---
    # OWASP LLM06 (Sensitive Information Disclosure) üçün əsas müdafiə rejimi.
    mode: str = os.getenv("AGENTSHIELD_MODE", "redact")

    # --- Gateway auth (opsional). Boşdursa auth tələb olunmur (dev rejimi). ---
    gateway_api_keys: list[str] = field(default_factory=lambda: _env_list("AGENTSHIELD_API_KEYS"))

    # Mode overrides are unsafe for non-administrator callers: disabled by default.
    allow_mode_override: bool = os.getenv("AGENTSHIELD_ALLOW_MODE_OVERRIDE", "false").lower() == "true"

    # --- Vault ---
    vault_db_path: str = os.getenv("AGENTSHIELD_VAULT_DB", "./agentshield_vault.db")
    vault_key_file: str = os.getenv("AGENTSHIELD_VAULT_KEY_FILE", "./.agentshield_vault.key")
    # base64-encoded 32-byte açar (verilməsə, key_file-dan oxunur / yaradılır)
    vault_key_b64: str = os.getenv("AGENTSHIELD_VAULT_KEY", "")

    # --- Injection filter hədləri (OWASP LLM01) ---
    injection_block_threshold: float = float(os.getenv("AGENTSHIELD_INJ_BLOCK", "0.7"))
    injection_warn_threshold: float = float(os.getenv("AGENTSHIELD_INJ_WARN", "0.35"))

    # --- Upstream provayderlər ---
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    anthropic_base_url: str = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
    upstream_timeout: float = float(os.getenv("AGENTSHIELD_UPSTREAM_TIMEOUT", "60"))

    # --- Audit log ---
    audit_log_path: str = os.getenv("AGENTSHIELD_AUDIT_LOG", "./agentshield_audit.jsonl")
    audit_memory_size: int = int(os.getenv("AGENTSHIELD_AUDIT_MEM", "500"))


settings = Settings()

VALID_MODES = {"block", "redact", "warn", "log-only"}
