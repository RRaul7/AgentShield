"""
AgentShield — Token Vault (Reversible Redaction).

OWASP LLM06 müdafiəsi:
  * Aşkarlanmış həssas dəyər deterministik tokenlə əvəzlənir: [EMAIL_1], [API_KEY_2]…
  * Real dəyər AES-256-GCM ilə şifrələnib lokal SQLite vault-da saxlanır.
  * LLM cavabı qayıdanda tokenlər avtomatik real dəyərlərlə əvəz olunur.
  * LLM provayderi real datanı HEÇ VAXT görmür.

Açar idarəçiliyi:
  * AGENTSHIELD_VAULT_KEY (base64, 32 bayt) verilə bilər;
  * verilməsə, açar faylı (chmod 600) avtomatik yaradılır.
  * Dedup üçün plaintext-in HMAC-SHA256 dəyəri saxlanır (rainbow-safe) —
    eyni dəyər həmişə eyni tokeni alır.
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import os
import re
import sqlite3
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TOKEN_RE = re.compile(r"\[(EMAIL|PHONE|IBAN|CARD|FIN|API_KEY|JWT|PRIVATE_KEY|SECRET)_(\d+)\]")


class TokenVault:
    def __init__(self, db_path: str, key_file: str, key_b64: str = ""):
        self._lock = threading.Lock()
        self._key = self._load_or_create_key(key_file, key_b64)
        self._aes = AESGCM(self._key)
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS vault(
                   token      TEXT PRIMARY KEY,
                   type       TEXT NOT NULL,
                   hmac       TEXT NOT NULL,
                   nonce      BLOB NOT NULL,
                   ciphertext BLOB NOT NULL,
                   created_at REAL NOT NULL
               )"""
        )
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_vault_hmac ON vault(hmac)")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS counters(
                   type TEXT PRIMARY KEY,
                   n    INTEGER NOT NULL
               )"""
        )
        self._db.commit()

    # ------------------------------------------------------------------ key
    @staticmethod
    def _load_or_create_key(key_file: str, key_b64: str) -> bytes:
        if key_b64:
            key = base64.b64decode(key_b64)
            if len(key) != 32:
                raise ValueError("AGENTSHIELD_VAULT_KEY 32 bayt (base64) olmalıdır")
            return key
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return base64.b64decode(f.read().strip())
        key = AESGCM.generate_key(bit_length=256)  # 32 bayt
        with open(key_file, "wb") as f:
            f.write(base64.b64encode(key))
        os.chmod(key_file, 0o600)
        return key

    # -------------------------------------------------------------- helpers
    def _hmac(self, value: str) -> str:
        return hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()

    def _next_counter(self, type_: str) -> int:
        cur = self._db.execute("SELECT n FROM counters WHERE type=?", (type_,))
        row = cur.fetchone()
        n = (row[0] if row else 0) + 1
        self._db.execute(
            "INSERT INTO counters(type,n) VALUES(?,?) "
            "ON CONFLICT(type) DO UPDATE SET n=excluded.n",
            (type_, n),
        )
        return n

    # ------------------------------------------------------------ public API
    def tokenize(self, value: str, type_: str) -> str:
        """Dəyəri şifrələyib saxla, deterministik token qaytar."""
        with self._lock:
            h = self._hmac(value)
            cur = self._db.execute(
                "SELECT token FROM vault WHERE hmac=? AND type=?", (h, type_)
            )
            row = cur.fetchone()
            if row:
                return row[0]

            n = self._next_counter(type_)
            token = f"[{type_}_{n}]"
            nonce = os.urandom(12)
            ct = self._aes.encrypt(nonce, value.encode(), token.encode())  # AAD = token
            self._db.execute(
                "INSERT INTO vault(token,type,hmac,nonce,ciphertext,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (token, type_, h, nonce, ct, time.time()),
            )
            self._db.commit()
            return token

    def resolve(self, token: str) -> str | None:
        cur = self._db.execute(
            "SELECT nonce, ciphertext FROM vault WHERE token=?", (token,)
        )
        row = cur.fetchone()
        if not row:
            return None
        nonce, ct = row
        try:
            return self._aes.decrypt(nonce, ct, token.encode()).decode()
        except Exception:
            return None  # açar dəyişibsə / data pozulubsa

    def detokenize_text(self, text: str, allowed_tokens: set[str] | None = None) -> tuple[str, int]:
        """Mətndəki bütün [TYPE_N] tokenlərini real dəyərlərlə əvəz et."""
        count = 0

        def _sub(m: re.Match) -> str:
            nonlocal count
            # Restore only tokens issued for this request, never a foreign token.
            if allowed_tokens is not None and m.group(0) not in allowed_tokens:
                return m.group(0)
            real = self.resolve(m.group(0))
            if real is None:
                return m.group(0)
            count += 1
            return real

        return TOKEN_RE.sub(_sub, text), count

    def stats(self) -> dict:
        cur = self._db.execute("SELECT type, COUNT(*) FROM vault GROUP BY type")
        return {row[0]: row[1] for row in cur.fetchall()}
