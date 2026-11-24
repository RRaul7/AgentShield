"""
AgentShield — PII və Secret Detection mühərriki.

OWASP LLM06 (Sensitive Information Disclosure) qatı:
  * Regex-əsaslı detektorlar: email, telefon, IBAN (mod-97), kredit kartı (Luhn),
    Azərbaycan FIN kodu (kontekst-şüurlu).
  * Secret scanner: AWS / GitHub / OpenAI / Anthropic / Slack açarları, JWT,
    PEM private key blokları.
  * Entropy analizi: kontekst sözləri yaxınlığında yüksək-entropiyalı stringlər
    (generic secret).

Qeyd: Bütün nümunə/test dataları sintetikdir.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Nəticə strukturu
# ---------------------------------------------------------------------------
@dataclass
class Detection:
    type: str        # EMAIL, PHONE, IBAN, CARD, FIN, API_KEY, JWT, PRIVATE_KEY, SECRET
    value: str       # aşkarlanmış xam dəyər (yalnız in-memory; loglara yazılMIR)
    start: int
    end: int
    detector: str    # hansı detektor tapdı
    priority: int    # üst-üstə düşmə (overlap) həlli üçün


# ---------------------------------------------------------------------------
# Validatorlar
# ---------------------------------------------------------------------------
def luhn_valid(number: str) -> bool:
    """Kredit kartı üçün Luhn checksum yoxlaması."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def iban_valid(iban: str) -> bool:
    """IBAN mod-97 yoxlaması (ISO 13616)."""
    s = re.sub(r"\s", "", iban).upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    try:
        numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(numeric) % 97 == 1


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ---------------------------------------------------------------------------
# Regex qaydaları
# priority: kiçik rəqəm = yüksək prioritet (overlap zamanı qalib)
# ---------------------------------------------------------------------------
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"
)

_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # (detector_id, pattern, mapped_type)
    ("aws_access_key",  re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "API_KEY"),
    ("github_token",    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"), "API_KEY"),
    ("github_pat",      re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "API_KEY"),
    ("anthropic_key",   re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), "API_KEY"),
    ("openai_key",      re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b"), "API_KEY"),
    ("slack_token",     re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "API_KEY"),
    ("google_api_key",  re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "API_KEY"),
    ("jwt",             re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "JWT"),
]

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# Beynəlxalq + AZ formatları: +994 50 123 45 67, (050) 123-45-67 və s.
_PHONE_RE = re.compile(r"(?<![\w.])\+?\d[\d\s\-().]{7,17}\d(?![\w.])")

_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b")

_CARD_RE = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")

# AZ FIN: 7 simvol (rəqəm + böyük hərf qarışıq). FP azaltmaq üçün kontekst tələb olunur.
_FIN_RE = re.compile(r"\b(?=[A-Z0-9]{7}\b)(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{7}\b")
_FIN_CONTEXT = re.compile(r"(fin|şəxsiyyət|vəsiqə|vesiqe|identity|id\s*card)", re.IGNORECASE)

# Entropy scanner üçün kontekst sözləri
_SECRET_CONTEXT = re.compile(
    r"(secret|password|passwd|pwd|token|api[_\-\s]?key|credential|parol|açar|acar)",
    re.IGNORECASE,
)
_CANDIDATE_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/=_\-]{20,}\b")

_CONTEXT_WINDOW = 40  # simvol


def _has_context(text: str, start: int, ctx_re: re.Pattern) -> bool:
    lo = max(0, start - _CONTEXT_WINDOW)
    return bool(ctx_re.search(text[lo:start]))


# ---------------------------------------------------------------------------
# Əsas mühərrik
# ---------------------------------------------------------------------------
class PIIDetector:
    """Mətndə həssas məlumatları aşkarlayır və overlap-ları həll edir."""

    def scan(self, text: str) -> list[Detection]:
        found: list[Detection] = []

        # 1) PEM private key blokları (ən yüksək prioritet)
        for m in _PRIVATE_KEY_RE.finditer(text):
            found.append(Detection("PRIVATE_KEY", m.group(), m.start(), m.end(),
                                   "pem_private_key", 0))

        # 2) Məlum secret patternləri
        for det_id, pattern, mapped in _SECRET_PATTERNS:
            for m in pattern.finditer(text):
                found.append(Detection(mapped, m.group(), m.start(), m.end(), det_id, 1))

        # 3) Kredit kartı (Luhn ilə təsdiqlənmiş)
        for m in _CARD_RE.finditer(text):
            if luhn_valid(m.group()):
                found.append(Detection("CARD", m.group(), m.start(), m.end(),
                                       "credit_card_luhn", 2))

        # 4) IBAN (mod-97 ilə təsdiqlənmiş)
        for m in _IBAN_RE.finditer(text):
            if iban_valid(m.group()):
                found.append(Detection("IBAN", m.group(), m.start(), m.end(),
                                       "iban_mod97", 3))

        # 5) Email
        for m in _EMAIL_RE.finditer(text):
            found.append(Detection("EMAIL", m.group(), m.start(), m.end(), "email", 4))

        # 6) Telefon (9–15 rəqəm)
        for m in _PHONE_RE.finditer(text):
            digit_count = len(re.sub(r"\D", "", m.group()))
            if 9 <= digit_count <= 15:
                found.append(Detection("PHONE", m.group(), m.start(), m.end(),
                                       "phone", 5))

        # 7) AZ FIN — yalnız kontekst sözü yaxınlıqdadırsa
        for m in _FIN_RE.finditer(text):
            if _has_context(text, m.start(), _FIN_CONTEXT):
                found.append(Detection("FIN", m.group(), m.start(), m.end(),
                                       "az_fin_context", 6))

        # 8) Entropy-əsaslı generic secret (kontekst + entropiya > 4.0)
        for m in _CANDIDATE_TOKEN_RE.finditer(text):
            tok = m.group()
            if shannon_entropy(tok) > 4.0 and _has_context(text, m.start(), _SECRET_CONTEXT):
                found.append(Detection("SECRET", tok, m.start(), m.end(),
                                       "entropy_secret", 7))

        return self._resolve_overlaps(found)

    @staticmethod
    def _resolve_overlaps(dets: list[Detection]) -> list[Detection]:
        """Üst-üstə düşən aşkarlamalarda prioritet + uzunluğa görə qalibi seç."""
        dets = sorted(dets, key=lambda d: (d.priority, -(d.end - d.start), d.start))
        chosen: list[Detection] = []
        occupied: list[tuple[int, int]] = []
        for d in dets:
            if any(d.start < e and d.end > s for s, e in occupied):
                continue
            chosen.append(d)
            occupied.append((d.start, d.end))
        return sorted(chosen, key=lambda d: d.start)
