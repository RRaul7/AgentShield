"""
AgentShield — Heuristik Prompt Injection / Jailbreak filtri.

OWASP LLM01 (Prompt Injection) müdafiə qatı — Faza 1 (heuristik):
  * Normalizasiya: lowercase, zero-width simvollərin silinməsi, leet-speak decode.
  * Obfuskasiya: base64 blokları decode edilib təkrar skan olunur (dərinlik 1).
  * Çəkili qayda dəsti → 0..1 arası risk skoru.
  * Verdikt: allow / warn / block (konfiqurasiya edilə bilən hədlərlə).

Qeyd: Bu modul YALNIZ müdafiə məqsədli detection patternləri saxlayır —
hücum payload-u generasiya etmir.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Normalizasiya
# ---------------------------------------------------------------------------
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
_LEET_MAP = str.maketrans({"1": "i", "0": "o", "3": "e", "4": "a",
                           "5": "s", "7": "t", "@": "a", "$": "s"})


def normalize(text: str) -> str:
    t = text.translate(_ZERO_WIDTH).lower()
    t = re.sub(r"\s+", " ", t)
    return t


def leet_normalize(text: str) -> str:
    return text.translate(_LEET_MAP)


_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def decode_base64_blobs(text: str) -> list[str]:
    """Base64-ə oxşayan blokları decode et; oxuna bilən mətn qaytarsa, siyahıya al."""
    decoded: list[str] = []
    for m in _B64_RE.finditer(text):
        try:
            raw = base64.b64decode(m.group(), validate=True)
            s = raw.decode("utf-8", errors="strict")
        except Exception:
            continue
        if s and sum(ch.isprintable() for ch in s) / len(s) > 0.9:
            decoded.append(s)
    return decoded


# ---------------------------------------------------------------------------
# Qayda dəsti  (id, regex, çəki, təsvir)
# ---------------------------------------------------------------------------
@dataclass
class Rule:
    id: str
    pattern: re.Pattern
    weight: float
    description: str


def _r(id_: str, pat: str, w: float, desc: str) -> Rule:
    return Rule(id_, re.compile(pat, re.IGNORECASE), w, desc)


RULES: list[Rule] = [
    # --- Təlimat override cəhdləri ---
    _r("override_instructions",
       r"\b(ignore|disregard|forget|skip|bypass)\b.{0,40}\b(previous|prior|above|all|any|earlier|original)\b.{0,30}\b(instruction|rule|prompt|direction|guideline)s?\b",
       0.6, "Əvvəlki təlimatları ləğv etmə cəhdi"),
    _r("override_az",
       r"(əvvəlki|bütün)\s+(təlimat|qayda)ları?\s+(unut|iqnor|ləğv)",
       0.6, "AZ dilində təlimat override"),
    _r("new_instructions",
       r"\b(new|updated|real|actual)\s+(instructions?|rules?|system\s*prompt)\s*[:\-]",
       0.45, "Yeni təlimat inyeksiyası"),

    # --- System prompt sızdırma cəhdləri ---
    _r("prompt_leak",
       r"\b(reveal|show|print|repeat|output|display|tell me)\b.{0,40}\b(system\s*prompt|initial\s*instructions?|hidden\s*(rules|instructions)|your\s+instructions)\b",
       0.6, "System prompt sızdırma cəhdi"),
    _r("prompt_leak_az",
       r"(sistem\s*prompt|gizli\s*təlimat)\w*\s*(göstər|de|yaz|çap)",
       0.6, "AZ dilində system prompt sızdırma"),

    # --- Rol / persona jailbreak ---
    _r("role_override",
       r"\byou\s+are\s+now\b|\bfrom\s+now\s+on\s+you\b|\bpretend\s+(to\s+be|you\s+are)\b",
       0.35, "Rol override / persona dəyişmə"),
    _r("jailbreak_persona",
       r"\b(dan\s*mode|do\s+anything\s+now|developer\s+mode|jailbreak|evil\s*(ai|assistant)|no\s+(restrictions?|filters?|guardrails?)|without\s+(any\s+)?(restrictions?|limitations?|filters?))\b",
       0.55, "Məşhur jailbreak persona işarələri"),
    _r("disable_safety",
       r"\b(disable|turn\s*off|remove|override)\b.{0,30}\b(safety|guardrails?|filters?|moderation|restrictions?)\b",
       0.55, "Təhlükəsizlik mexanizmini söndürmə cəhdi"),

    # --- Struktur / tag smuggling (indirect injection üçün də kritik) ---
    _r("tag_smuggling",
       r"</?\s*(system|assistant)\s*>|<\|im_start\|>|<\|im_end\|>|\[/?INST\]|\[/?SYS\]",
       0.5, "Chat-format tag smuggling"),
    _r("fake_authority",
       r"\b(admin|root|sudo|developer)\s*(override|access|command)\b|\bBEGIN\s+ADMIN\b",
       0.4, "Saxta səlahiyyət iddiası"),

    # --- Data eksfiltrasiya təlimatları (RAG/indirect üçün) ---
    _r("exfil_instruction",
       r"\b(send|post|forward|upload|exfiltrate)\b.{0,40}\b(conversation|chat|data|credentials?|secrets?|keys?)\b.{0,40}\b(to|at)\s+https?://",
       0.7, "Data eksfiltrasiya təlimatı"),
    _r("hidden_instruction_marker",
       r"\b(ai\s+assistant|language\s+model|llm)\s*[,:]?\s*(please\s+)?(ignore|execute|follow)\b",
       0.4, "Sənəd içində gizli AI təlimatı (indirect injection)"),
]


# ---------------------------------------------------------------------------
# Nəticə
# ---------------------------------------------------------------------------
@dataclass
class InjectionVerdict:
    score: float                 # 0..1
    verdict: str                 # allow | warn | block
    matched_rules: list[dict] = field(default_factory=list)
    decoded_layers: int = 0      # neçə base64 qatı açılıb skan edildi


class InjectionFilter:
    def __init__(self, block_threshold: float = 0.7, warn_threshold: float = 0.35):
        self.block_threshold = block_threshold
        self.warn_threshold = warn_threshold

    def _scan_variant(self, text: str) -> tuple[float, list[dict]]:
        score = 0.0
        matched: list[dict] = []
        for rule in RULES:
            if rule.pattern.search(text):
                score += rule.weight
                matched.append({"id": rule.id, "weight": rule.weight,
                                "description": rule.description})
        return score, matched

    def scan(self, text: str) -> InjectionVerdict:
        variants = [normalize(text)]
        variants.append(leet_normalize(variants[0]))

        decoded = decode_base64_blobs(text)
        for d in decoded:
            variants.append(normalize(d))

        total = 0.0
        seen_ids: set[str] = set()
        matched: list[dict] = []
        for v in variants:
            s, m = self._scan_variant(v)
            for item in m:
                if item["id"] not in seen_ids:
                    seen_ids.add(item["id"])
                    matched.append(item)
                    total += item["weight"]

        # Base64 içində injection tapılıbsa — obfuskasiya bonusu
        if decoded and matched:
            total += 0.2
            matched.append({"id": "obfuscation_base64", "weight": 0.2,
                            "description": "Base64 obfuskasiyası altında injection"})

        score = min(1.0, total)
        if score >= self.block_threshold:
            verdict = "block"
        elif score >= self.warn_threshold:
            verdict = "warn"
        else:
            verdict = "allow"
        return InjectionVerdict(score=round(score, 3), verdict=verdict,
                                matched_rules=matched, decoded_layers=len(decoded))
