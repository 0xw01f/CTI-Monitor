"""
Noise filtering, threat classification, risk scoring, and deduplication.

Noise gate:         check_noise(title, content, actor) → {is_noise, noise_reason}
Type classifier:    classify_type(title, content)       → str
Tag extractor:      extract_tags(title, content)        → list[str]
Risk scorer:        compute_risk_score(...)             → {score, severity, reasons}
Dedup key:          build_dedup_key(title, actor)       → str
Legacy wrapper:     classify_threat(title, content)     → (type, severity, score, tags)
"""

import re
import unicodedata

# ---------------------------------------------------------------------------
# 1. NOISE FILTERING
# ---------------------------------------------------------------------------

_NOISE_KEYWORDS: list[str] = [
    "free download",
    "seed phrase",
    "combo free",
    "free combo",
    "combolist free",
    "cracked",
    "tutorial",
    "leech",
    "public data",
    "crack download",
    "nulled",
    "warez",
    "serial key",
    "keygen",
    "activation code",
    "license key",
    "free tool",
    "mega link",
    "course free",
    "udemy free",
    "free course",
    "torrent",
]

_NOISE_CATEGORY_KEYWORDS: list[str] = [
    "game hack",
    "fortnite",
    "minecraft",
    "roblox",
    "gaming account",
    "onlyfans",
    "xxx",
    "adult content",
    "rat builder",
    "malware builder free",
]

# Patterns matched against lowercased title
_JUNK_TITLE_PATTERNS: list[re.Pattern] = [
    re.compile(r"^chinese\s+data\s+(id[-_\s]?\d+|#\d+|\d+)$"),  # "Chinese data ID-1234"
    re.compile(r"^\w{1,3}\s+(data|db|combo)\s*$"),  # "XX data"
    re.compile(r"^(combo|db|data)\s+(free|public)\s*$"),
]

# Patterns matched against lowercased title (spam actor patterns)
_SPAM_TITLE_PATTERNS: list[re.Pattern] = [
    re.compile(r"chinese\s+data\s+(id|#)[-_\s]?\d+"),
    re.compile(r"free\s+\w+\s+combo"),
    re.compile(r"combo\s+list\s+free"),
]


def check_noise(title: str, content: str = "", actor: str = "") -> dict:
    """
    Returns {"is_noise": bool, "noise_reason": str | None}.
    Aggressively filters low-value content.
    """
    text = f"{title} {content}".lower()
    title_lower = title.lower().strip()

    for kw in _NOISE_KEYWORDS:
        if kw in text:
            return {"is_noise": True, "noise_reason": f"keyword: {kw}"}

    for kw in _NOISE_CATEGORY_KEYWORDS:
        if kw in text:
            return {"is_noise": True, "noise_reason": f"category: {kw}"}

    for pattern in _JUNK_TITLE_PATTERNS:
        if pattern.match(title_lower):
            return {"is_noise": True, "noise_reason": "junk title pattern"}

    for pattern in _SPAM_TITLE_PATTERNS:
        if pattern.search(title_lower):
            return {"is_noise": True, "noise_reason": "spam title pattern"}

    if len(title_lower) < 8 and not content.strip():
        return {"is_noise": True, "noise_reason": "too short / empty"}

    return {"is_noise": False, "noise_reason": None}


# ---------------------------------------------------------------------------
# 2. THREAT TYPE CLASSIFICATION
# ---------------------------------------------------------------------------

_TYPE_KEYWORDS: dict[str, list[str]] = {
    "database": [
        "database",
        "db dump",
        "sql dump",
        "mysql",
        "mongodb",
        "postgres",
        "mssql",
        "sqlite",
        "dump",
        "data breach",
        "leaked database",
        "database leak",
        "db leak",
        "records leaked",
        "million records",
        "thousand records",
        "rows leaked",
    ],
    "access": [
        "rdp",
        "ssh access",
        "vpn access",
        "admin panel",
        "root access",
        "webshell",
        "shell access",
        "cpanel",
        "admin access",
        "full access",
        "backdoor access",
        "remote access",
        "initial access",
    ],
    "credentials": [
        "combo",
        "combolist",
        "email:pass",
        "user:pass",
        "login credentials",
        "password list",
        "username password",
        "login dump",
        "account credentials",
        "email password",
        "credential dump",
    ],
    "stealer_logs": [
        "stealer log",
        "stealer logs",
        "infostealer",
        "redline log",
        "raccoon log",
        "vidar log",
        "lumma log",
        "stealc log",
        "logs stealer",
        "cookies stealer",
        "browser logs",
        "stealer",
    ],
    "source_code": [
        "source code",
        "src code",
        "github leak",
        "repository leak",
        "code leak",
        "leaked source",
        "git dump",
    ],
}


def classify_type(title: str, content: str = "") -> str:
    """Returns one of: database, access, credentials, stealer_logs, source_code, other."""
    text = f"{title} {content}".lower()
    for threat_type, keywords in _TYPE_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return threat_type
    return "other"


# ---------------------------------------------------------------------------
# 3. TAG EXTRACTION
# ---------------------------------------------------------------------------

_TAGS_KEYWORDS: dict[str, list[str]] = {
    "database": ["database", "db", "sql", "mysql", "mongodb", "postgres", "mssql"],
    "combo": ["combo", "combolist", "wordlist"],
    "access": ["rdp", "ssh", "vpn", "shell", "admin", "webshell"],
    "ransomware": ["ransomware", "encrypt", "locker", "double extortion"],
    "credentials": ["credentials", "login", "password", "username", "user:pass", "email:pass"],
    "government": ["government", "gov", "ministry", "police", "military", "army"],
    "healthcare": ["hospital", "health", "medical", "clinic", "pharma", "patient"],
    "finance": ["bank", "financial", "credit", "payment", "swift", "insurance"],
    "education": ["university", "school", "college", ".edu"],
    "stealer": ["stealer", "infostealer", "redline", "raccoon", "vidar"],
    "source_code": ["source code", "github", "repository", "git"],
    "fresh": ["fresh", "2024", "2025", "2026", "new breach", "latest"],
}


def extract_tags(title: str, content: str = "") -> list[str]:
    text = f"{title} {content}".lower()
    return [tag for tag, keywords in _TAGS_KEYWORDS.items() if any(k in text for k in keywords)]


# ---------------------------------------------------------------------------
# 4. RISK SCORING
# ---------------------------------------------------------------------------

_SECTOR_KEYWORDS: dict[str, list[str]] = {
    "government": ["government", "gov", "ministry", "police", "military", "army", "national", "federal"],
    "finance": ["bank", "financial", "credit", "payment", "swift", "insurance", "stock", "nasdaq"],
    "healthcare": ["hospital", "health", "medical", "clinic", "pharma", "patient"],
}

_VOLUME_PATTERN = re.compile(
    r"\b(\d+(?:[.,]\d+)?)\s*(k|m|b|gb|tb|million|billion|thousand)\b"
    r"|\b\d+[,\s]\d{3,}\s*(records?|rows?|entries|accounts?|users?)\b",
    re.I,
)

_STRONG_KEYWORDS = [
    "leak",
    "breach",
    "breached",
    "fresh",
    "new",
    "latest",
    "0day",
    "zero-day",
    "exploit",
    "rce",
    "critical",
    "apt",
]

_SPAM_PENALTY_PATTERN = re.compile(r"chinese\s+data\s+(id|#)[-_\s]?\d+", re.I)


def compute_risk_score(
    title: str,
    content: str,
    tags: list,
    threat_type: str,
    is_noise: bool,
) -> dict:
    """
    Returns {"score": int 0-100, "severity": str, "reasons": list[str]}.

    Scoring:
      +30  database leak
      +25  large volume indicator
      +20  sensitive sector (gov / finance / healthcare)
      +15  strong keyword (leak / breach / fresh / 0day …)
      -40  noise keyword matched
      -30  spam actor pattern
    """
    score = 0
    reasons: list[str] = []
    text = f"{title} {content}".lower()

    # --- Penalties ---
    if is_noise:
        score -= 40
        reasons.append("noise")

    if _SPAM_PENALTY_PATTERN.search(title):
        score -= 30
        reasons.append("spam_pattern")

    # --- Positive signals ---
    type_bonus = {
        "database": 30,
        "source_code": 25,
        "stealer_logs": 20,
        "access": 20,
        "credentials": 15,
        "other": 0,
    }
    bonus = type_bonus.get(threat_type, 0)
    if bonus:
        score += bonus
        reasons.append(threat_type)

    if _VOLUME_PATTERN.search(text):
        score += 25
        reasons.append("large_volume")

    for sector, keywords in _SECTOR_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            score += 20
            reasons.append(f"sector:{sector}")
            break  # count sector bonus once

    for kw in _STRONG_KEYWORDS:
        if kw in text:
            score += 15
            reasons.append(f"keyword:{kw}")
            break  # count keyword bonus once

    score = max(0, min(100, score))

    if score < 30:
        severity = "low"
    elif score < 70:
        severity = "medium"
    else:
        severity = "critical"

    return {"score": score, "severity": severity, "reasons": reasons}


# ---------------------------------------------------------------------------
# 5. DEDUPLICATION KEY
# ---------------------------------------------------------------------------

_ID_PATTERN = re.compile(r"\b(id[-_\s]?\d+|#\d+|\b\d{4,}\b)", re.I)
_NON_WORD = re.compile(r"[^\w\s]")
_MULTI_SPACE = re.compile(r"\s+")


def _ascii_fold(text: str) -> str:
    """Strip diacritics: 'México' → 'Mexico', 'Üniversität' → 'Universitat'."""
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


def build_dedup_key(title: str, actor: str = "") -> str:
    """
    Normalised, actor-prefixed dedup key.
    Strips numeric IDs, punctuation, diacritics, and collapses whitespace.
    Example: "SnowSoul" + "Chinese Data ID-1234" → "snowsoul_chinese_data"
    """
    normalized = _ID_PATTERN.sub("", _ascii_fold(title).lower())
    normalized = _NON_WORD.sub(" ", normalized)
    normalized = _MULTI_SPACE.sub("_", normalized.strip())
    normalized = normalized[:60].rstrip("_")

    actor_part = re.sub(r"[^\w]", "", _ascii_fold(actor or "").lower())[:20]
    if actor_part:
        return f"{actor_part}_{normalized}"
    return normalized


# ---------------------------------------------------------------------------
# 6. FULL ENRICHMENT (single-call helper used by poller)
# ---------------------------------------------------------------------------


def enrich_post(title: str, content: str = "", actor: str = "") -> dict:
    """
    Run the full enrichment pipeline and return:
    {
        title, actor,
        is_noise, noise_reason,
        type, tags,
        risk_score, severity, score_reasons,
        dedup_key,
    }
    Country is NOT included here – use origin.detect_victim_origin() separately.
    """
    noise = check_noise(title, content, actor)
    threat_type = classify_type(title, content)
    tags = extract_tags(title, content)
    scoring = compute_risk_score(title, content, tags, threat_type, noise["is_noise"])
    dedup = build_dedup_key(title, actor)

    return {
        "title": title,
        "actor": actor,
        "is_noise": noise["is_noise"],
        "noise_reason": noise["noise_reason"],
        "type": threat_type,
        "tags": tags,
        "risk_score": scoring["score"],
        "severity": scoring["severity"],
        "score_reasons": scoring["reasons"],
        "dedup_key": dedup,
    }


# ---------------------------------------------------------------------------
# Legacy compatibility (poller still calls classify_threat directly)
# ---------------------------------------------------------------------------


def classify_threat(title: str, content: str = ""):
    """
    Legacy wrapper: returns (type, severity, score, tags).
    Noise filtering is applied; noisy posts get score=0 / severity='low'.
    """
    enriched = enrich_post(title, content)
    return (
        enriched["type"],
        enriched["severity"],
        enriched["risk_score"],
        enriched["tags"],
    )
