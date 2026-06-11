"""
Multi-signal victim origin detection.
Returns ISO-3166 alpha-2 country codes.

Signal hierarchy (highest → lowest weight):
  strong  : country names / adjectives, phone prefixes  (0.90 / 0.75)
  medium  : TLDs, city names, language hints            (0.65 / 0.60 / 0.50)
  weak    : GeoText NER                                 (0.45)

A single weak signal alone never produces a result – confidence threshold 0.40.
"""

import json
import re
from dataclasses import dataclass, field

import httpx
from geotext import GeoText

from ..config import settings

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

# Country name / alias / adjective → ISO-3166-1 alpha-2
COUNTRY_NAMES: dict[str, str] = {
    # ---- A ----
    "afghanistan": "AF",
    "afghan": "AF",
    "albania": "AL",
    "albanian": "AL",
    "algeria": "DZ",
    "algerian": "DZ",
    "angola": "AO",
    "angolan": "AO",
    "argentina": "AR",
    "argentinian": "AR",
    "argentine": "AR",
    "armenia": "AM",
    "armenian": "AM",
    "australia": "AU",
    "australian": "AU",
    "austria": "AT",
    "austrian": "AT",
    "azerbaijan": "AZ",
    "azerbaijani": "AZ",
    # ---- B ----
    "bangladesh": "BD",
    "bangladeshi": "BD",
    "belarus": "BY",
    "belarusian": "BY",
    "belgium": "BE",
    "belgian": "BE",
    "bolivia": "BO",
    "bolivian": "BO",
    "brazil": "BR",
    "brazilian": "BR",
    "bulgaria": "BG",
    "bulgarian": "BG",
    # ---- C ----
    "cambodia": "KH",
    "cambodian": "KH",
    "cameroon": "CM",
    "cameroonian": "CM",
    "canada": "CA",
    "canadian": "CA",
    "chile": "CL",
    "chilean": "CL",
    "china": "CN",
    "chinese": "CN",
    "colombia": "CO",
    "colombian": "CO",
    "croatia": "HR",
    "croatian": "HR",
    "cuba": "CU",
    "cuban": "CU",
    "czechia": "CZ",
    "czech": "CZ",
    "czech republic": "CZ",
    # ---- D ----
    "denmark": "DK",
    "danish": "DK",
    "deutschland": "DE",
    # ---- E ----
    "ecuador": "EC",
    "ecuadorian": "EC",
    "egypt": "EG",
    "egyptian": "EG",
    "england": "GB",
    "espana": "ES",
    "españa": "ES",
    "estonia": "EE",
    "estonian": "EE",
    "ethiopia": "ET",
    "ethiopian": "ET",
    # ---- F ----
    "finland": "FI",
    "finnish": "FI",
    "france": "FR",
    "french": "FR",
    # ---- G ----
    "georgia": "GE",
    "georgian": "GE",
    "germany": "DE",
    "german": "DE",
    "deutsch": "DE",
    "ghana": "GH",
    "ghanaian": "GH",
    "great britain": "GB",
    "greece": "GR",
    "greek": "GR",
    # ---- H ----
    "holland": "NL",
    "hong kong": "HK",
    "hong konger": "HK",
    "hungary": "HU",
    "hungarian": "HU",
    # ---- I ----
    "india": "IN",
    "indian": "IN",
    "indonesia": "ID",
    "indonesian": "ID",
    "iran": "IR",
    "iranian": "IR",
    "iraq": "IQ",
    "iraqi": "IQ",
    "ireland": "IE",
    "irish": "IE",
    "israel": "IL",
    "israeli": "IL",
    "italy": "IT",
    "italian": "IT",
    # ---- J ----
    "japan": "JP",
    "japanese": "JP",
    "jordan": "JO",
    "jordanian": "JO",
    # ---- K ----
    "kazakhstan": "KZ",
    "kazakh": "KZ",
    "kenya": "KE",
    "kenyan": "KE",
    "kuwait": "KW",
    "kuwaiti": "KW",
    # ---- L ----
    "latvia": "LV",
    "latvian": "LV",
    "lebanon": "LB",
    "lebanese": "LB",
    "lithuania": "LT",
    "lithuanian": "LT",
    # ---- M ----
    "malaysia": "MY",
    "malaysian": "MY",
    "mexico": "MX",
    "mexican": "MX",
    "moldova": "MD",
    "moldovan": "MD",
    "morocco": "MA",
    "moroccan": "MA",
    "myanmar": "MM",
    "burmese": "MM",
    # ---- N ----
    "netherlands": "NL",
    "dutch": "NL",
    "new zealand": "NZ",
    "new zealander": "NZ",
    "nigeria": "NG",
    "nigerian": "NG",
    "north korea": "KP",
    "north korean": "KP",
    "norway": "NO",
    "norwegian": "NO",
    # ---- P ----
    "pakistan": "PK",
    "pakistani": "PK",
    "peru": "PE",
    "peruvian": "PE",
    "philippines": "PH",
    "filipino": "PH",
    "poland": "PL",
    "polish": "PL",
    "portugal": "PT",
    "portuguese": "PT",
    # ---- Q ----
    "qatar": "QA",
    "qatari": "QA",
    # ---- R ----
    "romania": "RO",
    "romanian": "RO",
    "russia": "RU",
    "russian": "RU",
    # ---- S ----
    "saudi arabia": "SA",
    "saudi": "SA",
    "senegal": "SN",
    "senegalese": "SN",
    "serbia": "RS",
    "serbian": "RS",
    "singapore": "SG",
    "singaporean": "SG",
    "slovakia": "SK",
    "slovak": "SK",
    "south africa": "ZA",
    "south african": "ZA",
    "south korea": "KR",
    "korean": "KR",
    "south korean": "KR",
    "spain": "ES",
    "spanish": "ES",
    "sri lanka": "LK",
    "sri lankan": "LK",
    "sweden": "SE",
    "swedish": "SE",
    "switzerland": "CH",
    "swiss": "CH",
    # ---- T ----
    "taiwan": "TW",
    "taiwanese": "TW",
    "thailand": "TH",
    "thai": "TH",
    "turkey": "TR",
    "turkish": "TR",
    # ---- U ----
    "uae": "AE",
    "united arab emirates": "AE",
    "emirati": "AE",
    "uk": "GB",
    "united kingdom": "GB",
    "ukraine": "UA",
    "ukrainian": "UA",
    "uruguay": "UY",
    "uruguayan": "UY",
    "usa": "US",
    "us": "US",
    "america": "US",
    "american": "US",
    "united states": "US",
    "uzbekistan": "UZ",
    "uzbek": "UZ",
    # ---- V ----
    "venezuela": "VE",
    "venezuelan": "VE",
    "vietnam": "VN",
    "vietnamese": "VN",
}

# Phone prefix → ISO (longer prefixes first to avoid +1 matching +1x)
PHONE_PREFIXES: dict[str, str] = {
    "+850": "KP",
    "+852": "HK",
    "+853": "MO",
    "+855": "KH",
    "+856": "LA",
    "+880": "BD",
    "+886": "TW",
    "+960": "MV",
    "+961": "LB",
    "+962": "JO",
    "+963": "SY",
    "+964": "IQ",
    "+965": "KW",
    "+966": "SA",
    "+967": "YE",
    "+968": "OM",
    "+970": "PS",
    "+971": "AE",
    "+972": "IL",
    "+973": "BH",
    "+974": "QA",
    "+975": "BT",
    "+977": "NP",
    "+992": "TJ",
    "+993": "TM",
    "+994": "AZ",
    "+995": "GE",
    "+996": "KG",
    "+998": "UZ",
    "+212": "MA",
    "+213": "DZ",
    "+216": "TN",
    "+218": "LY",
    "+221": "SN",
    "+233": "GH",
    "+234": "NG",
    "+237": "CM",
    "+244": "AO",
    "+251": "ET",
    "+353": "IE",
    "+354": "IS",
    "+356": "MT",
    "+357": "CY",
    "+358": "FI",
    "+370": "LT",
    "+371": "LV",
    "+372": "EE",
    "+374": "AM",
    "+375": "BY",
    "+380": "UA",
    "+381": "RS",
    "+385": "HR",
    "+386": "SI",
    "+420": "CZ",
    "+421": "SK",
    "+27": "ZA",
    "+30": "GR",
    "+31": "NL",
    "+32": "BE",
    "+33": "FR",
    "+34": "ES",
    "+36": "HU",
    "+39": "IT",
    "+40": "RO",
    "+41": "CH",
    "+43": "AT",
    "+44": "GB",
    "+45": "DK",
    "+46": "SE",
    "+47": "NO",
    "+48": "PL",
    "+49": "DE",
    "+51": "PE",
    "+52": "MX",
    "+54": "AR",
    "+55": "BR",
    "+56": "CL",
    "+57": "CO",
    "+58": "VE",
    "+60": "MY",
    "+61": "AU",
    "+62": "ID",
    "+63": "PH",
    "+64": "NZ",
    "+65": "SG",
    "+66": "TH",
    "+7": "RU",
    "+81": "JP",
    "+82": "KR",
    "+84": "VN",
    "+86": "CN",
    "+90": "TR",
    "+91": "IN",
    "+92": "PK",
    "+93": "AF",
    "+94": "LK",
    "+95": "MM",
    "+98": "IR",
    "+1": "US",
    "+20": "EG",
}

# ccTLD → ISO
TLD_HINTS: dict[str, str] = {
    ".af": "AF",
    ".al": "AL",
    ".dz": "DZ",
    ".ao": "AO",
    ".ar": "AR",
    ".am": "AM",
    ".au": "AU",
    ".at": "AT",
    ".az": "AZ",
    ".bd": "BD",
    ".by": "BY",
    ".be": "BE",
    ".bo": "BO",
    ".br": "BR",
    ".bg": "BG",
    ".kh": "KH",
    ".cm": "CM",
    ".ca": "CA",
    ".cl": "CL",
    ".cn": "CN",
    ".co": "CO",
    ".hr": "HR",
    ".cu": "CU",
    ".cz": "CZ",
    ".dk": "DK",
    ".ec": "EC",
    ".eg": "EG",
    ".ee": "EE",
    ".et": "ET",
    ".fi": "FI",
    ".fr": "FR",
    ".ge": "GE",
    ".de": "DE",
    ".gh": "GH",
    ".gr": "GR",
    ".hk": "HK",
    ".hu": "HU",
    ".in": "IN",
    ".id": "ID",
    ".ir": "IR",
    ".iq": "IQ",
    ".ie": "IE",
    ".il": "IL",
    ".it": "IT",
    ".jp": "JP",
    ".jo": "JO",
    ".kz": "KZ",
    ".ke": "KE",
    ".kw": "KW",
    ".lv": "LV",
    ".lb": "LB",
    ".lt": "LT",
    ".my": "MY",
    ".mx": "MX",
    ".md": "MD",
    ".ma": "MA",
    ".mm": "MM",
    ".nl": "NL",
    ".nz": "NZ",
    ".ng": "NG",
    ".kp": "KP",
    ".no": "NO",
    ".pk": "PK",
    ".pe": "PE",
    ".ph": "PH",
    ".pl": "PL",
    ".pt": "PT",
    ".qa": "QA",
    ".ro": "RO",
    ".ru": "RU",
    ".sa": "SA",
    ".sn": "SN",
    ".rs": "RS",
    ".sg": "SG",
    ".sk": "SK",
    ".za": "ZA",
    ".kr": "KR",
    ".es": "ES",
    ".lk": "LK",
    ".se": "SE",
    ".ch": "CH",
    ".tw": "TW",
    ".th": "TH",
    ".tr": "TR",
    ".ua": "UA",
    ".ae": "AE",
    ".gb": "GB",
    ".uk": "GB",
    ".us": "US",
    ".uy": "UY",
    ".uz": "UZ",
    ".ve": "VE",
    ".vn": "VN",
}

# Major city → ISO
CITY_HINTS: dict[str, str] = {
    # France
    "paris": "FR",
    "marseille": "FR",
    "lyon": "FR",
    "toulouse": "FR",
    "nice": "FR",
    "bordeaux": "FR",
    "lille": "FR",
    "strasbourg": "FR",
    # Germany
    "berlin": "DE",
    "munich": "DE",
    "hamburg": "DE",
    "cologne": "DE",
    "frankfurt": "DE",
    "stuttgart": "DE",
    "dusseldorf": "DE",
    # Spain
    "madrid": "ES",
    "barcelona": "ES",
    "valencia": "ES",
    "seville": "ES",
    # Italy
    "rome": "IT",
    "milan": "IT",
    "naples": "IT",
    "turin": "IT",
    # UK
    "london": "GB",
    "manchester": "GB",
    "birmingham": "GB",
    "glasgow": "GB",
    "liverpool": "GB",
    "edinburgh": "GB",
    # USA
    "new york": "US",
    "los angeles": "US",
    "chicago": "US",
    "houston": "US",
    "san francisco": "US",
    "seattle": "US",
    "boston": "US",
    "miami": "US",
    "washington dc": "US",
    "dallas": "US",
    "atlanta": "US",
    # China
    "beijing": "CN",
    "shanghai": "CN",
    "guangzhou": "CN",
    "shenzhen": "CN",
    "chengdu": "CN",
    "hangzhou": "CN",
    "wuhan": "CN",
    "tianjin": "CN",
    # Russia
    "moscow": "RU",
    "saint petersburg": "RU",
    "st petersburg": "RU",
    "novosibirsk": "RU",
    "ekaterinburg": "RU",
    # Japan
    "tokyo": "JP",
    "osaka": "JP",
    "kyoto": "JP",
    "yokohama": "JP",
    # South Korea
    "seoul": "KR",
    "busan": "KR",
    "incheon": "KR",
    # India
    "mumbai": "IN",
    "delhi": "IN",
    "new delhi": "IN",
    "bangalore": "IN",
    "hyderabad": "IN",
    "chennai": "IN",
    "kolkata": "IN",
    # Australia
    "sydney": "AU",
    "melbourne": "AU",
    "brisbane": "AU",
    "perth": "AU",
    # Canada
    "toronto": "CA",
    "montreal": "CA",
    "vancouver": "CA",
    "ottawa": "CA",
    # Brazil
    "sao paulo": "BR",
    "rio de janeiro": "BR",
    "brasilia": "BR",
    # Netherlands
    "amsterdam": "NL",
    "rotterdam": "NL",
    "the hague": "NL",
    # Switzerland
    "zurich": "CH",
    "geneva": "CH",
    "bern": "CH",
    # Ukraine
    "kyiv": "UA",
    "kiev": "UA",
    "kharkiv": "UA",
    "odessa": "UA",
    # Turkey
    "ankara": "TR",
    "istanbul": "TR",
    "izmir": "TR",
    # Iran
    "tehran": "IR",
    "mashhad": "IR",
    # Egypt
    "cairo": "EG",
    "alexandria": "EG",
    # Morocco
    "casablanca": "MA",
    "rabat": "MA",
    # Nigeria
    "lagos": "NG",
    "abuja": "NG",
    # Pakistan
    "karachi": "PK",
    "lahore": "PK",
    "islamabad": "PK",
    # Indonesia
    "jakarta": "ID",
    "surabaya": "ID",
    # Thailand
    "bangkok": "TH",
    # Vietnam
    "ho chi minh city": "VN",
    "hanoi": "VN",
    "hcmc": "VN",
    "saigon": "VN",
    # Malaysia
    "kuala lumpur": "MY",
    # Singapore
    "singapore": "SG",
    # Taiwan
    "taipei": "TW",
    # Hong Kong
    "hong kong": "HK",
    # Saudi Arabia
    "riyadh": "SA",
    "jeddah": "SA",
    # UAE
    "dubai": "AE",
    "abu dhabi": "AE",
    # Israel
    "tel aviv": "IL",
    "jerusalem": "IL",
    # Poland
    "warsaw": "PL",
    "krakow": "PL",
    # Romania
    "bucharest": "RO",
    # Czech Republic
    "prague": "CZ",
    # Hungary
    "budapest": "HU",
    # Serbia
    "belgrade": "RS",
    # Portugal
    "lisbon": "PT",
    "porto": "PT",
    # Greece
    "athens": "GR",
    # Sweden
    "stockholm": "SE",
    "gothenburg": "SE",
    # Norway
    "oslo": "NO",
    # Denmark
    "copenhagen": "DK",
    # Finland
    "helsinki": "FI",
    # Belgium
    "brussels": "BE",
    "antwerp": "BE",
    # Austria
    "vienna": "AT",
    # Philippines
    "manila": "PH",
    # Bangladesh
    "dhaka": "BD",
    # Sri Lanka
    "colombo": "LK",
    # Myanmar
    "yangon": "MM",
    # Kazakhstan
    "almaty": "KZ",
    "astana": "KZ",
    # Peru
    "lima": "PE",
    # Colombia
    "bogota": "CO",
    # Chile
    "santiago": "CL",
    # Argentina
    "buenos aires": "AR",
    # Mexico
    "mexico city": "MX",
    "guadalajara": "MX",
    # South Africa
    "johannesburg": "ZA",
    "cape town": "ZA",
    # Iraq
    "baghdad": "IQ",
    # Lebanon
    "beirut": "LB",
}

# Language / legal entity hints → ISO (used as medium-weak signal)
# NOTE: Only include terms that are specific to ONE country.
# Terms used across multiple countries (e.g. "empresa", "s.a.") are intentionally excluded.
LANGUAGE_HINTS: dict[str, str] = {
    "siren": "FR",
    "siret": "FR",
    "societe": "FR",
    "entreprise": "FR",
    "sarl": "FR",
    "s.a.s.": "FR",
    "gmbh": "DE",
    "strasse": "DE",
    "straße": "DE",
    "bundesland": "DE",
    # "empresa", "sociedad", "s.l.", "s.a." removed — used across all Spanish-speaking countries
    "azienda": "IT",
    "s.r.l.": "IT",
    "p.iva": "IT",
    "россия": "RU",
    "москва": "RU",
    "ооо": "RU",
    "有限公司": "CN",
    "股份": "CN",
    "株式会社": "JP",
    "주식회사": "KR",
    "sp. z o.o.": "PL",
    "spółka": "PL",
    "a.ş.": "TR",
}

# GeoText full country name → ISO
_GEOTEXT_TO_ISO: dict[str, str] = {
    v: k
    for k, v in {
        "FR": "France",
        "DE": "Germany",
        "ES": "Spain",
        "IT": "Italy",
        "GB": "United Kingdom",
        "US": "United States",
        "CA": "Canada",
        "AU": "Australia",
        "BR": "Brazil",
        "IN": "India",
        "CN": "China",
        "JP": "Japan",
        "RU": "Russia",
        "KR": "South Korea",
        "MX": "Mexico",
        "TR": "Turkey",
        "ID": "Indonesia",
        "NL": "Netherlands",
        "CH": "Switzerland",
        "PL": "Poland",
        "SE": "Sweden",
        "BE": "Belgium",
        "AR": "Argentina",
        "NO": "Norway",
        "AT": "Austria",
        "AE": "United Arab Emirates",
        "SA": "Saudi Arabia",
        "ZA": "South Africa",
        "PK": "Pakistan",
        "EG": "Egypt",
        "UA": "Ukraine",
        "NG": "Nigeria",
        "MY": "Malaysia",
        "TH": "Thailand",
        "VN": "Vietnam",
        "RO": "Romania",
        "PH": "Philippines",
        "CZ": "Czech Republic",
        "IL": "Israel",
        "PT": "Portugal",
        "CO": "Colombia",
        "DK": "Denmark",
        "CL": "Chile",
        "FI": "Finland",
        "SG": "Singapore",
        "HK": "Hong Kong",
        "TW": "Taiwan",
        "IR": "Iran",
        "IQ": "Iraq",
        "MA": "Morocco",
        "KZ": "Kazakhstan",
        "BD": "Bangladesh",
        "PE": "Peru",
        "HU": "Hungary",
        "GR": "Greece",
        "SK": "Slovakia",
        "HR": "Croatia",
        "RS": "Serbia",
        "BG": "Bulgaria",
        "LT": "Lithuania",
        "LV": "Latvia",
        "EE": "Estonia",
        "BY": "Belarus",
        "GE": "Georgia",
        "AZ": "Azerbaijan",
        "AM": "Armenia",
        "UZ": "Uzbekistan",
        "LB": "Lebanon",
        "JO": "Jordan",
        "KE": "Kenya",
        "ET": "Ethiopia",
        "GH": "Ghana",
        "SN": "Senegal",
        "AO": "Angola",
        "CM": "Cameroon",
        "DZ": "Algeria",
        "MM": "Myanmar",
        "KH": "Cambodia",
        "EC": "Ecuador",
        "BO": "Bolivia",
        "UY": "Uruguay",
        "VE": "Venezuela",
        "CU": "Cuba",
        "AL": "Albania",
        "KP": "North Korea",
        "NZ": "New Zealand",
        "LK": "Sri Lanka",
        "QA": "Qatar",
        "KW": "Kuwait",
        "AF": "Afghanistan",
    }.items()
}


# All known ISO codes (used for bracket matching)
_KNOWN_ISO_CODES: set[str] = set(COUNTRY_NAMES.values()) | set(TLD_HINTS.values())


# ---------------------------------------------------------------------------
# Signal extractors
# ---------------------------------------------------------------------------


def _match_country_names(text: str) -> list[tuple[str, str]]:
    """Match country names / adjectives. Sort by length desc to avoid partial matches."""
    lowered = text.lower()
    results = []
    for token in sorted(COUNTRY_NAMES, key=len, reverse=True):
        if re.search(rf"\b{re.escape(token)}\b", lowered):
            results.append((COUNTRY_NAMES[token], f"name:{token}"))
    return results


def _match_iso_brackets(text: str) -> list[tuple[str, str]]:
    """Detect explicit ISO codes placed by threat actors: (MX), [BR], |US|, etc.
    These are the highest-confidence signal since they are intentional labeling.
    """
    results = []
    for m in re.finditer(r"[\(\[\|]\s*([A-Z]{2})\s*[\)\]\|]", text):
        iso = m.group(1).upper()
        if iso in _KNOWN_ISO_CODES:
            results.append((iso, f"iso_bracket:{iso}"))
    return results


def _match_phone_prefixes(text: str) -> list[tuple[str, str]]:
    """Match phone-like prefixes (+XX followed by digit).
    Each distinct occurrence adds a signal (capped at 3 per prefix) so that
    a post containing multiple phone numbers from the same country raises
    confidence proportionally.
    """
    results = []
    # Sort longer prefixes first so +49 is checked before +4
    for prefix in sorted(PHONE_PREFIXES, key=len, reverse=True):
        pattern = rf"(?<!\d){re.escape(prefix)}(?!\d)[\s\-\.\(]?\d"
        count = min(len(re.findall(pattern, text)), 3)
        for _ in range(count):
            results.append((PHONE_PREFIXES[prefix], f"phone:{prefix}"))
    return results


def _match_tlds(text: str) -> list[tuple[str, str]]:
    """Extract ccTLDs from domain-like strings."""
    lowered = text.lower()
    results = []
    for ext in re.findall(r"\b(?:[a-z0-9-]+\.)+([a-z]{2,4})\b", lowered):
        tld = f".{ext}"
        if tld in TLD_HINTS:
            results.append((TLD_HINTS[tld], f"tld:{tld}"))
    return results


def _match_cities(text: str) -> list[tuple[str, str]]:
    lowered = text.lower()
    results = []
    for city in sorted(CITY_HINTS, key=len, reverse=True):
        if re.search(rf"\b{re.escape(city)}\b", lowered):
            results.append((CITY_HINTS[city], f"city:{city}"))
    return results


def _match_language_hints(text: str) -> list[tuple[str, str]]:
    lowered = text.lower()
    return [(iso, f"lang:{term}") for term, iso in LANGUAGE_HINTS.items() if term in lowered]


def _match_geotext(text: str) -> list[tuple[str, str]]:
    try:
        places = GeoText(text)
        return [(_GEOTEXT_TO_ISO[c], f"ner:{c}") for c in (places.countries or []) if c in _GEOTEXT_TO_ISO]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _aggregate(signals: list[tuple[str, str, float]]) -> tuple[str, float, list[str]] | None:
    """
    Aggregate (iso, evidence, weight) signals.
    Returns (iso, confidence, evidence_list) or None if below threshold.
    """
    if not signals:
        return None

    score: dict[str, float] = {}
    evidence: dict[str, list[str]] = {}
    for iso, ev, w in signals:
        score[iso] = score.get(iso, 0.0) + w
        evidence.setdefault(iso, []).append(ev)

    best = max(score, key=lambda k: score[k])
    conf = min(score[best], 1.0)

    # Require at least 0.40 confidence (prevents weak single-signal guesses)
    if conf < 0.40:
        return None

    return best, round(conf, 2), evidence[best][:5]


# ---------------------------------------------------------------------------
# LLM fallback (optional)
# ---------------------------------------------------------------------------


def _extract_json_block(raw: str) -> dict | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        pass
    m = re.search(r"\{[\s\S]*\}", raw)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


def _deepseek_stage(text: str) -> dict | None:
    """Optional DeepSeek fallback. Returns a partial origin dict or None."""
    if not getattr(settings, "deepseek_origin_enabled", False):
        return None
    if not getattr(settings, "deepseek_api_key", ""):
        return None

    payload = {
        "model": settings.deepseek_model,
        "temperature": settings.deepseek_temperature,
        "max_tokens": settings.deepseek_max_tokens,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a CTI classifier. Return the ISO-3166-1 alpha-2 country code "
                    "of the victim organisation from the threat post below. "
                    'Return strict JSON: {"country": "XX", "confidence": 0.0-1.0, "evidence": "..."}. '
                    "If uncertain, use null for country."
                ),
            },
            {"role": "user", "content": text[:6000]},
        ],
    }
    try:
        with httpx.Client(timeout=getattr(settings, "deepseek_timeout_seconds", 20)) as client:
            resp = client.post(
                f"{settings.deepseek_base_url.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.deepseek_api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return None

    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    parsed = _extract_json_block(content)
    if not parsed:
        return None

    country = parsed.get("country")
    if not isinstance(country, str) or not country.strip():
        return None

    country = country.strip().upper()[:2]
    try:
        conf = float(parsed.get("confidence", 0.45))
    except Exception:
        conf = 0.45
    conf = max(0.0, min(1.0, conf))

    return {
        "country": country,
        "method": "deepseek_fallback",
        "confidence": round(conf, 2),
        "evidence": str(parsed.get("evidence", "model inference"))[:280],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class OriginResult:
    country: str | None  # ISO-3166-1 alpha-2 or None
    method: str
    confidence: float
    evidence: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "country": self.country,
            "method": self.method,
            "confidence": round(self.confidence, 2),
            "evidence": "; ".join(self.evidence) if self.evidence else "no signal",
        }


def detect_victim_origin(raw_post: str) -> dict:
    """
    Multi-signal victim country detection.
    Returns dict: {country, method, confidence, evidence}.
    country is an ISO-3166-1 alpha-2 code (e.g. "CN", "FR") or None.
    """
    text = (raw_post or "").strip()
    if not text:
        return OriginResult(country=None, method="none", confidence=0.0).as_dict()

    signals: list[tuple[str, str, float]] = []

    # Explicit ISO bracket labels — highest confidence (threat actor intentionally tagged it)
    for iso, ev in _match_iso_brackets(text):
        signals.append((iso, ev, 0.95))

    # Strong signals
    for iso, ev in _match_country_names(text):
        signals.append((iso, ev, 0.90))

    for iso, ev in _match_phone_prefixes(text):
        signals.append((iso, ev, 0.75))

    # Medium signals
    for iso, ev in _match_tlds(text):
        signals.append((iso, ev, 0.65))

    for iso, ev in _match_cities(text):
        signals.append((iso, ev, 0.60))

    for iso, ev in _match_language_hints(text):
        signals.append((iso, ev, 0.50))

    # Weak signals
    for iso, ev in _match_geotext(text):
        signals.append((iso, ev, 0.45))

    result = _aggregate(signals)
    if result:
        iso, conf, ev_list = result
        return OriginResult(
            country=iso,
            method="multi_signal",
            confidence=conf,
            evidence=ev_list,
        ).as_dict()

    # LLM fallback (if enabled and no heuristic signal found)
    llm = _deepseek_stage(text)
    if llm:
        return llm

    # No signal → Unknown, do NOT guess
    return OriginResult(
        country=None,
        method="none",
        confidence=0.0,
        evidence=["no signal"],
    ).as_dict()
