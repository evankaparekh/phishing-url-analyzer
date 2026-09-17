"""Rule-based URL analysis that never visits the submitted URL."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import re
from urllib.parse import unquote, urlsplit


SUSPICIOUS_WORDS = {
    "account", "banking", "confirm", "login", "password", "secure",
    "signin", "update", "verify", "wallet",
}

SHORTENERS = {
    "bit.ly", "buff.ly", "cutt.ly", "is.gd", "ow.ly", "rebrand.ly",
    "shorturl.at", "t.co", "tiny.cc", "tinyurl.com",
}


@dataclass(frozen=True)
class Finding:
    points: int
    rule: str
    explanation: str


@dataclass(frozen=True)
class AnalysisResult:
    url: str
    normalized_url: str
    hostname: str
    score: int
    risk: str
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _risk_level(score: int) -> str:
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def analyze_url(url: str) -> AnalysisResult:
    """Return an explainable risk score without making a network request."""
    original = url.strip()
    if not original:
        raise ValueError("URL cannot be empty")

    normalized = original if "://" in original else f"http://{original}"
    parsed = urlsplit(normalized)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError("URL must contain a valid hostname")

    findings: list[Finding] = []

    def add(points: int, rule: str, explanation: str) -> None:
        findings.append(Finding(points, rule, explanation))

    if parsed.scheme.lower() != "https":
        add(15, "no_https", "The URL does not use HTTPS.")
    if _is_ip_address(hostname):
        add(25, "ip_address", "An IP address is used instead of a domain name.")
    if "xn--" in hostname:
        add(20, "punycode", "Punycode can be used for lookalike domains.")
    if "@" in parsed.netloc:
        add(20, "at_symbol", "Text before @ can disguise the real destination.")
    if len(normalized) >= 75:
        add(10, "long_url", "The URL is unusually long.")
    if not _is_ip_address(hostname) and len(hostname.split(".")) > 4:
        add(10, "many_subdomains", "The hostname has an unusual number of subdomains.")
    if hostname in SHORTENERS or any(hostname.endswith(f".{d}") for d in SHORTENERS):
        add(20, "shortener", "A URL shortener hides the final destination.")
    if hostname.count("-") >= 3:
        add(10, "many_hyphens", "The hostname contains several hyphens.")
    if re.search(r"%[0-9a-fA-F]{2}", original):
        add(10, "encoded_characters", "Encoded characters can hide parts of a URL.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    if port is not None and port not in {80, 443}:
        add(10, "unusual_port", f"The URL uses uncommon port {port}.")

    searchable = unquote(f"{hostname}{parsed.path}?{parsed.query}").lower()
    matched = sorted(word for word in SUSPICIOUS_WORDS if re.search(rf"\b{word}\b", searchable))
    if matched:
        points = min(30, len(matched) * 10)
        add(points, "suspicious_words", f"Sensitive-action words found: {', '.join(matched)}.")

    score = min(100, sum(f.points for f in findings))
    return AnalysisResult(original, normalized, hostname, score, _risk_level(score), tuple(findings))
