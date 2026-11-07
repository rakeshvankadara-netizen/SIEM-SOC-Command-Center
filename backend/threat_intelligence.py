"""
SIEM threat-intelligence module with AbuseIPDB live lookup and local fallback.
Preserves the synchronous check_ip_reputation(source_ip) API used by main.py.
"""
from __future__ import annotations

import ipaddress
import os
import time
from typing import Any, Dict, Optional

import httpx
from dotenv import load_dotenv

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS = int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"))
ABUSEIPDB_TIMEOUT_SECONDS = float(os.getenv("ABUSEIPDB_TIMEOUT_SECONDS", "8"))
CACHE_TTL_SECONDS = int(os.getenv("IP_REPUTATION_CACHE_TTL_SECONDS", "600"))

# Local demonstration indicators only; not public threat-intelligence claims.
THREAT_INTELLIGENCE: Dict[str, Dict[str, Any]] = {
    "192.168.1.77": {
        "reputation": "SUSPICIOUS",
        "threat_type": "Brute Force Source (Lab Indicator)",
        "risk_score": 80,
        "confidence": 85,
        "description": "Local demonstration indicator for brute-force testing.",
    },
    "10.0.0.99": {
        "reputation": "SUSPICIOUS",
        "threat_type": "Login Attack Source (Lab Indicator)",
        "risk_score": 70,
        "confidence": 80,
        "description": "Local demonstration indicator for login-attack testing.",
    },
    "198.51.100.25": {
        "reputation": "SIMULATED",
        "threat_type": "SIEM Test-Net Simulation",
        "risk_score": 40,
        "confidence": 100,
        "description": (
            "Documentation-only TEST-NET address used by synthetic SIEM events. "
            "Not a real attacker indicator and never submitted to AbuseIPDB."
        ),
    },
}

_CACHE: Dict[str, tuple[float, Dict[str, Any]]] = {}


def _result(ip_address: str, reputation: str, threat_type: str,
            risk_score: int, confidence: int, source: str,
            description: str, **extra: Any) -> Dict[str, Any]:
    result = {
        "ip_address": ip_address,
        "reputation": reputation,
        "threat_type": threat_type,
        "risk_score": max(0, min(100, int(risk_score))),
        "confidence": max(0, min(100, int(confidence))),
        "source": source,
        "description": description,
    }
    result.update(extra)
    return result


def _local_result(ip_text: str) -> Optional[Dict[str, Any]]:
    indicator = THREAT_INTELLIGENCE.get(ip_text)
    if not indicator:
        return None
    return _result(
        ip_text, indicator["reputation"], indicator["threat_type"],
        indicator["risk_score"], indicator["confidence"],
        "Local SIEM Demonstration Database",
        indicator.get("description", ""),
        ip_reputation_source="Local SIEM Demonstration Database",
        lookup_status="local",
    )


def _fallback(ip_text: str, reason: str) -> Dict[str, Any]:
    local = _local_result(ip_text)
    if local:
        local["description"] += f" Live lookup unavailable: {reason}"
        local["lookup_status"] = "fallback"
        return local
    return _result(
        ip_text, "UNKNOWN", "Live Reputation Lookup Unavailable", 0, 0,
        "AbuseIPDB unavailable; no local match",
        "The IP could not be checked against AbuseIPDB and has no local "
        f"indicator. This does not mean it is safe. Reason: {reason}",
        lookup_status="unavailable",
    )


def _check_abuseipdb(ip_text: str) -> Dict[str, Any]:
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {
        "ipAddress": ip_text,
        "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS,
        "verbose": "",
    }
    try:
        with httpx.Client(timeout=ABUSEIPDB_TIMEOUT_SECONDS) as client:
            response = client.get(
                ABUSEIPDB_CHECK_URL, headers=headers, params=params
            )
        if response.status_code in (401, 403):
            return _fallback(ip_text, "API key rejected or not authorized")
        if response.status_code == 429:
            return _fallback(ip_text, "provider rate limit reached")
        response.raise_for_status()
        data = (response.json().get("data") or {})
        score = int(data.get("abuseConfidenceScore") or 0)
        total_reports = int(data.get("totalReports") or 0)
        distinct_users = int(data.get("numDistinctUsers") or 0)

        if score >= 75:
            reputation, threat_type = "MALICIOUS", "High Abuse Confidence"
        elif score >= 25:
            reputation, threat_type = "SUSPICIOUS", "Reported Abuse Activity"
        else:
            reputation, threat_type = "LOW_RISK", "Low Abuse Reports"

        description = (
            f"AbuseIPDB abuse confidence: {score}/100. Reports: {total_reports}; "
            f"distinct reporters: {distinct_users}; lookback: "
            f"{ABUSEIPDB_MAX_AGE_DAYS} days. A low score is not proof that an IP is safe."
        )
        return _result(
            ip_text, reputation, threat_type, score, score, "AbuseIPDB",
            description,
            ip_reputation_source="AbuseIPDB",
            lookup_status="live",
            abuse_confidence_score=score,
            total_reports=total_reports,
            num_distinct_users=distinct_users,
            country_code=data.get("countryCode"),
            usage_type=data.get("usageType"),
            isp=data.get("isp"),
            domain=data.get("domain"),
            last_reported_at=data.get("lastReportedAt"),
            is_public=data.get("isPublic"),
        )
    except httpx.TimeoutException:
        return _fallback(ip_text, "request timed out")
    except httpx.HTTPStatusError as exc:
        return _fallback(ip_text, f"provider returned HTTP {exc.response.status_code}")
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        return _fallback(ip_text, "network error or invalid provider response")


def check_ip_reputation(source_ip: Any) -> Optional[Dict[str, Any]]:
    """Check a local indicator first, otherwise query AbuseIPDB for public IPs."""
    if source_ip is None:
        return None
    if isinstance(source_ip, (list, tuple, set)):
        source_ip = next((item for item in source_ip if item), None)
        if source_ip is None:
            return None

    ip_text = str(source_ip).strip()
    if not ip_text or ip_text.lower() in {"-", "unknown", "none", "::"}:
        return None
    if ip_text.startswith("[") and ip_text.endswith("]"):
        ip_text = ip_text[1:-1]

    try:
        parsed = ipaddress.ip_address(ip_text)
    except ValueError:
        return _result(
            ip_text, "INVALID", "Invalid IP Address", 0, 100,
            "Local Validation",
            "The supplied value is not a valid IPv4 or IPv6 address.",
            lookup_status="invalid",
        )

    normalized = str(parsed)

    # Preserve deterministic lab results and never send synthetic indicators out.
    local = _local_result(normalized)
    if local:
        return local

    # AbuseIPDB is intended for public IPs; do not submit private/reserved IPs.
    if not parsed.is_global:
        return _result(
            normalized, "NOT_APPLICABLE", "Non-public IP Address", 0, 0,
            "Local IP Validation",
            "Private, loopback, link-local, or reserved IPs are not checked against AbuseIPDB.",
            lookup_status="not_applicable",
        )

    now = time.monotonic()
    cached = _CACHE.get(normalized)
    if cached and now - cached[0] < CACHE_TTL_SECONDS:
        result = dict(cached[1])
        result["cached"] = True
        return result

    if not ABUSEIPDB_API_KEY:
        result = _fallback(normalized, "ABUSEIPDB_API_KEY is not configured")
    else:
        result = _check_abuseipdb(normalized)

    _CACHE[normalized] = (now, dict(result))
    result.setdefault("cached", False)
    return result


if __name__ == "__main__":
    for test_ip in ("198.51.100.25", "192.168.1.77", "8.8.8.8", "192.168.1.290"):
        print(f"{test_ip}: {check_ip_reputation(test_ip)}")
