"""
IOC Hunter — IP reputation and TLD WHOIS lookup helpers.

AbuseIPDB API docs: https://www.abuseipdb.com/api/v2
IANA WHOIS server:  whois.iana.org:43
"""

import socket
import json
import urllib.request
import urllib.parse
import urllib.error

# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def lookup_abuseipdb(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    """
    Query AbuseIPDB for reputation data on a single IP address.

    Returns the 'data' dict from the API response.
    Raises RuntimeError on API errors, ValueError if key or IP is missing.
    """
    if not api_key:
        raise ValueError("AbuseIPDB API key is required.")
    ip = ip.strip()
    if not ip:
        raise ValueError("IP address cannot be empty.")

    params = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
        "verbose": "",  # include recent reports
    })
    req = urllib.request.Request(
        f"{_ABUSEIPDB_URL}?{params}",
        headers={
            "Key": api_key,
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            return payload.get("data", payload)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            err = json.loads(body)
            detail = err.get("errors", [{}])[0].get("detail", str(e))
        except Exception:
            detail = str(e)
        raise RuntimeError(f"AbuseIPDB: {detail}") from e


# ---------------------------------------------------------------------------
# IANA WHOIS (TLD lookups)
# ---------------------------------------------------------------------------

_IANA_HOST = "whois.iana.org"
_IANA_PORT = 43


def lookup_tld_whois(tld: str) -> dict:
    """
    Query the IANA WHOIS server for information about a Top-Level Domain.

    Accepts with or without a leading dot (e.g. 'ru' or '.ru').
    Returns a dict with parsed fields plus the full 'raw' response string.
    Raises ValueError for empty input, RuntimeError on network errors.
    """
    tld = tld.strip().lstrip(".").lower()
    if not tld:
        raise ValueError("TLD cannot be empty.")

    try:
        with socket.create_connection((_IANA_HOST, _IANA_PORT), timeout=10) as sock:
            sock.sendall(f"{tld}\r\n".encode("utf-8"))
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError as e:
        raise RuntimeError(f"WHOIS connection failed: {e}") from e

    raw = b"".join(chunks).decode("utf-8", errors="replace")

    # Parse structured fields from the WHOIS text
    parsed: dict = {"tld": f".{tld}", "raw": raw}
    nservers: list[str] = []
    remarks: list[str] = []

    # Map WHOIS field names to our output keys (first occurrence wins)
    _field_map = {
        "organisation": "organisation",
        "organization":  "organisation",
        "registrar":     "registrar",
        "created":       "created",
        "changed":       "changed",
        "source":        "source",
        "status":        "status",
        "whois":         "whois_server",
        "contact":       "contact",
    }

    for line in raw.splitlines():
        if not line.strip() or line.startswith("%"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue

        if key == "nserver":
            nservers.append(value)
        elif key == "remarks":
            remarks.append(value)
        elif key in _field_map:
            dest = _field_map[key]
            if dest not in parsed:
                parsed[dest] = value

    if nservers:
        parsed["nservers"] = nservers
    if remarks:
        parsed["remarks"] = remarks

    return parsed
