"""
IOC Hunter — AI-Powered Threat Intelligence Scraper
Scrapes threat intel pages and extracts Indicators of Compromise (IOCs)
for use in threat hunting operations.

Usage:
  python scraper_bot.py <url>
  python scraper_bot.py <url> --output iocs.json
  python scraper_bot.py <url> --format csv
  python scraper_bot.py <url> --context "Lazarus Group campaign targeting finance sector"
"""

import asyncio
import sys
import re
import json
import csv
import io
import argparse
import datetime
import anthropic
from playwright.async_api import async_playwright


# ---------------------------------------------------------------------------
# Regex pre-extractors — pull raw IOC candidates before sending to Claude
# ---------------------------------------------------------------------------

def refang(text: str) -> str:
    """Restore defanged IOCs to their canonical form."""
    return (
        text.replace("[.]", ".")
            .replace("[:]", ":")
            .replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
            .replace("HXXPS://", "https://")
            .replace("HXXP://", "http://")
    )


def pre_extract_iocs(text: str) -> dict:
    """
    Regex-based IOC extraction to provide Claude with pre-identified candidates.
    Returns a dict of IOC type -> list of unique matches.
    """
    refanged = refang(text)

    patterns = {
        "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "ipv6": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
        "md5":  r"\b[0-9a-fA-F]{32}\b",
        "sha1": r"\b[0-9a-fA-F]{40}\b",
        "sha256": r"\b[0-9a-fA-F]{64}\b",
        "sha512": r"\b[0-9a-fA-F]{128}\b",
        "cve": r"\bCVE-\d{4}-\d{4,7}\b",
        "email": r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
        "url": r"https?://[^\s\"'<>\]){},]+",
        "domain": (
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
            r"(?:com|net|org|io|gov|edu|mil|int|co|uk|de|ru|cn|info|biz|xyz|top|tk|pw|cc|su|onion)\b"
        ),
        "mitre_attack": r"\bT\d{4}(?:\.\d{3})?\b",
        "registry_key": r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\s\"'<>]+",
        "file_path_win": r"[A-Za-z]:\\(?:[^\\\/:*?\"<>|\r\n]+\\)*[^\\\/:*?\"<>|\r\n]*",
        "file_path_unix": r"(?:/[a-zA-Z0-9_.\-]+){2,}",
        "bitcoin_address": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "monero_address": r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
        "filename": (
            r"\b[\w\-]+\."
            r"(?:zip|rar|7z|tar|gz|cab|iso|img"
            r"|exe|dll|sys|ocx|scr|com|pif"
            r"|bat|cmd|ps1|vbs|vbe|js|jse|hta|wsf|wsh"
            r"|doc|docx|docm|xls|xlsx|xlsm|ppt|pptx|pptm"
            r"|pdf|rtf|lnk|url|inf"
            r"|jar|class|apk|elf|sh|py|rb|pl)\b"
        ),
    }

    results = {}
    for ioc_type, pattern in patterns.items():
        matches = re.findall(pattern, refanged, re.IGNORECASE)
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for m in matches:
            key = m.lower()
            if key not in seen:
                seen.add(key)
                unique.append(m)
        if unique:
            results[ioc_type] = unique

    # Filter out private/loopback IPs from IPv4 results
    if "ipv4" in results:
        public_ips = []
        for ip in results["ipv4"]:
            parts = ip.split(".")
            a = int(parts[0])
            b = int(parts[1])
            is_private = (
                a == 10
                or (a == 172 and 16 <= b <= 31)
                or (a == 192 and b == 168)
                or a == 127
                or a == 0
            )
            if not is_private:
                public_ips.append(ip)
        if public_ips:
            results["ipv4"] = public_ips
        else:
            del results["ipv4"]

    return results


# ---------------------------------------------------------------------------
# Headless browser scraper
# ---------------------------------------------------------------------------

async def scrape_page(url: str) -> dict:
    """Launch headless Chromium, navigate to URL, and extract page content."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        )

        print(f"[*] Navigating to: {url}")
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
        except Exception:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

        await page.wait_for_timeout(1500)

        title = await page.title()

        # Extract raw HTML text (keep defanged forms intact for context)
        text_content = await page.evaluate("""() => {
            const cloned = document.body.cloneNode(true);
            for (const el of cloned.querySelectorAll('script, style, noscript, svg')) {
                el.remove();
            }
            return cloned.innerText || cloned.textContent || '';
        }""")

        # Also grab the raw HTML for code blocks / pre tags (common in threat reports)
        code_blocks = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('pre, code, .highlight'))
                .map(el => el.innerText || el.textContent || '')
                .filter(t => t.trim().length > 0)
                .join('\\n---\\n');
        }""")

        meta_desc = await page.evaluate("""() => {
            const meta = document.querySelector('meta[name="description"]');
            return meta ? meta.getAttribute('content') : '';
        }""")

        await browser.close()

        lines = [line.strip() for line in text_content.splitlines() if line.strip()]
        clean_text = "\n".join(lines)

        # Combine main text with code blocks
        full_text = clean_text
        if code_blocks.strip():
            full_text += "\n\n=== CODE/PRE BLOCKS ===\n" + code_blocks

        if len(full_text) > 60000:
            full_text = full_text[:60000] + "\n\n[...content truncated...]"

        return {
            "url": url,
            "title": title,
            "meta_description": meta_desc,
            "text": full_text,
        }


# ---------------------------------------------------------------------------
# Claude IOC analysis
# ---------------------------------------------------------------------------

def analyze_iocs_with_claude(scraped: dict, pre_extracted: dict, context: str) -> dict:
    """Send scraped content + pre-extracted candidates to Claude for deep IOC analysis."""
    client = anthropic.Anthropic()

    pre_extracted_str = ""
    if pre_extracted:
        pre_extracted_str = "\n\nREGEX PRE-EXTRACTED CANDIDATES (may contain false positives):\n"
        for ioc_type, values in pre_extracted.items():
            pre_extracted_str += f"  {ioc_type.upper()}: {', '.join(values[:30])}\n"
    else:
        pre_extracted_str = "\n\n(No IOCs matched by regex pre-extraction.)\n"

    context_str = f"\nThreat Hunt Context: {context}\n" if context else ""

    user_message = f"""You are analyzing a threat intelligence source for IOC extraction.
{context_str}
SOURCE URL: {scraped['url']}
PAGE TITLE: {scraped['title']}
{pre_extracted_str}

FULL PAGE CONTENT:
{scraped['text']}

---

Extract ALL Indicators of Compromise (IOCs) from the above content and return them as a valid JSON object with this exact structure:

{{
  "summary": "2-3 sentence summary of the threat/report",
  "threat_actor": "threat actor or group name if identified, else null",
  "malware_families": ["list of malware family names"],
  "campaigns": ["campaign names or operation names"],
  "targeted_sectors": ["list of targeted industries/sectors"],
  "targeted_countries": ["list of targeted countries/regions"],
  "mitre_techniques": [
    {{"id": "T1234", "name": "technique name", "context": "how it was used"}}
  ],
  "iocs": {{
    "ipv4": [
      {{"value": "1.2.3.4", "context": "C2 server", "confidence": "high|medium|low"}}
    ],
    "ipv6": [],
    "domains": [
      {{"value": "evil.com", "context": "phishing domain", "confidence": "high|medium|low"}}
    ],
    "urls": [
      {{"value": "https://evil.com/path", "context": "payload delivery", "confidence": "high|medium|low"}}
    ],
    "md5": [
      {{"value": "abc123...", "context": "dropper", "confidence": "high|medium|low"}}
    ],
    "sha1": [],
    "sha256": [
      {{"value": "abc123...", "context": "ransomware binary", "confidence": "high|medium|low"}}
    ],
    "sha512": [],
    "emails": [],
    "cves": [
      {{"value": "CVE-2024-1234", "context": "exploited vulnerability", "confidence": "high|medium|low"}}
    ],
    "registry_keys": [],
    "file_paths": [],
    "filenames": [
      {{"value": "malware.exe", "context": "dropper dropped by loader", "confidence": "high|medium|low"}}
    ],
    "mutexes": [],
    "user_agents": [],
    "bitcoin_addresses": [],
    "yara_rules": [],
    "other": []
  }},
  "tlp": "WHITE|GREEN|AMBER|RED",
  "source_reliability": "high|medium|low",
  "first_seen": "date if mentioned, else null",
  "last_seen": "date if mentioned, else null"
}}

IMPORTANT:
- Refang any defanged IOCs (e.g. 1[.]2[.]3[.]4 → 1.2.3.4, hxxps → https)
- Include ONLY confirmed IOCs, not examples or hypotheticals
- Assign confidence based on how explicitly the source attributes the IOC
- For filenames: extract any specific file names mentioned (e.g. SumatraPDF.exe, DWrite.dll, payload.zip) including those inside archives, dropped files, or tools used by the attacker
- Return ONLY the JSON object, no markdown fences or extra text"""

    print("[*] Sending to Claude for IOC extraction...")

    with client.messages.stream(
        model="claude-opus-4-6",
        max_tokens=8096,
        thinking={"type": "adaptive"},
        system=(
            "You are a senior threat intelligence analyst specializing in IOC extraction "
            "and malware analysis. You extract precise, actionable indicators from threat "
            "reports, blog posts, and security advisories. You always refang defanged IOCs, "
            "assign confidence levels based on source attribution, and never include false "
            "positives or generic infrastructure. Return only valid JSON."
        ),
        messages=[{"role": "user", "content": user_message}],
    ) as stream:
        raw = ""
        print("[*] Extracting IOCs", end="", flush=True)
        for text in stream.text_stream:
            raw += text
            print(".", end="", flush=True)
        print(" done")

    # Parse JSON from Claude's response
    try:
        # Strip any accidental markdown fences
        clean = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
        clean = re.sub(r"\s*```$", "", clean.strip(), flags=re.MULTILINE)
        return json.loads(clean)
    except json.JSONDecodeError:
        # Attempt to extract just the JSON object
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        print("[!] Warning: Could not parse Claude's JSON response", file=sys.stderr)
        return {"raw_response": raw}


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def print_ioc_report(data: dict, source_url: str):
    """Pretty-print the IOC report to the terminal."""
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    print("\n" + "=" * 70)
    print("  IOC THREAT INTELLIGENCE REPORT")
    print(f"  Source : {source_url}")
    print(f"  Generated: {ts}")
    print("=" * 70)

    if "summary" in data:
        print(f"\nSUMMARY\n  {data['summary']}")

    if data.get("threat_actor"):
        print(f"\nTHREAT ACTOR\n  {data['threat_actor']}")

    if data.get("malware_families"):
        print(f"\nMALWARE FAMILIES\n  {', '.join(data['malware_families'])}")

    if data.get("targeted_sectors"):
        print(f"\nTARGETED SECTORS\n  {', '.join(data['targeted_sectors'])}")

    if data.get("targeted_countries"):
        print(f"\nTARGETED COUNTRIES\n  {', '.join(data['targeted_countries'])}")

    if data.get("cves") or (data.get("iocs") and data["iocs"].get("cves")):
        cves = data.get("iocs", {}).get("cves", [])
        if cves:
            print(f"\nCVEs ({len(cves)})")
            for c in cves:
                print(f"  [{c.get('confidence','?').upper():6}] {c['value']:20}  {c.get('context','')}")

    if data.get("mitre_techniques"):
        print(f"\nMITRE ATT&CK TECHNIQUES ({len(data['mitre_techniques'])})")
        for t in data["mitre_techniques"]:
            tid = t.get("id", "?")
            name = t.get("name", "")
            ctx = t.get("context", "")
            print(f"  {tid:12} {name:40} {ctx}")

    iocs = data.get("iocs", {})
    ioc_types = [
        ("ipv4",            "IPv4 ADDRESSES"),
        ("ipv6",            "IPv6 ADDRESSES"),
        ("domains",         "DOMAINS"),
        ("urls",            "URLS"),
        ("sha256",          "SHA256 HASHES"),
        ("sha1",            "SHA1 HASHES"),
        ("md5",             "MD5 HASHES"),
        ("sha512",          "SHA512 HASHES"),
        ("emails",          "EMAIL ADDRESSES"),
        ("registry_keys",   "REGISTRY KEYS"),
        ("file_paths",      "FILE PATHS"),
        ("filenames",       "FILENAMES"),
        ("mutexes",         "MUTEXES"),
        ("user_agents",     "USER AGENTS"),
        ("bitcoin_addresses","BITCOIN ADDRESSES"),
        ("yara_rules",      "YARA RULES"),
        ("other",           "OTHER IOCs"),
    ]

    for key, label in ioc_types:
        entries = iocs.get(key, [])
        if not entries:
            continue
        print(f"\n{label} ({len(entries)})")
        for e in entries:
            if isinstance(e, dict):
                conf = e.get("confidence", "?").upper()
                val = e.get("value", "")
                ctx = e.get("context", "")
                print(f"  [{conf:6}] {val:55} {ctx}")
            else:
                print(f"  {e}")

    print(f"\nTLP         : {data.get('tlp', 'N/A')}")
    print(f"Reliability : {data.get('source_reliability', 'N/A')}")
    if data.get("first_seen"):
        print(f"First Seen  : {data['first_seen']}")
    if data.get("last_seen"):
        print(f"Last Seen   : {data['last_seen']}")
    print("=" * 70)


def to_csv(data: dict, source_url: str) -> str:
    """Export IOCs as a flat CSV suitable for importing into a SIEM or TIP."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "type", "value", "context", "confidence",
        "threat_actor", "malware_family", "source_url", "extracted_at"
    ])

    ts = datetime.datetime.utcnow().isoformat() + "Z"
    actor = data.get("threat_actor", "")
    malware = ", ".join(data.get("malware_families", []))
    iocs = data.get("iocs", {})

    for ioc_type, entries in iocs.items():
        for e in entries:
            if isinstance(e, dict):
                writer.writerow([
                    ioc_type,
                    e.get("value", ""),
                    e.get("context", ""),
                    e.get("confidence", ""),
                    actor,
                    malware,
                    source_url,
                    ts,
                ])
            else:
                writer.writerow([ioc_type, e, "", "", actor, malware, source_url, ts])

    # Add MITRE techniques as rows too
    for t in data.get("mitre_techniques", []):
        writer.writerow([
            "mitre_technique",
            t.get("id", ""),
            t.get("context", ""),
            "high",
            actor,
            malware,
            source_url,
            ts,
        ])

    return output.getvalue()


def to_markdown(data: dict, source_url: str) -> str:
    """Export the IOC report as a Markdown document."""
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = []

    lines.append("# IOC Threat Intelligence Report")
    lines.append("")
    lines.append(f"**Source:** {source_url}  ")
    lines.append(f"**Generated:** {ts}  ")
    if data.get("tlp"):
        lines.append(f"**TLP:** {data['tlp']}  ")
    if data.get("source_reliability"):
        lines.append(f"**Source Reliability:** {data['source_reliability']}  ")
    lines.append("")

    if data.get("summary"):
        lines.append("## Summary")
        lines.append("")
        lines.append(data["summary"])
        lines.append("")

    meta_fields = [
        ("threat_actor",       "Threat Actor"),
        ("malware_families",   "Malware Families"),
        ("campaigns",          "Campaigns"),
        ("targeted_sectors",   "Targeted Sectors"),
        ("targeted_countries", "Targeted Countries"),
    ]
    meta_rows = []
    for key, label in meta_fields:
        val = data.get(key)
        if val:
            if isinstance(val, list):
                val = ", ".join(val) if val else "—"
            meta_rows.append((label, val))

    if data.get("first_seen") or data.get("last_seen"):
        if data.get("first_seen"):
            meta_rows.append(("First Seen", data["first_seen"]))
        if data.get("last_seen"):
            meta_rows.append(("Last Seen", data["last_seen"]))

    if meta_rows:
        lines.append("## Threat Overview")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        for label, val in meta_rows:
            lines.append(f"| {label} | {val} |")
        lines.append("")

    if data.get("mitre_techniques"):
        lines.append("## MITRE ATT&CK Techniques")
        lines.append("")
        lines.append("| ID | Name | Context |")
        lines.append("|---|---|---|")
        for t in data["mitre_techniques"]:
            lines.append(f"| {t.get('id','?')} | {t.get('name','')} | {t.get('context','')} |")
        lines.append("")

    iocs = data.get("iocs", {})
    ioc_types = [
        ("ipv4",             "IPv4 Addresses"),
        ("ipv6",             "IPv6 Addresses"),
        ("domains",          "Domains"),
        ("urls",             "URLs"),
        ("sha256",           "SHA256 Hashes"),
        ("sha1",             "SHA1 Hashes"),
        ("md5",              "MD5 Hashes"),
        ("sha512",           "SHA512 Hashes"),
        ("emails",           "Email Addresses"),
        ("cves",             "CVEs"),
        ("registry_keys",    "Registry Keys"),
        ("file_paths",       "File Paths"),
        ("filenames",        "Filenames"),
        ("mutexes",          "Mutexes"),
        ("user_agents",      "User Agents"),
        ("bitcoin_addresses","Bitcoin Addresses"),
        ("yara_rules",       "YARA Rules"),
        ("other",            "Other IOCs"),
    ]

    for key, label in ioc_types:
        entries = iocs.get(key, [])
        if not entries:
            continue
        lines.append(f"## {label} ({len(entries)})")
        lines.append("")
        lines.append("| Value | Context | Confidence |")
        lines.append("|---|---|---|")
        for e in entries:
            if isinstance(e, dict):
                lines.append(f"| `{e.get('value','')}` | {e.get('context','')} | {e.get('confidence','?')} |")
            else:
                lines.append(f"| `{e}` | | |")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

async def main():
    parser = argparse.ArgumentParser(
        description="IOC Hunter — AI-powered threat intel scraper for threat hunting"
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="Threat intel URL to scrape (blog, advisory, report). Optional when --text-file is used.",
    )
    parser.add_argument(
        "--text-file", "-t",
        default=None,
        metavar="FILE",
        help="Path to a plain-text file containing article content to analyze instead of scraping a URL. Use - to read from stdin.",
    )
    parser.add_argument(
        "--source-url",
        default="",
        help="Source URL label to use in reports when analyzing pasted text (optional)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Save results to file (e.g. iocs.json or iocs.csv)",
        default=None,
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "markdown", "both", "all"],
        default="json",
        help="Output format: json (default), csv, markdown, both (json+csv), or all (json+csv+markdown)",
    )
    parser.add_argument(
        "--context", "-c",
        default="",
        help='Optional threat hunt context (e.g. "APT29 targeting energy sector")',
    )
    args = parser.parse_args()

    if not args.url and not args.text_file:
        parser.error("Provide a URL to scrape, or use --text-file to analyze a local file.")

    try:
        # 1. Scrape or load text
        if args.text_file:
            if args.text_file == "-":
                print("[*] Reading from stdin...")
                raw_text = sys.stdin.read()
            else:
                with open(args.text_file, "r", encoding="utf-8") as f:
                    raw_text = f.read()
            url = args.source_url or args.text_file
            scraped = {
                "url": url,
                "title": args.source_url or args.text_file,
                "meta_description": "",
                "text": raw_text[:60000],
            }
            print(f"[+] Loaded text — {len(scraped['text'])} chars")
        else:
            url = args.url
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            scraped = await scrape_page(url)
            print(f"[+] Scraped '{scraped['title']}' — {len(scraped['text'])} chars")

        # 2. Regex pre-extraction
        pre = pre_extract_iocs(scraped["text"])
        total_candidates = sum(len(v) for v in pre.values())
        print(f"[+] Regex pre-extracted {total_candidates} IOC candidates across {len(pre)} types")

        # 3. Claude deep analysis
        result = analyze_iocs_with_claude(scraped, pre, args.context)

        # 4. Print report to terminal
        print_ioc_report(result, url)

        # 5. Save outputs
        if args.output:
            base = args.output.rsplit(".", 1)[0] if "." in args.output else args.output
            fmt = args.format

            if fmt in ("json", "both", "all"):
                json_path = base + ".json"
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2)
                print(f"[+] JSON saved to:     {json_path}")

            if fmt in ("csv", "both", "all"):
                csv_path = base + ".csv"
                with open(csv_path, "w", encoding="utf-8", newline="") as f:
                    f.write(to_csv(result, url))
                print(f"[+] CSV saved to:      {csv_path}")

            if fmt in ("markdown", "all"):
                md_path = base + ".md"
                with open(md_path, "w", encoding="utf-8") as f:
                    f.write(to_markdown(result, url))
                print(f"[+] Markdown saved to: {md_path}")

        elif args.format == "csv":
            print("\n" + to_csv(result, url))
        elif args.format == "markdown":
            print("\n" + to_markdown(result, url))

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
