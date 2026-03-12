# IOC Hunter — AI-Powered Threat Intelligence Scraper

IOC Hunter is a command-line tool that scrapes threat intelligence pages (blog posts, advisories, reports) and uses Claude AI to extract and classify Indicators of Compromise (IOCs) for use in threat hunting operations.

---

## Features

- **Headless browser scraping** — Uses Playwright/Chromium to render JavaScript-heavy pages and extract full page content, including code blocks and `<pre>` tags common in threat reports.
- **Regex pre-extraction** — Before calling Claude, the tool runs regex patterns to identify IOC candidates across 15+ types, reducing false negatives.
- **AI-powered deep analysis** — Sends the scraped content and regex candidates to Claude (Opus 4.6) for intelligent IOC classification with confidence scoring.
- **Defang/refang support** — Automatically restores defanged IOCs (e.g., `hxxps://`, `1[.]2[.]3[.]4`) to canonical form.
- **Multiple output formats** — Print to terminal, export as JSON, CSV, or both.
- **SIEM/TIP-ready CSV** — Flat CSV export includes threat actor, malware family, source URL, and timestamp for direct ingestion.

---

## IOC Types Extracted

| Category | Types |
|---|---|
| **Network** | IPv4, IPv6, Domains, URLs |
| **File Hashes** | MD5, SHA1, SHA256, SHA512 |
| **Endpoint** | Registry keys, File paths, Mutexes, User agents |
| **Identity** | Email addresses |
| **Vulnerability** | CVEs |
| **Threat Intel** | MITRE ATT&CK techniques, YARA rules |
| **Financial** | Bitcoin addresses, Monero addresses |
| **Metadata** | Threat actor, Malware families, Campaigns, Targeted sectors/countries, TLP, Source reliability |

---

## Requirements

- Python 3.8+
- An Anthropic API key

### Python Dependencies

```
anthropic
playwright
```

Install them:

```bash
pip install -r requirements.txt
```

> **Note:** `asyncio` is part of the Python standard library and does not need to be installed separately.

After installing Playwright, install the Chromium browser:

```bash
playwright install chromium
```

### API Key Setup

IOC Hunter requires an Anthropic API key. Set it as an environment variable before running:

**Linux / macOS:**
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

**Windows (Command Prompt):**
```cmd
set ANTHROPIC_API_KEY=sk-ant-...
```

**Windows (PowerShell):**
```powershell
$env:ANTHROPIC_API_KEY="sk-ant-..."
```

---

## Web Interface (Streamlit)

IOC Hunter includes a Streamlit web UI as an alternative to the CLI.

```bash
streamlit run app.py
```

This opens a browser at `http://localhost:8501` with:
- Sidebar URL input, optional context field, and output format checkboxes
- Live status updates during scraping and analysis
- Results displayed in **Summary / IOCs / MITRE ATT&CK / Raw JSON** tabs
- One-click **Download JSON / CSV / Markdown** buttons

---

## CLI Usage

### Basic — scrape a URL and print report to terminal

```bash
python scraper_bot.py https://example.com/threat-report
```

### Save output as JSON

```bash
python scraper_bot.py https://example.com/threat-report --output iocs.json
```

### Save output as CSV

```bash
python scraper_bot.py https://example.com/threat-report --output iocs.csv --format csv
```

### Save both JSON and CSV

```bash
python scraper_bot.py https://example.com/threat-report --output iocs --format both
```

### Save as Markdown

```bash
python scraper_bot.py https://example.com/threat-report --output iocs --format markdown
```

### Save all formats (JSON + CSV + Markdown)

```bash
python scraper_bot.py https://example.com/threat-report --output iocs --format all
```

### Add threat hunt context (improves Claude's analysis)

```bash
python scraper_bot.py https://example.com/threat-report --context "Lazarus Group campaign targeting finance sector"
```

### Skip `https://` — it will be prepended automatically

```bash
python scraper_bot.py example.com/threat-report
```

---

## Command-Line Arguments

| Argument | Short | Description | Default |
|---|---|---|---|
| `url` | — | Threat intel URL to scrape *(required)* | — |
| `--output` | `-o` | Output file path (e.g. `iocs.json`, `iocs.csv`, or just `iocs` for both) | None (print only) |
| `--format` | `-f` | Output format: `json`, `csv`, `markdown`, `both` (json+csv), or `all` (json+csv+markdown) | `json` |
| `--context` | `-c` | Free-text threat hunt context to guide Claude's analysis | *(empty)* |

---

## Output

### Terminal Report

The terminal report is printed in a structured format:

```
======================================================================
  IOC THREAT INTELLIGENCE REPORT
  Source : https://example.com/report
  Generated: 2026-03-12 14:00 UTC
======================================================================

SUMMARY
  Lazarus Group deployed a new RAT targeting financial institutions...

THREAT ACTOR
  Lazarus Group

MALWARE FAMILIES
  BlindingCan, COPPERHEDGE

TARGETED SECTORS
  Financial Services, Banking

CVEs (1)
  [HIGH  ] CVE-2024-12345        Exploited for initial access

MITRE ATT&CK TECHNIQUES (3)
  T1566.001    Spearphishing Attachment         Used in initial intrusion
  T1055        Process Injection                Evades AV detection
  T1071.001    Web Protocols                    C2 communication

IPv4 ADDRESSES (2)
  [HIGH  ] 192.0.2.1              C2 server
  [MEDIUM] 198.51.100.4           Staging server

SHA256 HASHES (1)
  [HIGH  ] a1b2c3d4...            Dropper binary

TLP         : AMBER
Reliability : high
======================================================================
```

### JSON Output

The JSON file contains the full structured result including all IOC lists with value, context, and confidence fields, plus metadata fields like `threat_actor`, `malware_families`, `mitre_techniques`, `tlp`, and `source_reliability`.

### CSV Output

The CSV is a flat table with these columns:

| Column | Description |
|---|---|
| `type` | IOC type (e.g. `ipv4`, `sha256`, `domain`, `mitre_technique`) |
| `value` | The IOC value |
| `context` | How the IOC was used or described in the report |
| `confidence` | `high`, `medium`, or `low` |
| `threat_actor` | Attributed threat actor (if any) |
| `malware_family` | Associated malware families |
| `source_url` | URL the IOC was extracted from |
| `extracted_at` | ISO 8601 timestamp |

---

## How It Works

1. **Scrape** — Playwright launches a headless Chromium browser, navigates to the URL, waits for the page to fully load, and extracts the visible text content plus any code/pre blocks. Scripts, styles, and SVGs are removed. Content is capped at 60,000 characters.

2. **Regex Pre-extraction** — 15 regex patterns run across the scraped text to identify IOC candidates. Private/loopback IPs are filtered out. Results are passed to Claude as hints.

3. **Claude Analysis** — The full page text and regex candidates are sent to `claude-opus-4-6` with extended thinking enabled. Claude refangs defanged IOCs, assigns confidence levels, and returns a structured JSON response.

4. **Output** — Results are printed to the terminal and optionally saved as JSON and/or CSV.

---

## Notes

- **Defanged IOCs** — The tool automatically refangs common obfuscation patterns: `[.]` → `.`, `[:]` → `:`, `hxxp://` → `http://`, `hxxps://` → `https://`.
- **Private IPs** — RFC 1918 addresses (10.x.x.x, 172.16–31.x.x, 192.168.x.x) and loopback addresses are excluded from IPv4 results.
- **Content limit** — Pages are truncated at 60,000 characters to stay within model context limits.
- **API costs** — Each run makes one call to `claude-opus-4-6` with up to 8,096 output tokens. Longer pages with more IOCs will use more tokens.
- **TLP handling** — Claude assigns a Traffic Light Protocol (TLP) level based on the report's own stated classification, defaulting to WHITE if unspecified.
