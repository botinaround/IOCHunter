"""
IOC Hunter — Streamlit Web Interface
Run with: streamlit run app.py
"""

import asyncio
import threading
import json
import datetime
import os
import hashlib
import streamlit as st

from scraper_bot import (
    scrape_page,
    pre_extract_iocs,
    analyze_iocs_with_claude,
    to_csv,
    to_markdown,
)

# ---------------------------------------------------------------------------
# Auth — API key gate
# ---------------------------------------------------------------------------

def _load_valid_keys() -> set:
    """
    Load valid API keys from the IOC_HUNTER_API_KEYS environment variable.
    Set it to a comma-separated list of keys, e.g.:
      export IOC_HUNTER_API_KEYS="key-abc123,key-xyz789"
    """
    raw = os.environ.get("IOC_HUNTER_API_KEYS", "")
    return {k.strip() for k in raw.split(",") if k.strip()}


def _check_key(key: str) -> bool:
    valid = _load_valid_keys()
    if not valid:
        # No keys configured — block all access
        return False
    # Constant-time comparison via hash to avoid timing attacks
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return any(
        hashlib.sha256(v.encode()).hexdigest() == key_hash for v in valid
    )


def require_auth():
    """Renders the login gate. Returns only when the session is authenticated."""
    if st.session_state.get("authenticated"):
        return

    st.title("🔒 IOC Hunter")
    st.caption("Enter your API key to continue.")

    with st.form("auth_form"):
        key_input = st.text_input("API Key", type="password", placeholder="key-...")
        submitted = st.form_submit_button("Unlock", use_container_width=True)

    if submitted:
        if _check_key(key_input):
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Invalid API key.")

    st.stop()

# ---------------------------------------------------------------------------
# Page config — must be the very first st call, before auth gate
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="IOC Hunter",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

require_auth()

# ---------------------------------------------------------------------------
# Sidebar — inputs
# ---------------------------------------------------------------------------

with st.sidebar:
    st.title("🔍 IOC Hunter")
    st.caption("AI-Powered Threat Intelligence Scraper")
    st.divider()

    mode = st.radio(
        "Input Mode",
        ["Scrape URL", "Paste Text"],
        horizontal=True,
        help="Scrape a live URL, or paste article text directly (useful for paywalled/bot-protected pages)",
    )

    if mode == "Scrape URL":
        url_input = st.text_input(
            "Threat Intel URL",
            placeholder="https://example.com/threat-report",
            help="Blog post, advisory, or threat report URL to scrape",
        )
        pasted_text = ""
        source_label_input = ""
    else:
        pasted_text = st.text_area(
            "Paste Article Text",
            placeholder="Paste the full article or report text here...",
            height=250,
            help="Copy and paste the article content directly to bypass bot protection or paywalls",
        )
        source_label_input = st.text_input(
            "Source URL / Label (optional)",
            placeholder="https://example.com/threat-report",
            help="Used for attribution in the report — does not fetch the URL",
        )
        url_input = ""

    context_input = st.text_area(
        "Threat Hunt Context (optional)",
        placeholder="e.g. Lazarus Group campaign targeting finance sector",
        height=80,
        help="Additional context to guide Claude's IOC analysis",
    )

    st.divider()
    st.subheader("Output Options")

    dl_json = st.checkbox("JSON", value=True)
    dl_csv = st.checkbox("CSV", value=True)
    dl_md = st.checkbox("Markdown", value=True)

    st.divider()
    run_button = st.button("Run IOC Hunter", type="primary", use_container_width=True)

    st.divider()
    if st.button("Logout", use_container_width=True):
        st.session_state["authenticated"] = False
        st.rerun()

# ---------------------------------------------------------------------------
# Helper — render IOC tables
# ---------------------------------------------------------------------------

IOC_TYPE_LABELS = [
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

CONFIDENCE_COLORS = {"high": "🟢", "medium": "🟡", "low": "🔴"}


def render_results(data: dict, source_url: str):
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # --- Header metrics ---
    iocs = data.get("iocs", {})
    total_iocs = sum(len(v) for v in iocs.values())
    total_mitre = len(data.get("mitre_techniques", []))

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total IOCs", total_iocs)
    col2.metric("MITRE Techniques", total_mitre)
    col3.metric("TLP", data.get("tlp", "N/A"))
    col4.metric("Reliability", data.get("source_reliability", "N/A").capitalize())

    st.divider()

    # --- Tabs ---
    tab_summary, tab_iocs, tab_mitre, tab_raw = st.tabs(
        ["Summary", "IOCs", "MITRE ATT&CK", "Raw JSON"]
    )

    with tab_summary:
        if data.get("summary"):
            st.info(data["summary"])

        cols = st.columns(2)
        with cols[0]:
            if data.get("threat_actor"):
                st.markdown(f"**Threat Actor:** {data['threat_actor']}")
            if data.get("malware_families"):
                st.markdown(f"**Malware Families:** {', '.join(data['malware_families'])}")
            if data.get("campaigns"):
                st.markdown(f"**Campaigns:** {', '.join(data['campaigns'])}")
        with cols[1]:
            if data.get("targeted_sectors"):
                st.markdown(f"**Targeted Sectors:** {', '.join(data['targeted_sectors'])}")
            if data.get("targeted_countries"):
                st.markdown(f"**Targeted Countries:** {', '.join(data['targeted_countries'])}")
            if data.get("first_seen"):
                st.markdown(f"**First Seen:** {data['first_seen']}")
            if data.get("last_seen"):
                st.markdown(f"**Last Seen:** {data['last_seen']}")

        st.caption(f"Source: {source_url} | Generated: {ts}")

    with tab_iocs:
        has_any = False
        for key, label in IOC_TYPE_LABELS:
            entries = iocs.get(key, [])
            if not entries:
                continue
            has_any = True
            with st.expander(f"{label} ({len(entries)})", expanded=len(entries) <= 10):
                rows = []
                for e in entries:
                    if isinstance(e, dict):
                        conf = e.get("confidence", "?")
                        icon = CONFIDENCE_COLORS.get(conf, "⚪")
                        rows.append({
                            "Confidence": f"{icon} {conf}",
                            "Value": e.get("value", ""),
                            "Context": e.get("context", ""),
                        })
                    else:
                        rows.append({"Confidence": "", "Value": e, "Context": ""})
                st.dataframe(rows, use_container_width=True, hide_index=True)

        if not has_any:
            st.warning("No IOCs were extracted.")

    with tab_mitre:
        techniques = data.get("mitre_techniques", [])
        if techniques:
            rows = [
                {
                    "ID": t.get("id", ""),
                    "Name": t.get("name", ""),
                    "Context": t.get("context", ""),
                }
                for t in techniques
            ]
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.info("No MITRE ATT&CK techniques identified.")

    with tab_raw:
        st.json(data)


# ---------------------------------------------------------------------------
# Main — run analysis
# ---------------------------------------------------------------------------

st.title("IOC Hunter")
st.caption("Scrape a threat intelligence URL or paste article text directly, then click **Run IOC Hunter**.")

if run_button:
    if mode == "Scrape URL" and not url_input.strip():
        st.error("Please enter a URL in the sidebar.")
        st.stop()
    if mode == "Paste Text" and not pasted_text.strip():
        st.error("Please paste some article text in the sidebar.")
        st.stop()

    result = None

    with st.status("Running IOC Hunter...", expanded=True) as status:
        if mode == "Paste Text":
            url = source_label_input.strip() or "pasted-text"
            scraped = {
                "url": url,
                "title": source_label_input.strip() or "Pasted Text",
                "meta_description": "",
                "text": pasted_text.strip()[:60000],
            }
            st.write(f"Loaded pasted text — **{len(scraped['text']):,}** characters")
        else:
            url = url_input.strip()
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            st.write(f"Scraping `{url}`...")
            try:
                result_holder = {}

                def run_scrape():
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        result_holder["data"] = loop.run_until_complete(scrape_page(url))
                    except Exception as e:
                        result_holder["error"] = e
                    finally:
                        loop.close()

                t = threading.Thread(target=run_scrape)
                t.start()
                t.join()

                if "error" in result_holder:
                    raise result_holder["error"]
                scraped = result_holder["data"]
            except Exception as e:
                st.error(f"Scraping failed: {e}")
                st.stop()

            st.write(
                f"Scraped **{scraped['title']}** — "
                f"{len(scraped['text']):,} characters"
            )

        st.write("Running regex pre-extraction...")
        pre = pre_extract_iocs(scraped["text"])
        total_candidates = sum(len(v) for v in pre.values())
        st.write(
            f"Found **{total_candidates}** IOC candidates across "
            f"**{len(pre)}** types"
        )

        st.write("Sending to Claude for deep analysis...")
        try:
            result = analyze_iocs_with_claude(scraped, pre, context_input.strip())
        except Exception as e:
            st.error(f"Claude analysis failed: {e}")
            st.stop()

        status.update(label="Analysis complete!", state="complete", expanded=False)

    render_results(result, url)

    # --- Download buttons ---
    if result and (dl_json or dl_csv or dl_md):
        st.divider()
        st.subheader("Download Results")
        base = "iocs"
        dl_cols = st.columns(3)

        if dl_json:
            dl_cols[0].download_button(
                label="Download JSON",
                data=json.dumps(result, indent=2),
                file_name=f"{base}.json",
                mime="application/json",
                use_container_width=True,
            )

        if dl_csv:
            dl_cols[1].download_button(
                label="Download CSV",
                data=to_csv(result, url),
                file_name=f"{base}.csv",
                mime="text/csv",
                use_container_width=True,
            )

        if dl_md:
            dl_cols[2].download_button(
                label="Download Markdown",
                data=to_markdown(result, url),
                file_name=f"{base}.md",
                mime="text/markdown",
                use_container_width=True,
            )
