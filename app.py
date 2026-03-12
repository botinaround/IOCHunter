"""
IOC Hunter — Streamlit Web Interface
Run with: streamlit run app.py
"""

import asyncio
import threading
import json
import datetime
import os
import yaml
import streamlit as st
import streamlit_authenticator as stauth

from scraper_bot import (
    scrape_page,
    pre_extract_iocs,
    analyze_iocs_with_claude,
    analyze_threat_hunt_with_claude,
    analyze_executive_with_claude,
    to_csv,
    to_markdown,
)
from cache import get_cached, save_cache

# ---------------------------------------------------------------------------
# Page config — must be first st call
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="IOC Hunter",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Auth — Google OAuth2 via streamlit-authenticator
# ---------------------------------------------------------------------------

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

with open(CONFIG_PATH) as f:
    config = yaml.safe_load(f)

authenticator = stauth.Authenticate(
    config["credentials"],
    config["cookie"]["name"],
    config["cookie"]["key"],
    config["cookie"]["expiry_days"],
)

# Save config after every run so new OAuth2 users are persisted
with open(CONFIG_PATH, "w") as f:
    yaml.dump(config, f, default_flow_style=False)

# Gate the rest of the app
if not st.session_state.get("authentication_status"):
    st.markdown("""
    <style>
        [data-testid="stSidebar"] {display: none;}
        .login-container {
            max-width: 480px;
            margin: 60px auto 0 auto;
            padding: 48px 40px;
            background: #0e1117;
            border: 1px solid #2d2d2d;
            border-radius: 12px;
        }
        .login-logo {
            font-size: 52px;
            text-align: center;
            margin-bottom: 8px;
        }
        .login-title {
            font-size: 32px;
            font-weight: 700;
            text-align: center;
            color: #ffffff;
            margin: 0;
            letter-spacing: -0.5px;
        }
        .login-subtitle {
            text-align: center;
            color: #8b8b8b;
            font-size: 15px;
            margin-top: 6px;
            margin-bottom: 32px;
        }
        .login-divider {
            border: none;
            border-top: 1px solid #2d2d2d;
            margin: 28px 0;
        }
        .login-features {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-bottom: 32px;
        }
        .login-feature {
            display: flex;
            align-items: center;
            gap: 12px;
            color: #c0c0c0;
            font-size: 14px;
        }
        .login-feature-icon {
            font-size: 18px;
            width: 28px;
            text-align: center;
        }
        .login-footer {
            text-align: center;
            color: #555;
            font-size: 12px;
            margin-top: 28px;
        }
    </style>

    <div class="login-container">
        <div class="login-logo">🔍</div>
        <h1 class="login-title">IOC Hunter</h1>
        <p class="login-subtitle">AI-Powered Threat Intelligence Platform</p>
        <hr class="login-divider"/>
        <div class="login-features">
            <div class="login-feature">
                <span class="login-feature-icon">🎯</span>
                <span>Extract IOCs from any threat intelligence source</span>
            </div>
            <div class="login-feature">
                <span class="login-feature-icon">🧠</span>
                <span>Claude AI-powered deep analysis with confidence scoring</span>
            </div>
            <div class="login-feature">
                <span class="login-feature-icon">🕵️</span>
                <span>Threat hunt playbooks with detection queries</span>
            </div>
            <div class="login-feature">
                <span class="login-feature-icon">📊</span>
                <span>Executive reports for leadership briefings</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Center the login button
    _, center_col, _ = st.columns([1, 2, 1])
    with center_col:
        try:
            authenticator.experimental_guest_login(
                "Sign in with Google",
                provider="google",
                oauth2=config["oauth2"],
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"Login error: {e}")

    st.markdown("""
    <p style="text-align:center; color:#555; font-size:12px; margin-top:24px;">
        Access is restricted to authorized users only.<br/>
        Contact your administrator if you need access.
    </p>
    """, unsafe_allow_html=True)

    _, link_col, _ = st.columns([1, 2, 1])
    with link_col:
        if st.button("Privacy Policy", use_container_width=True, type="secondary"):
            st.switch_page("pages/2_Privacy_Policy.py")

    st.stop()

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

    report_type = st.radio(
        "Report Type",
        ["Technical IOC Report", "Threat Hunt Report", "Executive Report"],
        help=(
            "**Technical IOC Report** — Full IOC extraction with hashes, IPs, domains, MITRE techniques\n\n"
            "**Threat Hunt Report** — Hunting hypotheses, step-by-step playbook, detection queries\n\n"
            "**Executive Report** — Plain-English briefing for leadership with business impact and recommended actions"
        ),
    )

    st.divider()

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

    force_rerun = st.checkbox(
        "Force re-run (bypass cache)",
        value=False,
        help="Results are cached for 7 days. Check this to force a fresh analysis.",
    )

    st.divider()
    run_button = st.button("Run IOC Hunter", type="primary", use_container_width=True)

    st.divider()
    st.caption(f"Signed in as **{st.session_state.get('name', '')}**")
    authenticator.logout(button_name="Logout", location="sidebar", use_container_width=True)

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


def render_threat_hunt(data: dict):
    PRIORITY_COLORS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    priority = data.get("priority", "unknown")
    icon = PRIORITY_COLORS.get(priority, "⚪")

    col1, col2, col3 = st.columns(3)
    col1.metric("Priority", f"{icon} {priority.capitalize()}")
    col2.metric("Hunting Steps", len(data.get("hunting_steps", [])))
    col3.metric("Detection Opportunities", len(data.get("detection_opportunities", [])))

    st.divider()

    tab_overview, tab_steps, tab_iocs, tab_detections, tab_mitigations, tab_raw = st.tabs(
        ["Overview", "Hunt Steps", "IOCs to Hunt", "Detections", "Mitigations", "Raw JSON"]
    )

    with tab_overview:
        if data.get("summary"):
            st.info(data["summary"])

        cols = st.columns(2)
        with cols[0]:
            if data.get("threat_actor"):
                st.markdown(f"**Threat Actor:** {data['threat_actor']}")
            if data.get("malware_families"):
                st.markdown(f"**Malware Families:** {', '.join(data['malware_families'])}")
        with cols[1]:
            if data.get("affected_log_sources"):
                st.markdown("**Relevant Log Sources:**")
                for src in data["affected_log_sources"]:
                    st.markdown(f"- **{src.get('source','')}** — {src.get('relevance','')}")

        if data.get("hunting_hypotheses"):
            st.markdown("**Hunting Hypotheses:**")
            for h in data["hunting_hypotheses"]:
                st.markdown(f"> {h}")

        if data.get("false_positive_considerations"):
            st.markdown("**False Positive Considerations:**")
            for fp in data["false_positive_considerations"]:
                st.markdown(f"- {fp}")

    with tab_steps:
        for step in data.get("hunting_steps", []):
            with st.expander(f"Step {step.get('step','')} — {step.get('title','')}", expanded=True):
                st.markdown(step.get("description", ""))
                if step.get("log_sources"):
                    st.caption(f"Log sources: {', '.join(step['log_sources'])}")
                for q in step.get("queries", []):
                    st.markdown(f"**{q.get('platform','')}**")
                    st.code(q.get("query", ""), language="splunk" if "Splunk" in q.get("platform","") else "text")
                    if q.get("notes"):
                        st.caption(q["notes"])

    with tab_iocs:
        iocs = data.get("iocs_to_hunt", {})
        for key, label in [("ips","IP Addresses"), ("domains","Domains"), ("hashes","Hashes"),
                           ("filenames","Filenames"), ("registry_keys","Registry Keys"), ("other","Other")]:
            entries = iocs.get(key, [])
            if entries:
                st.markdown(f"**{label}**")
                for e in entries:
                    st.code(e, language="text")

    with tab_detections:
        detections = data.get("detection_opportunities", [])
        if detections:
            rows = [{"Technique": d.get("technique",""), "Behaviour": d.get("description",""),
                     "Log Source": d.get("log_source","")} for d in detections]
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.info("No detection opportunities identified.")

    with tab_mitigations:
        mitigations = data.get("recommended_mitigations", [])
        if mitigations:
            for i, m in enumerate(mitigations, 1):
                st.markdown(f"{i}. {m}")
        else:
            st.info("No mitigations identified.")

    with tab_raw:
        st.json(data)


def render_executive(data: dict):
    RISK_COLORS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    risk = data.get("risk_level", "unknown")
    icon = RISK_COLORS.get(risk, "⚪")

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk Level", f"{icon} {risk.capitalize()}")
    col2.metric("Attack Type", data.get("attack_type", "N/A"))
    col3.metric("Threat Actor", data.get("threat_actor") or "Unknown")

    st.divider()

    tab_brief, tab_actions, tab_questions, tab_raw = st.tabs(
        ["Briefing", "Recommended Actions", "Questions for Your Team", "Raw JSON"]
    )

    with tab_brief:
        if data.get("headline"):
            st.subheader(data["headline"])

        if data.get("summary"):
            st.info(data["summary"])

        if data.get("risk_justification"):
            st.markdown(f"**Why this risk level:** {data['risk_justification']}")

        cols = st.columns(2)
        with cols[0]:
            if data.get("affected_sectors"):
                st.markdown(f"**Affected Sectors:** {', '.join(data['affected_sectors'])}")
            if data.get("affected_regions"):
                st.markdown(f"**Affected Regions:** {', '.join(data['affected_regions'])}")
            if data.get("timeline"):
                st.markdown(f"**Timeline:** {data['timeline']}")
        with cols[1]:
            if data.get("business_impact"):
                st.markdown(f"**Business Impact:** {data['business_impact']}")

        if data.get("what_happened"):
            st.markdown("**What Happened:**")
            for point in data["what_happened"]:
                st.markdown(f"- {point}")

        if data.get("key_takeaways"):
            st.markdown("**Key Takeaways:**")
            for t in data["key_takeaways"]:
                st.markdown(f"- {t}")

    with tab_actions:
        actions = data.get("recommended_actions", [])
        if actions:
            for priority in ["immediate", "short-term", "long-term"]:
                group = [a for a in actions if a.get("priority") == priority]
                if group:
                    labels = {"immediate": "🔴 Immediate", "short-term": "🟡 Short-Term", "long-term": "🟢 Long-Term"}
                    st.markdown(f"**{labels[priority]}**")
                    for a in group:
                        st.markdown(f"- {a.get('action','')}")
        else:
            st.info("No recommended actions identified.")

    with tab_questions:
        questions = data.get("questions_to_ask_your_security_team", [])
        if questions:
            for i, q in enumerate(questions, 1):
                st.markdown(f"{i}. {q}")
        else:
            st.info("No questions generated.")

    with tab_raw:
        st.json(data)


# ---------------------------------------------------------------------------
# Main — run analysis
# ---------------------------------------------------------------------------

st.title("IOC Hunter")
st.caption("AI-Powered Threat Intelligence Analysis")

with st.expander("How to Use", expanded=False):
    st.markdown("""
### Getting Started

**1. Choose your input mode** (sidebar)
- **Scrape URL** — paste a link to a threat intel blog post, security advisory, or report and the tool will fetch and analyse it automatically.
- **Paste Text** — if a page is behind a paywall or bot protection (e.g. Cloudflare), copy the article text from your browser and paste it directly. Optionally add the source URL for attribution.

---

### Report Types

| Report | Best For |
|---|---|
| **Technical IOC Report** | SOC analysts and incident responders who need raw indicators — IPs, hashes, domains, CVEs, MITRE techniques |
| **Threat Hunt Report** | Threat hunters who need hypotheses, step-by-step hunting playbooks, detection queries, and log sources |
| **Executive Report** | Leadership and non-technical stakeholders — plain English summary, business impact, risk level, and recommended actions |

---

### Tips

- **Threat Hunt Context** — add extra context in the sidebar (e.g. *"APT29 targeting energy sector"*) to focus Claude's analysis on what matters to your environment.
- **Bot-protected sites** — if scraping fails with a Cloudflare or login error, switch to **Paste Text** mode and copy the article manually.
- **Downloads** — after analysis completes, use the download buttons to export results as JSON, CSV (Technical report only), or Markdown.
- **Confidence levels** — IOCs are rated 🟢 High / 🟡 Medium / 🔴 Low based on how explicitly the source attributes each indicator.
""")

if run_button:
    if mode == "Scrape URL" and not url_input.strip():
        st.error("Please enter a URL in the sidebar.")
        st.stop()
    if mode == "Paste Text" and not pasted_text.strip():
        st.error("Please paste some article text in the sidebar.")
        st.stop()

    # Clear previous result when a new run starts
    st.session_state.pop("result", None)
    st.session_state.pop("result_url", None)
    st.session_state.pop("result_report_type", None)

    result = None
    from_cache = False

    # Check cache first (only for URL mode — pasted text is never cached)
    if mode == "Scrape URL" and not force_rerun:
        cached_url = url_input.strip()
        if not cached_url.startswith(("http://", "https://")):
            cached_url = "https://" + cached_url
        cached = get_cached(cached_url, report_type)
        if cached:
            result = cached
            from_cache = True

    if from_cache:
        st.success("Loaded from cache (analysis within the last 7 days). Check **Force re-run** to refresh.")
        url = cached_url
    else:
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

            # Regex pre-extraction only needed for technical/hunt reports
            pre = {}
            if report_type in ("Technical IOC Report", "Threat Hunt Report"):
                st.write("Running regex pre-extraction...")
                pre = pre_extract_iocs(scraped["text"])
                total_candidates = sum(len(v) for v in pre.values())
                st.write(
                    f"Found **{total_candidates}** IOC candidates across "
                    f"**{len(pre)}** types"
                )

            report_labels = {
                "Technical IOC Report": "technical IOC extraction",
                "Threat Hunt Report": "threat hunt playbook",
                "Executive Report": "executive briefing",
            }
            st.write(f"Sending to Claude for {report_labels[report_type]}...")
            try:
                if report_type == "Technical IOC Report":
                    result = analyze_iocs_with_claude(scraped, pre, context_input.strip())
                elif report_type == "Threat Hunt Report":
                    result = analyze_threat_hunt_with_claude(scraped, pre, context_input.strip())
                else:
                    result = analyze_executive_with_claude(scraped, context_input.strip())
            except Exception as e:
                st.error(f"Claude analysis failed: {e}")
                st.stop()

            # Save to cache (URL mode only)
            if mode == "Scrape URL":
                save_cache(url, report_type, result)

            status.update(label="Analysis complete!", state="complete", expanded=False)

        # Persist result in session state so interactions don't wipe it
        st.session_state["result"] = result
        st.session_state["result_url"] = url
        st.session_state["result_report_type"] = report_type

# Render whatever is in session state (survives button clicks / radio changes)
result = st.session_state.get("result")
url = st.session_state.get("result_url", "")
saved_report_type = st.session_state.get("result_report_type", report_type)

if result:
    if saved_report_type == "Technical IOC Report":
        render_results(result, url)
    elif saved_report_type == "Threat Hunt Report":
        render_threat_hunt(result)
    else:
        render_executive(result)

    # --- Download buttons ---
    if dl_json:
        st.divider()
        st.subheader("Download Results")
        dl_cols = st.columns(3)

        dl_cols[0].download_button(
            label="Download JSON",
            data=json.dumps(result, indent=2),
            file_name="report.json",
            mime="application/json",
            use_container_width=True,
        )

        if saved_report_type == "Technical IOC Report":
            if dl_csv:
                dl_cols[1].download_button(
                    label="Download CSV",
                    data=to_csv(result, url),
                    file_name="iocs.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
            if dl_md:
                dl_cols[2].download_button(
                    label="Download Markdown",
                    data=to_markdown(result, url),
                    file_name="iocs.md",
                    mime="text/markdown",
                    use_container_width=True,
                )
