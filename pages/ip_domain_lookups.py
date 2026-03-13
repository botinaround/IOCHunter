"""
IOC Hunter — IP Reputation & TLD WHOIS Lookups
"""

import os
import streamlit as st
from lookup import lookup_abuseipdb, lookup_tld_whois

st.set_page_config(
    page_title="Lookups — IOC Hunter",
    page_icon="🔎",
    layout="wide",
)

# Auth gate
if not st.session_state.get("authentication_status"):
    st.warning("Please log in from the main page first.")
    st.stop()

is_key_tier = st.session_state.get("access_tier") == "key"

st.title("🔎 IP & TLD Lookups")
st.caption("Query AbuseIPDB for IP reputation, or look up TLD registry info via IANA WHOIS.")

tab_ip, tab_tld = st.tabs(["🌐 AbuseIPDB — IP Reputation", "🏷️ IANA WHOIS — TLD Lookup"])

# ---------------------------------------------------------------------------
# AbuseIPDB tab
# ---------------------------------------------------------------------------

with tab_ip:
    st.subheader("IP Reputation Lookup")
    st.caption(
        "Check an IP against the AbuseIPDB database for abuse confidence score, "
        "ISP, country of origin, and recent abuse reports."
    )

    col_left, col_right = st.columns([2, 1])

    with col_left:
        ip_input = st.text_input(
            "IP Address",
            placeholder="e.g. 185.220.101.1",
            key="abuseipdb_ip",
        )
        max_age = st.slider(
            "Include reports from the last N days",
            min_value=1,
            max_value=365,
            value=90,
            key="abuseipdb_age",
        )

    with col_right:
        server_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        if is_key_tier and server_key:
            abuseipdb_key = server_key
            st.success("✅ Server AbuseIPDB key in use.")
        else:
            abuseipdb_key = st.text_input(
                "AbuseIPDB API Key",
                type="password",
                placeholder="Free key at abuseipdb.com",
                help="Free tier: 1,000 checks/day. Register at abuseipdb.com.",
                key="abuseipdb_key_input",
            )
            if not abuseipdb_key:
                st.caption("No key? [Get a free one](https://www.abuseipdb.com/register)")

    if st.button("Look Up IP", type="primary", key="abuseipdb_go"):
        if not ip_input.strip():
            st.error("Enter an IP address.")
        elif not abuseipdb_key:
            st.error("Enter an AbuseIPDB API key.")
        else:
            with st.spinner(f"Querying AbuseIPDB for {ip_input.strip()}..."):
                try:
                    data = lookup_abuseipdb(ip_input, abuseipdb_key, max_age)
                    st.session_state["abuseipdb_result"] = data
                except Exception as e:
                    st.error(str(e))
                    st.session_state.pop("abuseipdb_result", None)

    result = st.session_state.get("abuseipdb_result")
    if result:
        st.divider()

        score = result.get("abuseConfidenceScore", 0)
        score_icon = "🔴" if score >= 75 else ("🟡" if score >= 25 else "🟢")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Abuse Score", f"{score_icon} {score}%")
        col2.metric("Country", result.get("countryCode", "N/A"))
        col3.metric("Total Reports", result.get("totalReports", 0))
        col4.metric("Distinct Reporters", result.get("numDistinctUsers", 0))

        st.divider()

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown(f"**IP Address:** `{result.get('ipAddress', '')}`")
            st.markdown(f"**ISP:** {result.get('isp', 'N/A')}")
            st.markdown(f"**Domain:** {result.get('domain', 'N/A')}")
            st.markdown(f"**Usage Type:** {result.get('usageType', 'N/A')}")
            hostnames = result.get("hostnames", [])
            st.markdown(f"**Hostname:** {hostnames[0] if hostnames else 'N/A'}")
        with col_b:
            st.markdown(f"**Whitelisted:** {'Yes' if result.get('isWhitelisted') else 'No'}")
            st.markdown(f"**TOR Node:** {'Yes' if result.get('isTor') else 'No'}")
            last = result.get("lastReportedAt")
            st.markdown(f"**Last Reported:** {last[:10] if last else 'Never'}")

        reports = result.get("reports", [])
        if reports:
            st.divider()
            st.subheader(f"Recent Reports ({len(reports)})")

            # AbuseIPDB category codes → labels
            _CATEGORIES = {
                1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
                4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
                7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
                10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
                13: "VPN IP", 14: "Port Scan", 15: "Hacking",
                16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
                19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
                22: "SSH", 23: "IoT Targeted",
            }

            rows = []
            for r in reports[:25]:
                cats = r.get("categories", [])
                cat_labels = ", ".join(_CATEGORIES.get(c, str(c)) for c in cats)
                rows.append({
                    "Date": (r.get("reportedAt") or "")[:10],
                    "Categories": cat_labels or "—",
                    "Reporter Country": r.get("reporterCountryCode", ""),
                    "Comment": (r.get("comment") or "")[:150],
                })
            st.dataframe(rows, use_container_width=True, hide_index=True)

        with st.expander("Raw JSON Response"):
            st.json(result)

# ---------------------------------------------------------------------------
# IANA WHOIS tab
# ---------------------------------------------------------------------------

with tab_tld:
    st.subheader("TLD WHOIS Lookup")
    st.caption(
        "Query the IANA WHOIS server (`whois.iana.org`) for Top-Level Domain registry "
        "information — useful for assessing domains used in threat reports. No API key required."
    )

    tld_input = st.text_input(
        "Top-Level Domain",
        placeholder="e.g. ru  |  cn  |  .onion  |  .bank",
        key="tld_input",
        help="Enter a TLD with or without a leading dot.",
    )

    if st.button("Look Up TLD", type="primary", key="tld_go"):
        if not tld_input.strip():
            st.error("Enter a TLD to look up.")
        else:
            with st.spinner(f"Querying IANA WHOIS for .{tld_input.strip().lstrip('.')}..."):
                try:
                    data = lookup_tld_whois(tld_input)
                    st.session_state["tld_result"] = data
                except Exception as e:
                    st.error(str(e))
                    st.session_state.pop("tld_result", None)

    result = st.session_state.get("tld_result")
    if result:
        st.divider()
        st.subheader(f"Results for `{result.get('tld', '')}`")

        _fields = [
            ("organisation", "Organisation / Registry"),
            ("registrar",    "Registrar"),
            ("whois_server", "WHOIS Server"),
            ("status",       "Status"),
            ("created",      "Created"),
            ("changed",      "Last Changed"),
            ("contact",      "Contact"),
            ("source",       "Source"),
        ]

        col_a, col_b = st.columns(2)
        for i, (key, label) in enumerate(_fields):
            if result.get(key):
                col = col_a if i % 2 == 0 else col_b
                col.markdown(f"**{label}:** {result[key]}")

        nservers = result.get("nservers", [])
        if nservers:
            st.markdown("**Name Servers:**")
            for ns in nservers:
                st.markdown(f"- `{ns}`")

        remarks = result.get("remarks", [])
        if remarks:
            st.markdown("**Remarks:**")
            for r in remarks:
                st.markdown(f"- {r}")

        with st.expander("Raw WHOIS Response"):
            st.code(result.get("raw", ""), language="text")
