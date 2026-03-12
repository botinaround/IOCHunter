"""
IOC Hunter — Cache Viewer
"""

import json
import datetime
import streamlit as st
from cache import get_all_entries, get_stats, delete_entry, clear_expired, clear_all, get_cached

st.set_page_config(page_title="Cache Viewer — IOC Hunter", page_icon="🗄️", layout="wide")

# Auth gate — reuse same session state as main app
if not st.session_state.get("authentication_status"):
    st.warning("Please log in from the main page first.")
    st.stop()

st.title("🗄️ Cache Viewer")
st.caption("Browse, inspect, and manage cached analysis results.")

# --- Stats ---
stats = get_stats()
col1, col2, col3 = st.columns(3)
col1.metric("Total Entries", stats["total"])
col2.metric("Active (not expired)", stats["active"])
col3.metric("Expired", stats["expired"])

st.divider()

# --- Management buttons ---
mgmt_col1, mgmt_col2 = st.columns([1, 1])
with mgmt_col1:
    if st.button("🧹 Clear Expired Entries", use_container_width=True):
        removed = clear_expired()
        st.success(f"Removed {removed} expired entries.")
        st.rerun()
with mgmt_col2:
    if st.button("🗑️ Clear Entire Cache", type="secondary", use_container_width=True):
        clear_all()
        st.success("Cache cleared.")
        st.rerun()

st.divider()

# --- Entry table ---
entries = get_all_entries()

if not entries:
    st.info("No cached entries yet. Run an analysis on the main page to populate the cache.")
else:
    now = datetime.datetime.utcnow().isoformat()

    REPORT_ICONS = {
        "Technical IOC Report": "🔬",
        "Threat Hunt Report":   "🎯",
        "Executive Report":     "📊",
    }

    for entry in entries:
        expired = entry["expires_at"] < now
        icon = REPORT_ICONS.get(entry["report_type"], "📄")
        status_badge = "🔴 Expired" if expired else "🟢 Active"
        created = entry["created_at"][:16].replace("T", " ") + " UTC"
        expires = entry["expires_at"][:16].replace("T", " ") + " UTC"

        with st.expander(
            f"{icon} {entry['report_type']}  |  {entry['url'][:80]}{'...' if len(entry['url']) > 80 else ''}  |  {status_badge}",
            expanded=False,
        ):
            col_a, col_b, col_c = st.columns(3)
            col_a.markdown(f"**URL:** {entry['url']}")
            col_b.markdown(f"**Created:** {created}")
            col_c.markdown(f"**Expires:** {expires}")

            # Load and show the result
            result = get_cached(entry["url"], entry["report_type"])
            if result:
                tab_preview, tab_json = st.tabs(["Preview", "Raw JSON"])

                with tab_preview:
                    if result.get("summary"):
                        st.info(result["summary"])
                    if result.get("headline"):
                        st.subheader(result["headline"])
                    if result.get("threat_actor"):
                        st.markdown(f"**Threat Actor:** {result['threat_actor']}")
                    if result.get("malware_families"):
                        st.markdown(f"**Malware Families:** {', '.join(result['malware_families'])}")
                    if result.get("risk_level"):
                        st.markdown(f"**Risk Level:** {result['risk_level'].capitalize()}")
                    if result.get("priority"):
                        st.markdown(f"**Priority:** {result['priority'].capitalize()}")

                with tab_json:
                    st.json(result)
            else:
                st.warning("Entry is expired — raw data no longer returned by cache.")
                st.json({"id": entry["id"], "url": entry["url"], "report_type": entry["report_type"]})

            if st.button(f"🗑️ Delete this entry", key=f"del_{entry['id']}"):
                delete_entry(entry["id"])
                st.success("Entry deleted.")
                st.rerun()
