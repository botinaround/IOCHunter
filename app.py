"""
IOC Hunter — Navigation controller and authentication.
Run with: streamlit run app.py
"""

import os
import hashlib
import yaml
import streamlit as st
from oauth_google import build_auth_url, generate_state, exchange_code, get_userinfo

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
# Google OAuth2 config
# ---------------------------------------------------------------------------

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

with open(CONFIG_PATH) as f:
    config = yaml.safe_load(f)

_GOOGLE_CLIENT_ID     = config["oauth2"]["google"]["client_id"]
_GOOGLE_CLIENT_SECRET = config["oauth2"]["google"]["client_secret"]
_GOOGLE_REDIRECT_URI  = config["oauth2"]["google"]["redirect_uri"]

# ---------------------------------------------------------------------------
# Handle Google OAuth callback (runs on every page load)
# ---------------------------------------------------------------------------

_qp = st.query_params
if "code" in _qp and not st.session_state.get("authentication_status"):
    _code  = _qp["code"]
    _state = _qp.get("state", "")
    if _state == st.session_state.get("oauth_state", ""):
        try:
            tokens   = exchange_code(_code, _GOOGLE_CLIENT_ID, _GOOGLE_CLIENT_SECRET, _GOOGLE_REDIRECT_URI)
            userinfo = get_userinfo(tokens["access_token"])
            _email   = userinfo.get("email", "")
            _name    = userinfo.get("name") or _email.split("@")[0]
            st.session_state["authentication_status"] = True
            st.session_state["name"]        = _name
            st.session_state["username"]    = _email
            st.session_state["access_tier"] = "google"
            st.query_params.clear()
            st.rerun()
        except Exception as _e:
            st.query_params.clear()
            st.session_state["oauth_error"] = str(_e)
            st.rerun()
    else:
        st.query_params.clear()
        st.rerun()

# ---------------------------------------------------------------------------
# Access key helpers
# ---------------------------------------------------------------------------

def _valid_access_keys() -> set:
    raw = os.environ.get("IOC_HUNTER_API_KEYS", "")
    return {k.strip() for k in raw.split(",") if k.strip()}

def _check_access_key(key: str) -> bool:
    valid = _valid_access_keys()
    if not valid:
        return False
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return any(hashlib.sha256(v.encode()).hexdigest() == key_hash for v in valid)

# ---------------------------------------------------------------------------
# Login page — shown only when not authenticated
# ---------------------------------------------------------------------------

if not st.session_state.get("authentication_status") and not st.session_state.get("key_authenticated"):

    st.markdown("""
    <style>
        [data-testid="stSidebar"] {display: none;}
        .login-container {
            max-width: 500px;
            margin: 48px auto 0 auto;
            padding: 40px;
            background: #0e1117;
            border: 1px solid #2d2d2d;
            border-radius: 12px;
        }
        .login-logo { font-size: 52px; text-align: center; margin-bottom: 8px; }
        .login-title {
            font-size: 32px; font-weight: 700; text-align: center;
            color: #ffffff; margin: 0; letter-spacing: -0.5px;
        }
        .login-subtitle {
            text-align: center; color: #8b8b8b;
            font-size: 15px; margin-top: 6px; margin-bottom: 28px;
        }
        .login-divider { border: none; border-top: 1px solid #2d2d2d; margin: 24px 0; }
        .login-features { display: flex; flex-direction: column; gap: 10px; margin-bottom: 28px; }
        .login-feature { display: flex; align-items: center; gap: 12px; color: #c0c0c0; font-size: 14px; }
        .login-feature-icon { font-size: 18px; width: 28px; text-align: center; }
        .tier-label {
            font-size: 11px; font-weight: 600; letter-spacing: 0.08em;
            text-transform: uppercase; color: #8b8b8b; margin-bottom: 8px;
        }
    </style>

    <div class="login-container">
        <div class="login-logo">🔍</div>
        <h1 class="login-title">IOC Hunter</h1>
        <p class="login-subtitle">AI-Powered Threat Intelligence Platform</p>
        <hr class="login-divider"/>
        <div class="login-features">
            <div class="login-feature"><span class="login-feature-icon">🎯</span><span>Extract IOCs from any threat intelligence source</span></div>
            <div class="login-feature"><span class="login-feature-icon">🧠</span><span>AI-powered deep analysis with confidence scoring</span></div>
            <div class="login-feature"><span class="login-feature-icon">🕵️</span><span>Threat hunt playbooks with detection queries</span></div>
            <div class="login-feature"><span class="login-feature-icon">📊</span><span>Executive reports for leadership briefings</span></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    _, center_col, _ = st.columns([1, 2, 1])
    with center_col:

        # --- Access Key login (uses server API key) ---
        st.markdown('<p class="tier-label">🔑 Access Key — Includes API Credits</p>', unsafe_allow_html=True)
        with st.form("key_login_form"):
            access_key_input = st.text_input(
                "Access Key",
                type="password",
                placeholder="key-...",
                label_visibility="collapsed",
            )
            key_submit = st.form_submit_button("Login with Access Key", use_container_width=True, type="primary")

        if key_submit:
            if _check_access_key(access_key_input):
                st.session_state["key_authenticated"] = True
                st.session_state["authentication_status"] = True
                st.session_state["name"] = "Key User"
                st.session_state["username"] = "key_user"
                st.session_state["access_tier"] = "key"
                st.rerun()
            else:
                st.error("Invalid access key.")

        st.markdown('<hr class="login-divider"/>', unsafe_allow_html=True)

        # --- BYO API Key login (Google OAuth or email fallback) ---
        st.markdown('<p class="tier-label">🌐 Bring Your Own API Key</p>', unsafe_allow_html=True)

        if st.session_state.get("oauth_error"):
            st.error(f"Google sign-in failed: {st.session_state.pop('oauth_error')}")

        _state = generate_state()
        st.session_state["oauth_state"] = _state
        _auth_url = build_auth_url(_GOOGLE_CLIENT_ID, _GOOGLE_REDIRECT_URI, _state)
        st.link_button("Sign in with Google", _auth_url, use_container_width=True, type="primary")

        st.markdown('<p style="text-align:center;color:#555;font-size:11px;margin:10px 0;">— or continue with email —</p>', unsafe_allow_html=True)

        with st.form("byok_login_form"):
            byok_email = st.text_input(
                "Email",
                placeholder="you@example.com",
                label_visibility="collapsed",
            )
            byok_submit = st.form_submit_button("Continue with Email", use_container_width=True)

        if byok_submit:
            email = byok_email.strip().lower()
            if not email or "@" not in email:
                st.error("Enter a valid email address.")
            else:
                st.session_state["authentication_status"] = True
                st.session_state["name"] = email.split("@")[0]
                st.session_state["username"] = email
                st.session_state["access_tier"] = "google"
                st.rerun()

        st.markdown("""
        <p style="text-align:center; color:#555; font-size:11px; margin-top:16px;">
            Don't have an access key? Sign in above and use your own API key.<br/>
            Contact your administrator to request an access key.
        </p>
        """, unsafe_allow_html=True)

        if st.button("Privacy Policy", use_container_width=True, type="secondary"):
            st.switch_page("pages/privacy_policy.py")

    st.stop()

# Fallback: ensure access_tier is always set for authenticated users
if st.session_state.get("authentication_status") and not st.session_state.get("access_tier"):
    st.session_state["access_tier"] = "google"

# ---------------------------------------------------------------------------
# Navigation — defines sidebar order and page labels
# ---------------------------------------------------------------------------

pg = st.navigation([
    st.Page("pages/threat_intel_hunter.py", title="Threat Intel Hunter", icon="🔍", default=True),
    st.Page("pages/historical_runs.py",     title="Historical Runs",     icon="🗄️"),
    st.Page("pages/ip_domain_lookups.py",   title="IP/Domain Lookups",   icon="🔎"),
    st.Page("pages/privacy_policy.py",      title="Privacy Policy",      icon="🔒"),
])
pg.run()
