"""
IOC Hunter — Privacy Policy
Accessible without login.
"""

import streamlit as st
import datetime

st.set_page_config(
    page_title="Privacy Policy — IOC Hunter",
    page_icon="🔒",
    layout="centered",
)

# Hide sidebar if not logged in
if not st.session_state.get("authentication_status"):
    st.markdown("<style>[data-testid='stSidebar'] {display: none;}</style>", unsafe_allow_html=True)

st.markdown("""
<style>
    .privacy-header {
        text-align: center;
        padding: 32px 0 16px 0;
    }
    .privacy-header h1 {
        font-size: 36px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .privacy-header p {
        color: #8b8b8b;
        font-size: 14px;
    }
    .section-card {
        background: #0e1117;
        border: 1px solid #2d2d2d;
        border-radius: 10px;
        padding: 24px 28px;
        margin-bottom: 16px;
    }
    .section-card h3 {
        margin-top: 0;
        font-size: 18px;
        font-weight: 600;
    }
    .section-card p, .section-card li {
        color: #c0c0c0;
        font-size: 14px;
        line-height: 1.7;
    }
    .highlight-box {
        background: #1a1f2e;
        border-left: 3px solid #4a90d9;
        border-radius: 4px;
        padding: 12px 16px;
        margin: 12px 0;
        color: #c0c0c0;
        font-size: 14px;
    }
    .footer-note {
        text-align: center;
        color: #555;
        font-size: 12px;
        margin-top: 32px;
        padding-bottom: 32px;
    }
</style>

<div class="privacy-header">
    <h1>🔒 Privacy Policy</h1>
    <p>IOC Hunter &nbsp;·&nbsp; Last updated: March 2026</p>
</div>

<div class="section-card">
    <h3>Overview</h3>
    <p>
        IOC Hunter is an internal threat intelligence tool that uses AI to extract and
        analyse Indicators of Compromise (IOCs) from threat intelligence sources.
        This policy explains what data we collect, how it is used, and how it is protected.
    </p>
    <div class="highlight-box">
        We do not sell, share, or monetise any user data. All data stays within this platform.
    </div>
</div>

<div class="section-card">
    <h3>Authentication Data</h3>
    <p>This application uses <strong>Google OAuth2</strong> for authentication. When you log in:</p>
    <ul>
        <li>Google shares your <strong>name</strong> and <strong>email address</strong> with this application.</li>
        <li>This information is used solely to identify your session and display your name in the interface.</li>
        <li>Your Google credentials (password) are never seen or stored by this application.</li>
        <li>Google records your login activity on their end — see
            <a href="https://policies.google.com/privacy" target="_blank" style="color:#4a90d9;">
            Google's Privacy Policy</a> for details.
        </li>
    </ul>
</div>

<div class="section-card">
    <h3>Analysis Data & Caching</h3>
    <p>When you run an analysis:</p>
    <ul>
        <li>The URL or text you submit is sent to <strong>Anthropic's Claude API</strong> for AI analysis.</li>
        <li>Analysis results are cached locally in a SQLite database for <strong>7 days</strong> to avoid
            repeat API calls for the same content.</li>
        <li>Cached results include the source URL, report type, and the full JSON analysis result.</li>
        <li>Cached entries expire automatically after 7 days and can be manually deleted at any time
            from the Cache Viewer.</li>
    </ul>
    <div class="highlight-box">
        Do not submit content that contains personally identifiable information (PII) or
        classified/sensitive data not intended for third-party AI processing.
    </div>
</div>

<div class="section-card">
    <h3>Third-Party Services</h3>
    <p>This application relies on the following third-party services:</p>
    <ul>
        <li>
            <strong>Google OAuth2</strong> — for user authentication.<br/>
            <a href="https://policies.google.com/privacy" target="_blank" style="color:#4a90d9;">
            Google Privacy Policy →</a>
        </li>
        <li>
            <strong>Anthropic Claude API</strong> — for AI-powered IOC extraction and report generation.
            Content submitted for analysis is processed by Anthropic's API.<br/>
            <a href="https://www.anthropic.ic/privacy" target="_blank" style="color:#4a90d9;">
            Anthropic Privacy Policy →</a>
        </li>
        <li>
            <strong>Playwright / Chromium</strong> — for headless web scraping of URLs you submit.
            No data is sent to third parties during scraping beyond the target website itself.
        </li>
    </ul>
</div>

<div class="section-card">
    <h3>Data Storage & Retention</h3>
    <ul>
        <li><strong>Session data</strong> — held in memory only and cleared when your browser session ends.</li>
        <li><strong>Cache data</strong> — stored in a local SQLite database on the server. Expires after 7 days.</li>
        <li><strong>Authentication config</strong> — your name and email are stored in a local YAML file
            on the server after first login to maintain your session across restarts.</li>
        <li>No data is stored in external databases or cloud storage services.</li>
    </ul>
</div>

<div class="section-card">
    <h3>Security</h3>
    <ul>
        <li>All traffic is encrypted in transit via <strong>HTTPS/TLS</strong>.</li>
        <li>The application is hosted on a private server with firewall rules restricting access to
            HTTPS and SSH only.</li>
        <li>Session cookies are signed with a secret key and expire after 30 days.</li>
        <li>The server and application are managed by the platform administrator.</li>
    </ul>
</div>

<div class="section-card">
    <h3>Your Rights</h3>
    <p>As a user of this platform you can:</p>
    <ul>
        <li><strong>View cached data</strong> — via the Cache Viewer page.</li>
        <li><strong>Delete cached entries</strong> — individually or all at once from the Cache Viewer.</li>
        <li><strong>Revoke Google access</strong> — at any time via
            <a href="https://myaccount.google.com/permissions" target="_blank" style="color:#4a90d9;">
            Google Account Permissions →</a>
        </li>
        <li><strong>Request data removal</strong> — contact your platform administrator to have your
            account and any associated data removed.</li>
    </ul>
</div>

<div class="footer-note">
    Questions about this policy? Contact your platform administrator.<br/>
    IOC Hunter &nbsp;·&nbsp; Internal Use Only
</div>
""", unsafe_allow_html=True)

if st.session_state.get("authentication_status"):
    if st.button("← Back to IOC Hunter"):
        st.switch_page("app.py")
else:
    if st.button("← Back to Login"):
        st.switch_page("app.py")
