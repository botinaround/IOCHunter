"""
Minimal Google OAuth2 helper for IOC Hunter.
Handles the authorization URL, code exchange, and userinfo fetch
using only the Python standard library.
"""

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

_AUTH_URL     = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_URL    = "https://oauth2.googleapis.com/token"
_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


def build_auth_url(client_id: str, redirect_uri: str, state: str) -> str:
    """Return the Google OAuth2 authorization URL to redirect the user to."""
    params = urllib.parse.urlencode({
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "response_type": "code",
        "scope":         "openid email profile",
        "state":         state,
        "access_type":   "online",
        "prompt":        "select_account",
    })
    return f"{_AUTH_URL}?{params}"


def generate_state() -> str:
    """Return a random state token for CSRF protection."""
    return secrets.token_urlsafe(32)


def exchange_code(code: str, client_id: str, client_secret: str, redirect_uri: str) -> dict:
    """
    Exchange an authorization code for access + ID tokens.
    Returns the token response dict.
    Raises RuntimeError on failure.
    """
    body = urllib.parse.urlencode({
        "code":          code,
        "client_id":     client_id,
        "client_secret": client_secret,
        "redirect_uri":  redirect_uri,
        "grant_type":    "authorization_code",
    }).encode("utf-8")

    req = urllib.request.Request(_TOKEN_URL, data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Token exchange failed: {detail}") from e


def get_userinfo(access_token: str) -> dict:
    """
    Fetch the authenticated user's profile (email, name, picture).
    Returns the userinfo dict.
    Raises RuntimeError on failure.
    """
    req = urllib.request.Request(
        _USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Userinfo fetch failed: {detail}") from e
