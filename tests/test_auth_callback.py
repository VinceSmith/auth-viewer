"""Tests for the /auth/callback route."""

import base64
import json
from unittest.mock import AsyncMock, patch

from starlette.testclient import TestClient

from app.main import app, _token_store
from tests.conftest import FAKE_SID, FAKE_API_A_ID, make_session_cookie, make_jwt

FAKE_STATE = "valid-state-value-long-enough-32c"
FAKE_CODE = "entra-auth-code-xyz"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_cookie(oauth_scope: str = "openid profile") -> str:
    return make_session_cookie({
        "sid": FAKE_SID,
        "oauth_state": FAKE_STATE,
        "oauth_scope": oauth_scope,
        "flow_type": "auth_code",
        "target_scope": "",
    })


def _make_tokens():
    access_token = make_jwt(payload={
        "aud": f"api://{FAKE_API_A_ID}", "exp": 9_999_999_999, "sub": "u1",
    })
    id_token = make_jwt(payload={
        "sub": "u1", "name": "Alice",
        "preferred_username": "alice@contoso.com",
        "oid": "oid-alice", "exp": 9_999_999_999,
    })
    return access_token, id_token


def _success_result(access_token: str, id_token: str) -> dict:
    return {
        "response": {"status": 200, "headers": {}, "body": {
            "access_token": access_token,
            "refresh_token": "rt-value",
            "id_token": id_token,
        }},
        "request": {"method": "POST", "url": "https://login.example.com/token"},
        "exchange_step": {"label": "Token Exchange", "request": {}, "response": {}, "token": None},
    }


def _clear_sid():
    _token_store.pop(FAKE_SID, None)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_callback_happy_path_redirects_to_root():
    access_token, id_token = _make_tokens()
    result = _success_result(access_token, id_token)
    client = TestClient(app, raise_server_exceptions=False)

    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock) as mock_ex:
        mock_ex.return_value = result
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": _base_cookie()},
            allow_redirects=False,
        )

    assert resp.status_code == 303
    assert resp.headers.get("location") in ("/", "http://testserver/")


def test_callback_stores_tokens_in_token_store():
    access_token, id_token = _make_tokens()
    result = _success_result(access_token, id_token)
    api_scope = f"api://{FAKE_API_A_ID}/access_as_user"
    cookie = _base_cookie(api_scope)

    _clear_sid()
    client = TestClient(app, raise_server_exceptions=False)

    resource_step = {"label": "Resource Call", "request": {}, "response": {}, "token": None}
    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock) as mock_ex, \
         patch("app.main.flows.call_resource", new_callable=AsyncMock) as mock_res:
        mock_ex.return_value = result
        mock_res.return_value = resource_step
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": cookie},
            allow_redirects=False,
        )

    assert resp.status_code == 303
    assert FAKE_SID in _token_store, "Expected FAKE_SID entry in _token_store"
    assert "auth_code" in _token_store[FAKE_SID], "Expected 'auth_code' key in _token_store[FAKE_SID]"
    assert _token_store[FAKE_SID]["auth_code"]["access_token"] == access_token


def test_callback_stores_user_profile():
    access_token, id_token = _make_tokens()
    result = _success_result(access_token, id_token)

    _clear_sid()
    client = TestClient(app, raise_server_exceptions=False)

    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock) as mock_ex:
        mock_ex.return_value = result
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": _base_cookie()},
            allow_redirects=False,
        )

    assert resp.status_code == 303
    assert FAKE_SID in _token_store
    profile = _token_store[FAKE_SID].get("user_profile")
    assert profile is not None, "user_profile should be stored in _token_store"
    assert profile["name"] == "Alice"
    assert profile["preferred_username"] == "alice@contoso.com"


def test_callback_state_mismatch_returns_error_page():
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get(
        f"/auth/callback?code={FAKE_CODE}&state=WRONG_STATE_VALUE",
        cookies={"session": _base_cookie()},
        allow_redirects=False,
    )

    assert resp.status_code == 200, "State mismatch should render an error page (200), not redirect"
    assert "location" not in resp.headers


def test_callback_entra_error_param_renders_error_page():
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get(
        "/auth/callback?error=access_denied&error_description=User+cancelled",
        cookies={"session": _base_cookie()},
        allow_redirects=False,
    )

    assert resp.status_code == 200
    assert "access_denied" in resp.text or "User cancelled" in resp.text


def test_callback_exchange_error_body_does_not_silently_succeed():
    """BUG (A-5): callback silently redirects to / even though token exchange returned an error body."""
    error_result = {
        "response": {"status": 400, "headers": {}, "body": {
            "error": "invalid_grant",
            "error_description": "Refresh token expired",
        }},
        "request": {"method": "POST", "url": "https://login.example.com/token"},
        "exchange_step": {"label": "Token Exchange", "request": {}, "response": {}, "token": None},
    }
    client = TestClient(app, raise_server_exceptions=False)

    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock) as mock_ex:
        mock_ex.return_value = error_result
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": _base_cookie()},
            allow_redirects=False,
        )

    assert resp.status_code != 303, (
        "BUG: callback silently redirected to / even though token exchange failed."
    )


def test_callback_sets_last_flow_in_session():
    """BUG (A-5): callback sets last_flow='profile_login' for non-resource-scope flows
    instead of preserving the actual flow_type ('auth_code') from the session."""
    access_token, id_token = _make_tokens()
    result = _success_result(access_token, id_token)
    client = TestClient(app, raise_server_exceptions=False)

    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock) as mock_ex:
        mock_ex.return_value = result
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": _base_cookie()},
            allow_redirects=False,
        )

    assert resp.status_code == 303

    from itsdangerous import TimestampSigner
    from app.config import settings

    raw_cookie = resp.cookies.get("session", "")
    signer = TimestampSigner(settings.session_secret)
    data = signer.unsign(raw_cookie, return_timestamp=False)
    session_data = json.loads(base64.b64decode(data))

    assert session_data.get("last_flow") == "auth_code", (
        f"BUG: last_flow was {session_data.get('last_flow')!r}, expected 'auth_code'. "
        "The callback sets last_flow='profile_login' for non-resource-scope flows "
        "instead of preserving the actual flow_type from the session."
    )
