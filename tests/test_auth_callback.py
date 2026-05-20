"""Tests for the /auth/callback route."""

import base64
import json
from unittest.mock import AsyncMock, patch

from itsdangerous import TimestampSigner
from starlette.testclient import TestClient

from app.config import settings
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
            follow_redirects=False,
        )

    assert resp.status_code == 303
    assert resp.headers.get("location") in ("/", "http://testserver/")


def test_callback_stores_tokens_in_token_store():
    access_token, id_token = _make_tokens()
    result = _success_result(access_token, id_token)
    api_scope = f"api://{FAKE_API_A_ID}/access_as_user"
    cookie = _base_cookie(api_scope)

    client = TestClient(app, raise_server_exceptions=False)

    resource_step = {"label": "Resource Call", "request": {}, "response": {}, "token": None}
    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock) as mock_ex, \
         patch("app.main.flows.call_resource", new_callable=AsyncMock) as mock_res:
        mock_ex.return_value = result
        mock_res.return_value = resource_step
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": cookie},
            follow_redirects=False,
        )

    assert resp.status_code == 303
    assert FAKE_SID in _token_store, "Expected FAKE_SID entry in _token_store"
    assert "auth_code" in _token_store[FAKE_SID], "Expected 'auth_code' key in _token_store[FAKE_SID]"
    assert _token_store[FAKE_SID]["auth_code"]["access_token"] == access_token


def test_callback_stores_user_profile():
    access_token, id_token = _make_tokens()
    result = _success_result(access_token, id_token)

    client = TestClient(app, raise_server_exceptions=False)

    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock) as mock_ex:
        mock_ex.return_value = result
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": _base_cookie()},
            follow_redirects=False,
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
        follow_redirects=False,
    )

    assert resp.status_code == 200, "State mismatch should render an error page (200), not redirect"
    assert "location" not in resp.headers
    assert "state" in resp.text.lower() or "mismatch" in resp.text.lower() or "error" in resp.text.lower()


def test_callback_entra_error_param_renders_error_page():
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get(
        "/auth/callback?error=access_denied&error_description=User+cancelled",
        cookies={"session": _base_cookie()},
        follow_redirects=False,
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
            follow_redirects=False,
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
            follow_redirects=False,
        )

    assert resp.status_code == 303

    raw_cookie = resp.cookies.get("session", "")
    signer = TimestampSigner(settings.session_secret)
    data = signer.unsign(raw_cookie, return_timestamp=False)
    session_data = json.loads(base64.b64decode(data))

    assert session_data.get("last_flow") == "auth_code", (
        f"BUG: last_flow was {session_data.get('last_flow')!r}, expected 'auth_code'. "
        "The callback sets last_flow='profile_login' for non-resource-scope flows "
        "instead of preserving the actual flow_type from the session."
    )


def test_callback_marks_session_as_live_auth():
    access_token, id_token = _make_tokens()
    result = _success_result(access_token, id_token)
    client = TestClient(app, raise_server_exceptions=False)

    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock) as mock_ex:
        mock_ex.return_value = result
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": _base_cookie()},
            follow_redirects=False,
        )

    assert resp.status_code == 303

    raw_cookie = resp.cookies.get("session", "")
    signer = TimestampSigner(settings.session_secret)
    data = signer.unsign(raw_cookie, return_timestamp=False)
    session_data = json.loads(base64.b64decode(data))

    assert session_data.get("simulation_mode") is False


def test_callback_profile_login_stores_steps_with_authorize_and_exchange():
    """BUG: session bootstrap callback strips 'steps' from the stored result.
    The frontend renders no step pills when steps=[].
    The profile_login diagram has two labeled rects (Authorize, Token Exchange);
    the stored result must include both as step objects so the pills appear."""
    from app.main import _result_store
    access_token, id_token = _make_tokens()
    mock_result = _success_result(access_token, id_token)
    # Inject a fake authorize step so auth_steps is non-empty
    mock_result["exchange_step"] = {
        "label": "Token Exchange",
        "request": {"method": "POST", "url": "https://login.example.com/token"},
        "response": {"status": 200, "body": {}},
        "tokens": {},
        "highlights": [],
        "description": "",
    }
    client = TestClient(app, raise_server_exceptions=False)

    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock) as mock_ex:
        mock_ex.return_value = mock_result
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": _base_cookie()},
            follow_redirects=False,
        )

    assert resp.status_code == 303

    # Decode result_id from the session cookie
    raw_cookie = resp.cookies.get("session", "")
    signer = TimestampSigner(settings.session_secret)
    data = signer.unsign(raw_cookie, return_timestamp=False)
    session_data = json.loads(base64.b64decode(data))
    result_id = session_data.get("result_id")
    assert result_id, "No result_id in session — callback didn't store the result"

    stored = _result_store.get(result_id)
    assert stored is not None, "result_id not found in _result_store"
    assert stored.get("flow_type") == "profile_login"

    steps = stored["result"].get("steps")
    assert steps is not None, (
        "BUG: 'steps' was stripped from profile_login result. "
        "The frontend shows no step pills."
    )
    assert len(steps) >= 1, f"Expected at least 1 step, got: {steps}"
    labels = [s.get("label", "") for s in steps]
    assert any("Token Exchange" in l or "Exchange" in l for l in labels), (
        f"Expected a Token Exchange step pill; got labels: {labels}"
    )


def test_auth_callback_authorize_step_diagram_index():
    """authorize_step must carry diagram_index=0 (maps to first rect in profile_login diagram)."""
    import secrets
    from app.main import _result_store
    access_token, id_token = _make_tokens()
    mock_result = _success_result(access_token, id_token)
    mock_result["exchange_step"] = {
        "label": "Token Exchange",
        "request": {"method": "POST", "url": "https://login.example.com/token"},
        "response": {"status": 200, "body": {}},
        "tokens": {},
        "highlights": [],
        "description": "",
    }

    # Inject a fake authorize_step via _result_store
    step_id = secrets.token_urlsafe(16)
    fake_authorize_step = {
        "label": "Authorization Redirect",
        "request": {"method": "GET", "url": "https://login.example.com/authorize"},
        "response": {"status": 302, "body": {}},
        "tokens": {},
        "highlights": [],
        "description": "",
    }
    _result_store[f"step_{step_id}"] = fake_authorize_step

    cookie = make_session_cookie({
        "sid": FAKE_SID,
        "oauth_state": FAKE_STATE,
        "oauth_scope": "openid profile",
        "flow_type": "auth_code",
        "target_scope": "",
        "authorize_step_id": step_id,
    })
    client = TestClient(app, raise_server_exceptions=False)

    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock) as mock_ex:
        mock_ex.return_value = mock_result
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": cookie},
            follow_redirects=False,
        )

    assert resp.status_code == 303

    raw_cookie = resp.cookies.get("session", "")
    signer = TimestampSigner(settings.session_secret)
    data = signer.unsign(raw_cookie, return_timestamp=False)
    session_data = json.loads(base64.b64decode(data))
    result_id = session_data.get("result_id")
    stored = _result_store.get(result_id)
    assert stored is not None

    steps = stored["result"].get("steps", [])
    authorize = next((s for s in steps if "Authoriz" in s.get("label", "")), None)
    exchange = next((s for s in steps if "Exchange" in s.get("label", "")), None)

    assert authorize is not None, f"No authorize step found in: {[s.get('label') for s in steps]}"
    assert authorize.get("diagram_index") == 0, (
        f"authorize_step must have diagram_index=0, got {authorize.get('diagram_index')!r}"
    )
    assert exchange is not None, f"No exchange step found in: {[s.get('label') for s in steps]}"
    assert exchange.get("diagram_index") == 1, (
        f"exchange_step must have diagram_index=1, got {exchange.get('diagram_index')!r}"
    )
