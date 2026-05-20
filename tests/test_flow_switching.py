"""Tests for _token_store audience isolation across flow types (Task A-3)."""
import time
from unittest.mock import AsyncMock, patch

import pytest
from starlette.testclient import TestClient

from app.config import settings as app_settings
from app.main import _token_store, app
from tests.conftest import (
    FAKE_API_A_ID,
    FAKE_API_B_ID,
    FAKE_BLUEPRINT_ID,
    FAKE_SID,
    make_jwt,
    make_session_cookie,
)

def _mock_step() -> dict:
    return {"steps": [{"label": "X", "request": {}, "response": {}, "token": None}]}


def _seed(data: dict) -> None:
    _token_store._data[FAKE_SID] = data
    _token_store._expires[FAKE_SID] = time.time() + 4 * 3600


def _cookie(flow_type: str = "obo") -> str:
    return make_session_cookie({"sid": FAKE_SID, "flow_type": flow_type})


def _api_a_token() -> str:
    return make_jwt(payload={"aud": FAKE_API_A_ID, "sub": "u1", "exp": 9_999_999_999})


def _api_b_token() -> str:
    return make_jwt(payload={"aud": FAKE_API_B_ID, "sub": "u1", "exp": 9_999_999_999})


def _blueprint_token() -> str:
    return make_jwt(payload={"aud": FAKE_BLUEPRINT_ID, "sub": "u1", "exp": 9_999_999_999})


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


# ── Test 1 ────────────────────────────────────────────────────────────────────


def test_obo_uses_api_a_token_not_api_b_token(client):
    """API-B token in auth_code slot must not flow into OBO (wrong audience)."""
    _seed({"auth_code": {"access_token": _api_b_token(), "refresh_token": ""}})

    with patch("app.main.flows.execute_obo", new_callable=AsyncMock) as mock_obo:
        mock_obo.return_value = _mock_step()
        resp = client.post(
            "/api/execute",
            json={"flow_type": "obo", "scope": f"api://{FAKE_API_A_ID}/access_as_user"},
            cookies={"session": _cookie("obo")},
        )

    # API-B token has wrong audience — execute_obo must NOT be called
    assert not mock_obo.called, (
        "BUG: execute_obo was called despite token having wrong audience (API-B instead of API-A). "
        "State bleeding detected."
    )
    assert resp.status_code == 400


# ── Test 2 ────────────────────────────────────────────────────────────────────


def test_obo_does_not_use_agent_id_obo_token(client):
    """Blueprint token stored under agent_id_obo must not bleed into OBO flow."""
    _seed({"agent_id_obo": {"access_token": _blueprint_token(), "refresh_token": ""}})

    with patch("app.main.flows.execute_obo", new_callable=AsyncMock) as mock_obo:
        mock_obo.return_value = _mock_step()
        resp = client.post(
            "/api/execute",
            json={"flow_type": "obo", "scope": f"api://{FAKE_API_A_ID}/access_as_user"},
            cookies={"session": _cookie("obo")},
        )

    # OBO store_keys don't include agent_id_obo slot — execute_obo must NOT be called
    assert not mock_obo.called, (
        "BUG: execute_obo was called despite no valid OBO token being seeded. "
        "State bleeding from agent_id_obo slot detected."
    )
    assert resp.status_code == 400


# ── Test 3 ────────────────────────────────────────────────────────────────────


def test_agent_id_obo_does_not_use_obo_token(client):
    """API-A token stored under obo must not bleed into agent_id_obo flow."""
    _seed({"obo": {"access_token": _api_a_token(), "refresh_token": ""}})

    with patch("app.main.flows.execute_agent_id_obo", new_callable=AsyncMock) as mock_agent_obo:
        mock_agent_obo.return_value = _mock_step()
        resp = client.post(
            "/api/execute",
            json={"flow_type": "agent_id_obo", "scope": f"api://{FAKE_BLUEPRINT_ID}/access_as_user"},
            cookies={"session": _cookie("agent_id_obo")},
        )

    assert not mock_agent_obo.called, (
        "BUG: execute_agent_id_obo was called despite no valid token being seeded. "
        "State bleeding from obo slot detected."
    )
    assert resp.status_code == 400


# ── Test 4 ────────────────────────────────────────────────────────────────────


def test_correct_api_a_token_flows_through_obo(client):
    """Positive case: token with real api_a_app_id audience must reach execute_obo."""
    real_api_a_token = make_jwt(
        payload={"aud": app_settings.api_a_app_id, "sub": "u1", "exp": 9_999_999_999}
    )
    _seed({"auth_code": {"access_token": real_api_a_token, "refresh_token": ""}})

    with patch("app.main.flows.execute_obo", new_callable=AsyncMock) as mock_obo:
        mock_obo.return_value = _mock_step()
        resp = client.post(
            "/api/execute",
            json={"flow_type": "obo", "scope": f"api://{app_settings.api_a_app_id}/access_as_user"},
            cookies={"session": _cookie("obo")},
        )

    assert mock_obo.called, "execute_obo must be called when a valid API-A token is present"
    received_token = mock_obo.call_args.kwargs.get(
        "user_access_token", mock_obo.call_args.args[0] if mock_obo.call_args.args else ""
    )
    assert received_token == real_api_a_token, "execute_obo must receive the seeded API-A token"


# ── Test 5 ────────────────────────────────────────────────────────────────────


def test_client_credentials_ignores_user_token_store(client):
    """App-only flow must not read from _token_store at all."""
    _seed({"auth_code": {"access_token": _api_a_token(), "refresh_token": ""}})

    with patch("app.main.flows.execute_client_credentials", new_callable=AsyncMock) as mock_cc:
        mock_cc.return_value = _mock_step()
        resp = client.post(
            "/api/execute",
            json={"flow_type": "client_credentials", "scope": f"api://{FAKE_API_B_ID}/.default"},
            cookies={"session": _cookie("client_credentials")},
        )

    assert mock_cc.called, "execute_client_credentials must be called"
    assert resp.status_code == 200
