"""Tests for POST /api/silent-acquire."""
import time
from unittest.mock import AsyncMock, patch

import pytest
from starlette.testclient import TestClient

from app.main import app, _token_store
from tests.conftest import FAKE_SID, FAKE_API_A_ID, make_session_cookie


def _silent_ok_result(at: str) -> dict:
    return {
        "response": {"status": 200, "headers": {}, "body": {
            "access_token": at,
            "refresh_token": "new-rt",
        }},
        "step": {"label": "Silent Acquire", "request": {}, "response": {}, "token": None},
    }


def _silent_error_result() -> dict:
    return {
        "response": {"status": 400, "headers": {}, "body": {
            "error": "invalid_grant",
            "error_description": "RT expired",
        }},
        "step": {"label": "Silent Acquire", "request": {}, "response": {}, "token": None},
    }


def _seed(data: dict) -> None:
    _token_store._data[FAKE_SID] = data
    _token_store._expires[FAKE_SID] = time.time() + 4 * 3600


def _client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


def _post(client: TestClient) -> object:
    return client.post(
        "/api/silent-acquire",
        json={"scope": f"api://{FAKE_API_A_ID}/access_as_user", "flow_type": "obo"},
        cookies={"session": make_session_cookie({"sid": FAKE_SID})},
    )


def test_silent_acquire_no_refresh_token_returns_400():
    _seed({})
    client = _client()
    resp = _post(client)
    assert resp.status_code == 400
    assert resp.json() == {"error": "no_refresh_token"}


def test_silent_acquire_passes_refresh_token_to_flow():
    _seed({"refresh_token": "my-rt"})
    mock = AsyncMock(return_value=_silent_ok_result("tok"))
    with patch("app.main.flows.silent_acquire", mock):
        resp = _post(_client())
    assert resp.status_code == 200
    mock.assert_called_once_with(
        refresh_token="my-rt",
        scope=f"api://{FAKE_API_A_ID}/access_as_user",
    )


def test_silent_acquire_entra_error_returns_400():
    _seed({"refresh_token": "my-rt"})
    mock = AsyncMock(return_value=_silent_error_result())
    with patch("app.main.flows.silent_acquire", mock):
        resp = _post(_client())
    assert resp.status_code == 400
    assert resp.json() == {"error": "invalid_grant", "message": "RT expired"}


def test_silent_acquire_updates_refresh_token_in_store():
    _seed({"refresh_token": "old-rt"})
    mock = AsyncMock(return_value=_silent_ok_result("access-tok"))
    with patch("app.main.flows.silent_acquire", mock):
        _post(_client())
    assert _token_store.get(FAKE_SID, {}).get("refresh_token") == "new-rt"


def test_silent_acquire_returns_access_token_in_body():
    _seed({"refresh_token": "my-rt"})
    mock = AsyncMock(return_value=_silent_ok_result("expected-at"))
    with patch("app.main.flows.silent_acquire", mock):
        resp = _post(_client())
    assert resp.status_code == 200
    assert resp.json()["access_token"] == "expected-at"
