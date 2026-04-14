"""TestClient-based tests for /api/execute dispatch routing."""
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import _FlowError, _run_delegated_flow


FAKE_STEP = {"label": "Test", "request": {}, "response": {}, "token": None}
FAKE_RESULT = {"steps": [FAKE_STEP]}


@pytest.fixture()
def client():
    """TestClient with session middleware; no live Entra calls."""
    from app.main import app
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


def _post(client, flow_type: str, scope: str = "openid", user_token: str = "") -> dict:
    resp = client.post(
        "/api/execute",
        json={"flow_type": flow_type, "scope": scope, "user_token": user_token},
    )
    return resp


# ---------------------------------------------------------------------------
# App-only flows — no user session required
# ---------------------------------------------------------------------------

class TestClientCredentialsDispatch:
    def test_routes_to_execute_client_credentials(self, client):
        with patch("app.main.flows.execute_client_credentials", new_callable=AsyncMock) as mock:
            mock.return_value = FAKE_RESULT
            resp = _post(client, "client_credentials", scope="api://some/.default")
        assert resp.status_code == 200
        mock.assert_called_once_with(scope="api://some/.default")
        assert resp.json()["result"] == FAKE_RESULT

    def test_routes_to_execute_client_credentials_chain(self, client):
        with patch("app.main.flows.execute_client_credentials_chain", new_callable=AsyncMock) as mock:
            mock.return_value = FAKE_RESULT
            resp = _post(client, "client_credentials_chain")
        assert resp.status_code == 200
        mock.assert_called_once()

    def test_routes_to_agent_id_autonomous(self, client):
        with patch("app.main.flows.execute_agent_id_autonomous", new_callable=AsyncMock) as mock:
            mock.return_value = FAKE_RESULT
            resp = _post(client, "agent_id_autonomous")
        assert resp.status_code == 200
        mock.assert_called_once()

    def test_routes_to_agent_id_autonomous_chain(self, client):
        with patch("app.main.flows.execute_agent_id_autonomous_chain", new_callable=AsyncMock) as mock:
            mock.return_value = FAKE_RESULT
            resp = _post(client, "agent_id_autonomous_chain")
        assert resp.status_code == 200
        mock.assert_called_once()


# ---------------------------------------------------------------------------
# Unknown flow type → 400
# ---------------------------------------------------------------------------

class TestUnknownFlowType:
    def test_returns_400_for_unknown(self, client):
        resp = _post(client, "totally_unknown_flow")
        assert resp.status_code == 400
        assert "Unknown flow type" in resp.json()["error"]

    def test_missing_flow_type_returns_422(self, client):
        """Pydantic validation rejects missing required field."""
        resp = client.post("/api/execute", json={"scope": "openid"})
        assert resp.status_code == 422

    def test_empty_flow_type_returns_400(self, client):
        resp = _post(client, "")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Delegated flows — require user token in session
# ---------------------------------------------------------------------------

class TestDelegatedFlowsNoToken:
    """When no user token is available, delegated flows return 400."""

    def test_auth_code_no_token(self, client):
        resp = _post(client, "auth_code")
        assert resp.status_code == 400
        data = resp.json()
        assert "error" in data

    def test_obo_no_token(self, client):
        resp = _post(client, "obo")
        assert resp.status_code == 400

    def test_agent_id_obo_no_token(self, client):
        resp = _post(client, "agent_id_obo")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Flow execution errors surface as 500
# ---------------------------------------------------------------------------

class TestFlowExecutionError:
    def test_exception_returns_500(self, client):
        with patch("app.main.flows.execute_client_credentials", side_effect=RuntimeError("boom")):
            resp = _post(client, "client_credentials")
        assert resp.status_code == 500
        assert "boom" in resp.json()["error"]


# ---------------------------------------------------------------------------
# Result includes diagram field
# ---------------------------------------------------------------------------

class TestResponseShape:
    def test_response_includes_result_and_diagram(self, client):
        with patch("app.main.flows.execute_client_credentials", new_callable=AsyncMock) as mock:
            mock.return_value = FAKE_RESULT
            resp = _post(client, "client_credentials")
        body = resp.json()
        assert "result" in body
        assert "diagram" in body


# ---------------------------------------------------------------------------
# Unit tests for _run_delegated_flow
# ---------------------------------------------------------------------------

class TestRunDelegatedFlow:
    async def test_no_token_raises_flow_error(self):
        with patch("app.main._resolve_user_token", new_callable=AsyncMock, return_value=("", [])):
            with pytest.raises(_FlowError) as exc_info:
                await _run_delegated_flow({}, "obo", AsyncMock())
        assert "No user token" in exc_info.value.body["error"]
        assert exc_info.value.status_code == 400

    async def test_expired_token_raises_flow_error(self):
        with patch("app.main._resolve_user_token", new_callable=AsyncMock, return_value=("some-token", [])):
            with patch("app.main._is_token_expired", return_value=True):
                with pytest.raises(_FlowError) as exc_info:
                    await _run_delegated_flow({}, "obo", AsyncMock())
        assert exc_info.value.body["error"] == "token_expired"
        assert exc_info.value.status_code == 400

    async def test_info_steps_prepended_to_result(self):
        info = [{"label": "Cache Hit"}]
        with patch("app.main._resolve_user_token", new_callable=AsyncMock, return_value=("tok", info)):
            with patch("app.main._is_token_expired", return_value=False):
                execute_fn = AsyncMock(return_value={"steps": [{"label": "OBO Step"}]})
                result = await _run_delegated_flow({}, "obo", execute_fn)
        assert execute_fn.called
        assert result["steps"][0]["label"] == "Cache Hit"
        assert result["steps"][1]["label"] == "OBO Step"

    async def test_execute_fn_exception_propagates(self):
        with patch("app.main._resolve_user_token", new_callable=AsyncMock, return_value=("tok", [])):
            with patch("app.main._is_token_expired", return_value=False):
                execute_fn = AsyncMock(side_effect=RuntimeError("downstream failure"))
                with pytest.raises(RuntimeError, match="downstream failure"):
                    await _run_delegated_flow({}, "obo", execute_fn)
