"""Tests for no-auth simulation mode.

These tests define the simulation contract before implementation:
simulation mode must be self-contained, deterministic, and unable to call live
Entra/Graph/resource API paths by accident.
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.auth.token_utils import decode_jwt
from app.main import app
from tests.conftest import FAKE_SID, make_jwt, make_session_cookie


SIM_FLOWS = [
    ("auth_code", "api://sim-api-a/access_as_user", ""),
    ("client_credentials", "api://sim-api-b/.default", ""),
    ("obo", "api://sim-api-b/read", ""),
    ("agent_id_autonomous", "https://graph.microsoft.com/.default", ""),
    ("agent_id_obo", "api://sim-api-b/read", "api_a"),
]


@pytest.fixture()
def simulation_enabled(monkeypatch):
    from app import main as main_module

    monkeypatch.setattr(main_module.settings, "simulation_mode", True, raising=False)
    yield
    monkeypatch.setattr(main_module.settings, "simulation_mode", False, raising=False)


@pytest.fixture()
def client():
    return TestClient(app, raise_server_exceptions=False)


def test_settings_exposes_simulation_mode_default_false():
    from app.config import Settings

    assert Settings().simulation_mode is False


def test_index_does_not_redirect_when_simulation_mode_enabled(client, simulation_enabled):
    resp = client.get("/", follow_redirects=False)

    assert resp.status_code == 200

    assert "/auth/login" not in resp.headers.get("location", "")


def test_index_defaults_to_simulated_without_env_flag(client, monkeypatch):
    from app import main as main_module

    monkeypatch.setattr(main_module.settings, "simulation_mode", False, raising=False)

    resp = client.get("/", follow_redirects=False)
    body = resp.text

    assert resp.status_code == 200
    assert "Simulated demo" in body
    assert "Sign in for live auth" not in body
    assert ">Live auth<" in body
    assert "Sign in to use live Entra auth" in body
    assert "You can explore these flows in Simulated demo mode before signing in." in body
    assert client.get("/api/session").json()["simulation_mode"] is True


def test_auth_login_starts_live_auth_transition(client, monkeypatch):
    from app import main as main_module

    monkeypatch.setattr(main_module.settings, "simulation_mode", False, raising=False)
    with patch("app.main.flows.build_auth_code_url", new=AsyncMock(return_value={
        "authorize_url": "https://login.example.test/authorize",
        "request": {},
        "authorize_step": {"label": "Authorize Redirect"},
        "discovery_step": {"label": "OIDC Discovery"},
    })):
        resp = client.get("/auth/login?scope=openid+profile+offline_access", follow_redirects=False)

    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "https://login.example.test/authorize"
    assert client.get("/api/session").json()["simulation_mode"] is False


def test_mode_simulated_returns_signed_in_session_to_demo(client, simulation_enabled):
    resp = client.get("/mode/simulated", follow_redirects=True)

    assert resp.status_code == 200
    assert client.get("/api/session").json()["simulation_mode"] is True


def test_live_profile_overrides_stale_simulated_session(client, monkeypatch):
    from app import main as main_module

    monkeypatch.setattr(main_module.settings, "simulation_mode", False, raising=False)
    id_token = make_jwt(payload={
        "sub": "u1",
        "name": "Alice",
        "preferred_username": "alice@contoso.com",
        "oid": "oid-alice",
        "exp": 9_999_999_999,
    })
    access_token = make_jwt(payload={"aud": "api://api-a", "sub": "u1", "exp": 9_999_999_999})
    main_module._token_store[FAKE_SID] = {
        "auth_code": {"access_token": access_token, "refresh_token": "rt-value"},
        "refresh_token": "rt-value",
        "id_token_raw": id_token,
        "user_profile": {
            "name": "Alice",
            "preferred_username": "alice@contoso.com",
            "oid": "oid-alice",
        },
    }
    stale_cookie = make_session_cookie({"sid": FAKE_SID, "simulation_mode": True})

    resp = client.get("/", cookies={"session": stale_cookie}, follow_redirects=False)
    session_resp = client.get("/api/session", cookies={"session": stale_cookie})

    assert resp.status_code == 200
    assert ">Live Entra auth<" not in resp.text
    assert "id=\"status-live\"" not in resp.text
    assert "Use demo" not in resp.text
    assert "Simulated demo: no real auth calls" not in resp.text
    assert ">Simulated demo<" in resp.text
    assert ">Live auth<" in resp.text
    assert session_resp.json()["simulation_mode"] is False


def test_session_reports_simulation_token_state(client, simulation_enabled):
    resp = client.get("/api/session")

    body = resp.json()


    assert resp.status_code == 200
    assert body["simulation_mode"] is True
    assert body["has_access_token"] is True
    assert body["has_id_token"] is True
    assert body["has_refresh_token"] is True
    assert body["token_expired"] is False


def test_me_returns_fake_profile_and_decoded_id_token(client, simulation_enabled):
    resp = client.get("/api/me")
    body = resp.json()

    assert resp.status_code == 200
    assert body["signed_in"] is True
    assert body["profile"]["preferred_username"].endswith("@example.test")
    assert body["id_token"]["payload"]["aud"]
    assert body["id_token_raw"].count(".") == 2


def test_simulation_execute_all_flows_without_live_calls(client, simulation_enabled, monkeypatch):
    from app import main as main_module

    class PoisonTokenStore:
        def get(self, *args, **kwargs):
            raise AssertionError("simulation should not read _token_store")

    monkeypatch.setattr(main_module, "_token_store", PoisonTokenStore())
    live_functions = [
        "build_auth_code_url",
        "exchange_auth_code",
        "execute_client_credentials",
        "execute_client_credentials_chain",
        "execute_obo",
        "execute_agent_id_autonomous",
        "execute_agent_id_autonomous_chain",
        "execute_agent_id_obo",
        "call_resource",
        "silent_acquire",
        "fetch_signin_logs",
    ]
    patches = [
        patch(f"app.main.flows.{name}", new=AsyncMock(side_effect=AssertionError(f"live flow called: {name}")))
        for name in live_functions
    ]
    patches.extend([
        patch("httpx.AsyncClient", side_effect=AssertionError("outbound HTTP called")),
        patch("app.auth.flows.httpx.AsyncClient", side_effect=AssertionError("outbound HTTP called")),
    ])

    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10], patches[11], patches[12]:
        for flow_type, scope, chain_target in SIM_FLOWS:
            resp = client.post(
                "/api/execute",
                json={"flow_type": flow_type, "scope": scope, "chain_target": chain_target},
            )
            body = resp.json()
            assert resp.status_code == 200, body
            assert body["result"]["steps"], flow_type
            assert "sequenceDiagram" in body["diagram"]


def test_simulation_auth_code_uses_configured_api_b_resource(client, simulation_enabled, monkeypatch):
    from app import main as main_module

    configured_api_b_id = "22222222-2222-2222-2222-222222222222"
    scope = f"openid profile api://{configured_api_b_id}/read"
    monkeypatch.setattr(main_module.settings, "api_b_app_id", configured_api_b_id, raising=False)
    monkeypatch.setattr(main_module.settings, "api_b_scope", f"api://{configured_api_b_id}/read", raising=False)

    resp = client.post("/api/execute", json={"flow_type": "auth_code", "scope": scope})
    body = resp.json()

    assert resp.status_code == 200, body
    resource_step = body["result"]["steps"][-1]
    token_payload = resource_step["tokens"]["access_token"]["payload"]
    assert resource_step["label"] == "Call API B"
    assert resource_step["response"]["body"]["resource"] == "API B"
    assert token_payload["aud"] == configured_api_b_id


def test_simulation_auth_code_starts_with_user_login(client, simulation_enabled):
    resp = client.post(
        "/api/execute",
        json={"flow_type": "auth_code", "scope": "api://sim-api-a/access_as_user"},
    )
    body = resp.json()

    assert resp.status_code == 200, body
    labels = [step["label"] for step in body["result"]["steps"]]
    assert labels[:2] == ["User Login", "Auth Code Token Exchange"]


def test_simulation_obo_models_api_a_hop_before_downstream(client, simulation_enabled):
    resp = client.post(
        "/api/execute",
        json={"flow_type": "obo", "scope": "api://sim-api-b/read"},
    )
    body = resp.json()

    assert resp.status_code == 200, body
    labels = [step["label"] for step in body["result"]["steps"]]
    assert labels == [
        "User Login",
        "Auth Code Token Exchange",
        "Call API A",
        "OBO Token Exchange",
        "Call API B",
    ]

    _login, _auth_code_exchange, call_api_a, obo_exchange, call_api_b = body["result"]["steps"]
    assert call_api_a["tokens"]["access_token"]["payload"]["aud"] == "00000000-0000-0000-0000-000000000003"
    assert obo_exchange["tokens"]["access_token"]["payload"]["aud"] != call_api_a["tokens"]["access_token"]["payload"]["aud"]
    assert call_api_b["response"]["body"]["resource"] == "API B"


def test_simulation_agent_obo_starts_with_user_login(client, simulation_enabled):
    resp = client.post(
        "/api/execute",
        json={"flow_type": "agent_id_obo", "scope": "api://sim-api-b/read", "chain_target": "api_a"},
    )
    body = resp.json()

    assert resp.status_code == 200, body
    labels = [step["label"] for step in body["result"]["steps"]]
    assert labels[:2] == ["User Login", "Auth Code Token Exchange"]
    assert "Token Cache Hit" not in labels
    assert "Silent Token Acquisition" not in labels


def test_simulation_agent_obo_chain_returns_matching_diagram(client, simulation_enabled):
    resp = client.post(
        "/api/execute",
        json={"flow_type": "agent_id_obo", "scope": "api://sim-api-b/read", "chain_target": "api_a"},
    )
    body = resp.json()

    assert resp.status_code == 200, body
    indices = [step["diagram_index"] for step in body["result"]["steps"]]
    assert indices == [0, 1, 2, 3, 4, 5, 6]
    assert body["diagram"].count("Note right of") == 7
    assert "Step 6" in body["diagram"]
    assert "Step 7" in body["diagram"]


def test_simulation_user_auth_rerun_does_not_use_cached_token(client, simulation_enabled):
    labels_by_run = []
    for _ in range(2):
        resp = client.post(
            "/api/execute",
            json={"flow_type": "obo", "scope": "api://sim-api-b/read"},
        )
        body = resp.json()
        assert resp.status_code == 200, body
        labels_by_run.append([step["label"] for step in body["result"]["steps"]])

    assert labels_by_run[0] == labels_by_run[1]
    assert labels_by_run[1][:2] == ["User Login", "Auth Code Token Exchange"]
    assert all("Token Cache Hit" not in labels for labels in labels_by_run)
    assert all("Silent Token Acquisition" not in labels for labels in labels_by_run)


def test_simulation_step_copy_teaches_flow_without_simulation_caveats(client, simulation_enabled):
    resp = client.post(
        "/api/execute",
        json={"flow_type": "agent_id_obo", "scope": "api://sim-api-b/read", "chain_target": "api_a"},
    )
    body = resp.json()

    assert resp.status_code == 200, body
    visible_copy = "\n".join(
        f"{step.get('label', '')}\n{step.get('description', '')}"
        for step in body["result"]["steps"]
    ).lower()
    forbidden_phrases = [
        "simulated",
        "no cached token",
        "no browser redirect",
        "no real auth",
        "no live",
        "static values",
    ]
    assert all(phrase not in visible_copy for phrase in forbidden_phrases)


def test_simulation_descriptions_align_with_live_flow_language(client, simulation_enabled):
    resp = client.post(
        "/api/execute",
        json={"flow_type": "agent_id_obo", "scope": "api://sim-api-b/read", "chain_target": "api_a"},
    )
    body = resp.json()

    assert resp.status_code == 200, body
    descriptions = {step["label"]: step["description"] for step in body["result"]["steps"]}

    assert "User authenticates and consents to the requested scopes" in descriptions["User Login"]
    assert "POSTing to the /token endpoint with client credentials" in descriptions["Auth Code Token Exchange"]
    assert "Blueprint app authenticates with client_credentials + fmi_path" in descriptions["Blueprint Parent Token"]
    assert "client_assertion is the parent token" in descriptions["Agent OBO Exchange"]
    assert "verifies the RS256 signature" in descriptions["Call API A"]
    assert "audience switches to the downstream API" in descriptions["API A OBO to Downstream"]
    assert "API B validates the token" in descriptions["Call API B"]


def test_simulation_client_credentials_chain_models_api_a_hop(client, simulation_enabled):
    resp = client.post(
        "/api/execute",
        json={"flow_type": "client_credentials_chain", "scope": "api://sim-api-b/.default"},
    )
    body = resp.json()

    assert resp.status_code == 200, body
    labels = [step["label"] for step in body["result"]["steps"]]
    assert labels == [
        "Client Credentials for API A",
        "Call API A",
        "API A Client Credentials for API B",
        "API A Call API B",
    ]


def test_simulation_agent_autonomous_chain_uses_agent_id_steps(client, simulation_enabled):
    resp = client.post(
        "/api/execute",
        json={"flow_type": "agent_id_autonomous_chain", "scope": "api://sim-api-b/.default"},
    )
    body = resp.json()

    assert resp.status_code == 200, body
    labels = [step["label"] for step in body["result"]["steps"]]
    assert labels == [
        "Blueprint Parent Token",
        "FMI Exchange for API A",
        "Call API A",
        "API A Client Credentials for API B",
        "API A Call API B",
    ]


def test_simulation_unknown_resource_scope_returns_error(client, simulation_enabled):
    resp = client.post(
        "/api/execute",
        json={"flow_type": "auth_code", "scope": "openid profile api://unknown-app/read"},
    )

    assert resp.status_code == 400
    assert "Unknown target resource" in resp.json()["error"]


def test_simulation_client_credentials_missing_scope_returns_error(client, simulation_enabled):
    resp = client.post(
        "/api/execute",
        json={"flow_type": "client_credentials", "scope": ""},
    )

    assert resp.status_code == 400
    assert "Unknown target resource" in resp.json()["error"]


def test_simulation_unknown_chain_target_returns_error(client, simulation_enabled):
    resp = client.post(
        "/api/execute",
        json={
            "flow_type": "agent_id_obo",
            "scope": "https://graph.microsoft.com/User.Read",
            "chain_target": "not_a_target",
        },
    )

    assert resp.status_code == 400
    assert "Unknown chain target" in resp.json()["error"]


def test_simulation_unknown_flow_matches_route_contract(client, simulation_enabled):
    resp = client.post("/api/execute", json={"flow_type": "unknown", "scope": "openid"})

    assert resp.status_code == 400
    assert "Unknown flow type" in resp.json()["error"]


def test_simulation_silent_acquire_is_api_compatible_without_live_call(client, simulation_enabled):
    with patch("app.main.flows.silent_acquire", new=AsyncMock(side_effect=AssertionError("live silent acquire called"))):
        resp = client.post(
            "/api/silent-acquire",
            json={"scope": "api://sim-api-a/access_as_user", "flow_type": "auth_code"},
        )

    body = resp.json()
    assert resp.status_code == 200
    assert body["access_token"].count(".") == 2
    assert body["result"]["response"]["body"]["access_token"] == body["access_token"]


def test_simulation_signin_logs_are_canned_and_marked(client, simulation_enabled):
    with patch("app.main.flows.fetch_signin_logs", new=AsyncMock(side_effect=AssertionError("live Graph called"))):
        resp = client.get("/api/signin-logs")

    body = resp.json()
    assert resp.status_code == 200
    assert body["simulation_mode"] is True
    assert body["entries"]
    assert all(entry["simulated"] is True for entry in body["entries"])


def test_simulation_fixture_contract():
    from app.auth import simulation

    for flow_type, scope, chain_target in SIM_FLOWS:
        result = simulation.execute(flow_type=flow_type, scope=scope, chain_target=chain_target)
        assert result["steps"], flow_type
        for step in result["steps"]:
            assert step["label"]
            assert step["description"]
            assert step["diagram_index"] >= -1
            assert any(key in step for key in ("request", "response", "tokens"))
            assert isinstance(step.get("tokens", {}), dict)
            for token_data in step.get("tokens", {}).values():
                raw = token_data.get("raw") if isinstance(token_data, dict) else None
                if raw and raw.count(".") == 2:
                    decoded = decode_jwt(raw)
                    payload = decoded["payload"]
                    assert payload["iss"]
                    assert payload["tid"]
                    assert payload["aud"]
                    assert payload["exp"]
                    assert payload.get("scp") or payload.get("roles") or payload.get("idtyp") == "app"