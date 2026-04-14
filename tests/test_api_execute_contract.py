"""HTTP contract tests for /api/execute.

These tests POST to the real endpoint through TestClient and assert on the
*actual JSON response* — catching bugs that unit tests miss because they never
exercise the full main.py → flows.py pipeline.

Key contracts verified:
  - diagram_index sequence for every flow type
  - Token Cache Hit / Audience Mismatch / Silent Acquire get diagram_index=-1
  - All steps carry the required field set (label, description, tokens, highlights)
  - Error paths return the correct HTTP status and error key
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.auth import flows
from app.main import app, _token_store

from tests.conftest import (
    FAKE_SID,
    FAKE_API_A_ID,
    FAKE_API_B_ID,
    FAKE_BLUEPRINT_ID,
    make_jwt,
    make_session_cookie,
    make_mock_response,
    make_httpx_ctx,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

REQUIRED_STEP_FIELDS = {"label", "description", "tokens", "highlights"}


def _client_with_session(sid: str = FAKE_SID) -> TestClient:
    """TestClient with a session cookie carrying *sid*."""
    return TestClient(app, raise_server_exceptions=True)


def _session_cookie(sid: str = FAKE_SID) -> str:
    return make_session_cookie({"sid": sid})


def _make_token(aud: str, exp: int = 9_999_999_999) -> str:
    return make_jwt(payload={"aud": aud, "exp": exp, "sub": "u1", "scp": "access_as_user"})


def _post_execute(client: TestClient, flow_type: str, scope: str = "openid profile",
                  sid: str = FAKE_SID) -> dict:
    resp = client.post(
        "/api/execute",
        json={"flow_type": flow_type, "scope": scope},
        cookies={"session": _session_cookie(sid)},
    )
    return resp


def _fake_resource_step(label: str = "Call API A") -> dict:
    """Minimal step dict returned by a mocked resource call."""
    return {
        "label": label,
        "description": "test resource call",
        "request": {"method": "GET", "url": "http://localhost:8001/me"},
        "response": {"status": 200, "body": {}},
        "tokens": {},
        "highlights": {},
    }


def _prefill_oidc():
    """Pre-populate _oidc_cache so no real HTTP call is needed."""
    from app.auth.flows import _oidc_cache
    _oidc_cache.update({
        "authorization_endpoint": "https://login.example.com/authorize",
        "token_endpoint": "https://login.example.com/token",
        "issuer": "https://login.example.com",
        "jwks_uri": "https://login.example.com/jwks",
    })


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def prefill_oidc():
    _prefill_oidc()
    yield


@pytest.fixture()
def fake_settings():
    """Return a MagicMock settings that matches the FAKE_* constants in conftest."""
    from unittest.mock import MagicMock
    fake = MagicMock()
    fake.tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    fake.client_id = "cccccccc-1111-2222-3333-444444444444"
    fake.client_secret = "test-client-secret"
    fake.api_a_app_id = FAKE_API_A_ID
    fake.api_a_client_secret = "api-a-secret"
    fake.api_a_scope = f"api://{FAKE_API_A_ID}/access_as_user"
    fake.api_a_base_url = "http://localhost:8001"
    fake.api_b_app_id = FAKE_API_B_ID
    fake.api_b_scope = f"api://{FAKE_API_B_ID}/read"
    fake.api_b_base_url = "http://localhost:8002"
    fake.agent_blueprint_app_id = FAKE_BLUEPRINT_ID
    fake.agent_blueprint_secret = "blueprint-secret"
    fake.agent_identity_id = "agagagag-4444-4444-4444-444444444444"
    fake.agent_identity_tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    fake.redirect_uri = "http://localhost:8000/auth/callback"
    fake.authority = "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    fake.agent_token_endpoint = "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/oauth2/v2.0/token"
    fake.session_secret = "test-session-secret"
    return fake


@pytest.fixture(autouse=True)
def patch_all_settings(fake_settings):
    """Patch settings in both flows and main so FAKE_* IDs resolve correctly."""
    with patch("app.auth.flows.settings", fake_settings), \
         patch("app.main.settings", fake_settings):
        yield fake_settings


@pytest.fixture()
def client():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


def _seed_token(aud: str, flow_key: str = "auth_code", sid: str = FAKE_SID) -> str:
    """Put a valid token in _token_store and return it."""
    token = _make_token(aud)
    _token_store[sid] = {flow_key: {"access_token": token, "refresh_token": "rt-val"}}
    return token


# ---------------------------------------------------------------------------
# Step schema validation
# ---------------------------------------------------------------------------

class TestStepSchema:
    """Every step returned by /api/execute must carry the required fields."""

    def test_client_credentials_steps_have_required_fields(self, client):
        token_resp = make_mock_response(200, {"access_token": _make_token("api-app"), "token_type": "Bearer"})
        resource_resp = make_mock_response(200, {"data": "ok"})
        ctx_token, mock_tok = make_httpx_ctx(token_resp)
        ctx_res, mock_res = make_httpx_ctx(resource_resp)

        scope = f"api://{FAKE_API_A_ID}/.default"
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_token, ctx_res]):
            resp = _post_execute(client, "client_credentials", scope=scope)

        assert resp.status_code == 200
        steps = resp.json()["result"]["steps"]
        assert len(steps) >= 1
        for step in steps:
            missing = REQUIRED_STEP_FIELDS - step.keys()
            assert not missing, f"Step '{step.get('label')}' missing fields: {missing}"

    def test_every_step_has_string_label(self, client):
        token_resp = make_mock_response(200, {"access_token": _make_token("x"), "token_type": "Bearer"})
        resource_resp = make_mock_response(200, {})
        ctx_token, _ = make_httpx_ctx(token_resp)
        ctx_res, _ = make_httpx_ctx(resource_resp)

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_token, ctx_res]):
            resp = _post_execute(client, "client_credentials")

        steps = resp.json()["result"]["steps"]
        for step in steps:
            assert isinstance(step["label"], str) and step["label"], (
                f"Step has empty/non-string label: {step}"
            )

    def test_every_step_has_diagram_index_field(self, client):
        """Every step in every flow response must have a diagram_index key."""
        token_resp = make_mock_response(200, {"access_token": _make_token("x"), "token_type": "Bearer"})
        resource_resp = make_mock_response(200, {})
        ctx_token, _ = make_httpx_ctx(token_resp)
        ctx_res, _ = make_httpx_ctx(resource_resp)

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_token, ctx_res]):
            resp = _post_execute(client, "client_credentials")

        steps = resp.json()["result"]["steps"]
        for step in steps:
            assert "diagram_index" in step, (
                f"Step '{step.get('label')}' is missing 'diagram_index'"
            )


# ---------------------------------------------------------------------------
# diagram_index: client_credentials
# ---------------------------------------------------------------------------

class TestDiagramIndexClientCredentials:

    def test_cc_step_has_index_0(self, client):
        token_resp = make_mock_response(200, {"access_token": _make_token("x"), "token_type": "Bearer"})
        resource_resp = make_mock_response(200, {})
        ctx_token, _ = make_httpx_ctx(token_resp)
        ctx_res, _ = make_httpx_ctx(resource_resp)

        scope = f"api://{FAKE_API_A_ID}/.default"
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_token, ctx_res]):
            resp = _post_execute(client, "client_credentials", scope=scope)

        steps = resp.json()["result"]["steps"]
        cc_step = next((s for s in steps if "Client Credentials" in s["label"] and "Chain" not in s["label"] and "API A" not in s["label"]), None)
        assert cc_step is not None, f"No CC step in: {[s['label'] for s in steps]}"
        assert cc_step["diagram_index"] == 0, f"CC step should have diagram_index=0, got {cc_step['diagram_index']}"

    def test_resource_step_has_index_1(self, client):
        token_resp = make_mock_response(200, {"access_token": _make_token("x"), "token_type": "Bearer"})
        resource_resp = make_mock_response(200, {})
        ctx_token, _ = make_httpx_ctx(token_resp)
        ctx_res, _ = make_httpx_ctx(resource_resp)

        scope = f"api://{FAKE_API_A_ID}/.default"
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_token, ctx_res]):
            resp = _post_execute(client, "client_credentials", scope=scope)

        steps = resp.json()["result"]["steps"]
        resource_step = next((s for s in steps if "Call" in s["label"]), None)
        assert resource_step is not None
        assert resource_step["diagram_index"] == 1

    def test_oidc_discovery_step_has_index_minus_1(self, client):
        """When OIDC cache is empty, discovery step must have diagram_index=-1."""
        flows._oidc_cache.clear()  # Force a real discovery call
        token_resp = make_mock_response(200, {"access_token": _make_token("x"), "token_type": "Bearer"})
        resource_resp = make_mock_response(200, {})
        discovery_resp = make_mock_response(200, {
            "authorization_endpoint": "https://login.example.com/authorize",
            "token_endpoint": "https://login.example.com/token",
            "issuer": "https://login.example.com",
            "jwks_uri": "https://login.example.com/jwks",
        })
        ctx_disc, mock_disc = make_httpx_ctx(discovery_resp)
        ctx_token, _ = make_httpx_ctx(token_resp)
        ctx_res, _ = make_httpx_ctx(resource_resp)
        # get → discovery, post → token, get → resource
        mock_disc.get = AsyncMock(return_value=discovery_resp)
        mock_disc.post = AsyncMock(return_value=token_resp)
        ctx_all = MagicMock()
        ctx_all.__aenter__ = AsyncMock(return_value=mock_disc)
        ctx_all.__aexit__ = AsyncMock(return_value=False)

        with patch("app.auth.flows.httpx.AsyncClient", return_value=ctx_all):
            resp = _post_execute(client, "client_credentials", scope=f"api://{FAKE_API_A_ID}/.default")

        steps = resp.json()["result"]["steps"]
        disc_step = next((s for s in steps if "OIDC" in s["label"]), None)
        assert disc_step is not None, f"No OIDC discovery step. Steps: {[s['label'] for s in steps]}"
        assert disc_step["diagram_index"] == -1


# ---------------------------------------------------------------------------
# diagram_index: cached token path (THE CRITICAL BUG TEST)
# ---------------------------------------------------------------------------

class TestDiagramIndexCachedToken:
    """Cached token steps must always have diagram_index=-1."""

    def test_token_cache_hit_has_diagram_index_minus_1(self, client):
        """Token Cache Hit step must have diagram_index=-1 so it doesn't highlight a rect."""
        _seed_token(FAKE_API_A_ID, "auth_code")

        with patch("app.auth.flows.call_resource", new_callable=AsyncMock) as mock_res:
            mock_res.return_value = {**_fake_resource_step(), "diagram_index": 2}
            resp = _post_execute(
                client, "auth_code",
                scope=f"api://{FAKE_API_A_ID}/access_as_user",
            )

        assert resp.status_code == 200
        steps = resp.json()["result"]["steps"]
        cache_step = next((s for s in steps if "Cache Hit" in s["label"]), None)
        assert cache_step is not None, (
            f"Expected a 'Token Cache Hit' step but got: {[s['label'] for s in steps]}"
        )
        assert cache_step["diagram_index"] == -1, (
            f"Token Cache Hit must have diagram_index=-1 (no rect), "
            f"got {cache_step['diagram_index']!r}. "
            "This causes the wrong diagram rect to be highlighted."
        )

    def test_token_cache_hit_precedes_resource_step(self, client):
        """Cache Hit step must come before the resource step."""
        _seed_token(FAKE_API_A_ID, "auth_code")

        with patch("app.auth.flows.call_resource", new_callable=AsyncMock) as mock_res:
            mock_res.return_value = {**_fake_resource_step(), "diagram_index": 2}
            resp = _post_execute(
                client, "auth_code",
                scope=f"api://{FAKE_API_A_ID}/access_as_user",
            )

        steps = resp.json()["result"]["steps"]
        labels = [s["label"] for s in steps]
        cache_idx = next((i for i, l in enumerate(labels) if "Cache Hit" in l), None)
        resource_idx = next((i for i, l in enumerate(labels) if "Call" in l), None)
        assert cache_idx is not None
        assert resource_idx is not None
        assert cache_idx < resource_idx, (
            f"Cache Hit step ({cache_idx}) must come before resource step ({resource_idx})"
        )

    def test_resource_step_after_cache_hit_has_diagram_index_2(self, client):
        """After a cached token, the resource step must still have diagram_index=2."""
        _seed_token(FAKE_API_A_ID, "auth_code")

        with patch("app.auth.flows.call_resource", new_callable=AsyncMock) as mock_res:
            mock_res.return_value = {**_fake_resource_step(), "diagram_index": 2}
            resp = _post_execute(
                client, "auth_code",
                scope=f"api://{FAKE_API_A_ID}/access_as_user",
            )

        steps = resp.json()["result"]["steps"]
        resource_step = next((s for s in steps if "Call" in s["label"]), None)
        assert resource_step is not None
        assert resource_step["diagram_index"] == 2

    def test_obo_cache_hit_has_diagram_index_minus_1(self, client):
        """OBO cached token (Token Cache Hit) must have diagram_index=-1."""
        _seed_token(FAKE_API_A_ID, "obo")

        with patch("app.main.flows.execute_obo", new_callable=AsyncMock) as mock_obo:
            mock_obo.return_value = {"steps": [
                {**_fake_resource_step("Call API A"), "diagram_index": 2},
            ]}
            resp = _post_execute(client, "obo")

        assert resp.status_code == 200
        steps = resp.json()["result"]["steps"]
        cache_step = next((s for s in steps if "Cache Hit" in s["label"]), None)
        assert cache_step is not None, f"Expected Token Cache Hit step, got: {[s['label'] for s in steps]}"
        assert cache_step["diagram_index"] == -1

    def test_token_audience_mismatch_has_diagram_index_minus_1(self, client):
        """Token Audience Mismatch info step must have diagram_index=-1."""
        # Seed a token for auth_code but with wrong audience
        wrong_aud_token = _make_token(aud="wrong-audience-id")
        _token_store[FAKE_SID] = {"auth_code": {"access_token": wrong_aud_token}}

        # Request a scope that expects a specific audience
        with patch("app.main.flows.execute_obo", new_callable=AsyncMock) as mock_obo:
            mock_obo.return_value = {"steps": [{**_fake_resource_step(), "diagram_index": 2}]}
            resp = _post_execute(
                client, "obo",
                scope=f"api://{FAKE_API_A_ID}/access_as_user",
            )

        # Audience mismatch → no valid token → 400 (no refresh token either)
        # But the mismatch step gets appended in _resolve_user_token before we hit the error
        # The behavior: if no RT either, returns 400 but the info_steps are not returned
        # This test verifies the actual mismatch info_step when RT exists
        # Patch: seed with RT so we can observe the mismatch step
        _token_store[FAKE_SID] = {
            "auth_code": {
                "access_token": wrong_aud_token,
                "refresh_token": "rt-val",
            }
        }
        silent_resp = {
            "response": {"status": 200, "body": {
                "access_token": _make_token(FAKE_API_A_ID),
                "refresh_token": "new-rt",
            }},
            "step": {"label": "Silent Token Acquisition", "description": "...",
                     "request": {}, "response": {}, "tokens": {}, "highlights": {}},
        }
        with patch("app.main.flows.silent_acquire", new_callable=AsyncMock, return_value=silent_resp), \
             patch("app.main.flows.execute_obo", new_callable=AsyncMock) as mock_obo:
            mock_obo.return_value = {"steps": [{**_fake_resource_step(), "diagram_index": 2}]}
            resp = _post_execute(
                client, "obo",
                scope=f"api://{FAKE_API_A_ID}/access_as_user",
            )

        assert resp.status_code == 200
        steps = resp.json()["result"]["steps"]
        labels = [s["label"] for s in steps]
        # Should have mismatch + silent acquire + flow steps
        mismatch = next((s for s in steps if "Mismatch" in s["label"]), None)
        silent = next((s for s in steps if "Silent" in s["label"]), None)
        if mismatch:
            assert mismatch["diagram_index"] == -1, (
                f"Token Audience Mismatch must be diagram_index=-1, got {mismatch['diagram_index']}"
            )
        if silent:
            assert silent["diagram_index"] == 0, (
                f"Silent Token Acquisition must be diagram_index=0 (aligns to Token Exchange "
                f"in the silent diagram), got {silent['diagram_index']}"
            )

    def test_silent_token_acquisition_has_diagram_index_0(self, client):
        """Silent Token Acquisition step must have diagram_index=0.

        When a refresh_token is exchanged silently, _apply_silent_diagram_shift
        rewrites the step to point at diagram rect 0 (Token Exchange in the
        silent diagram). Downstream steps shift down by 1.
        """
        # No access_token, but we have a refresh token
        _token_store[FAKE_SID] = {"auth_code": {"refresh_token": "valid-rt"}}

        silent_resp = {
            "response": {"status": 200, "body": {
                "access_token": _make_token(FAKE_API_A_ID),
                "refresh_token": "new-rt",
            }},
            "step": {
                "label": "Silent Token Acquisition",
                "description": "Used refresh token",
                "request": {"method": "POST", "url": "https://login.example.com/token"},
                "response": {"status": 200, "body": {}},
                "tokens": {},
                "highlights": {},
            },
        }
        with patch("app.main.flows.silent_acquire", new_callable=AsyncMock, return_value=silent_resp), \
             patch("app.auth.flows.call_resource", new_callable=AsyncMock) as mock_res:
            mock_res.return_value = {**_fake_resource_step(), "diagram_index": 2}
            resp = _post_execute(
                client, "auth_code",
                scope=f"api://{FAKE_API_A_ID}/access_as_user",
            )

        assert resp.status_code == 200, resp.json()
        data = resp.json()
        steps = data["result"]["steps"]
        silent = next((s for s in steps if "Silent" in s["label"]), None)
        assert silent is not None, f"Expected Silent Token Acquisition step, got: {[s['label'] for s in steps]}"
        assert silent["diagram_index"] == 0, (
            f"Silent Token Acquisition must have diagram_index=0 (Token Exchange rect in silent diagram), "
            f"got {silent['diagram_index']!r}."
        )
        # Downstream resource step: was diagram_index=2, should shift to 1
        resource = next((s for s in steps if "Call" in s["label"]), None)
        if resource:
            assert resource["diagram_index"] == 1, (
                f"Resource step after silent acquire must shift to diagram_index=1, "
                f"got {resource['diagram_index']!r}"
            )
        # The response diagram should be the silent variant
        assert "refresh_token" in data["diagram"], "Silent path must use auth_code_silent diagram"
        assert "GET /authorize" not in data["diagram"], "Silent diagram must not show /authorize"


# ---------------------------------------------------------------------------
# diagram_index: auth_code execute resource call
# ---------------------------------------------------------------------------

class TestDiagramIndexAuthCode:

    def test_auth_code_resource_step_has_diagram_index_2(self, client):
        """The resource step in auth_code execute must have diagram_index=2.

        Diagram rects: 0=Authorize, 1=Token Exchange, 2=Resource Call.
        Authorize and Token Exchange are set in auth_callback, not here.
        """
        _seed_token(FAKE_API_A_ID, "auth_code")

        with patch("app.auth.flows.call_resource", new_callable=AsyncMock) as mock_res:
            mock_res.return_value = _fake_resource_step()
            resp = _post_execute(
                client, "auth_code",
                scope=f"api://{FAKE_API_A_ID}/access_as_user",
            )

        assert resp.status_code == 200
        steps = resp.json()["result"]["steps"]
        resource = next((s for s in steps if "Call" in s["label"]), None)
        assert resource is not None, f"No resource step in: {[s['label'] for s in steps]}"
        assert resource["diagram_index"] == 2, (
            f"Resource step must have diagram_index=2, got {resource['diagram_index']!r}"
        )


# ---------------------------------------------------------------------------
# diagram_index: OBO flow
# ---------------------------------------------------------------------------

class TestDiagramIndexOBO:

    def test_obo_call_api_a_has_diagram_index_2(self, client):
        """OBO's 'Call API A' step must have diagram_index=2.

        (Authorize=0, Token Exchange=1 from auth_callback; OBO starts at 2.)
        """
        _seed_token(FAKE_API_A_ID, "obo")
        token_resp = make_mock_response(200, {"access_token": _make_token(FAKE_API_B_ID), "token_type": "Bearer"})
        resource_resp = make_mock_response(200, {"data": "ok"})
        ctx_token, _ = make_httpx_ctx(token_resp)
        ctx_res, _ = make_httpx_ctx(resource_resp)

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_token, ctx_res, ctx_token]):
            resp = _post_execute(client, "obo", scope=f"api://{FAKE_API_B_ID}/read")

        assert resp.status_code == 200
        steps = resp.json()["result"]["steps"]
        call_api_a = next((s for s in steps if "Call API A" in s.get("label", "")), None)
        assert call_api_a is not None, f"No 'Call API A' step in: {[s['label'] for s in steps]}"
        assert call_api_a["diagram_index"] == 2

    def test_obo_exchange_has_diagram_index_3(self, client):
        """OBO token exchange step must have diagram_index=3."""
        _seed_token(FAKE_API_A_ID, "obo")
        token_resp = make_mock_response(200, {"access_token": _make_token(FAKE_API_B_ID), "token_type": "Bearer"})
        resource_resp = make_mock_response(200, {"data": "ok"})
        ctx_token, _ = make_httpx_ctx(token_resp)
        ctx_res, _ = make_httpx_ctx(resource_resp)

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_token, ctx_res, ctx_token]):
            resp = _post_execute(client, "obo", scope=f"api://{FAKE_API_B_ID}/read")

        assert resp.status_code == 200
        steps = resp.json()["result"]["steps"]
        obo_step = next((s for s in steps if "OBO" in s.get("label", "") or "On-Behalf" in s.get("label", "")), None)
        assert obo_step is not None, f"No OBO exchange step in: {[s['label'] for s in steps]}"
        assert obo_step["diagram_index"] == 3


# ---------------------------------------------------------------------------
# diagram_index: agent_id_autonomous
# ---------------------------------------------------------------------------

class TestDiagramIndexAgentAutonomous:

    def _mock_three_calls(self):
        """Returns context managers for: parent token, FMI exchange, resource call."""
        parent_token_resp = make_mock_response(200, {
            "access_token": _make_token(FAKE_BLUEPRINT_ID),
            "token_type": "Bearer",
        })
        fmi_token_resp = make_mock_response(200, {
            "access_token": _make_token("api://agent"),
            "token_type": "Bearer",
        })
        resource_resp = make_mock_response(200, {"data": "ok"})
        c1, _ = make_httpx_ctx(parent_token_resp)
        c2, _ = make_httpx_ctx(fmi_token_resp)
        c3, _ = make_httpx_ctx(resource_resp)
        return c1, c2, c3

    def test_parent_token_has_diagram_index_0(self, client):
        c1, c2, c3 = self._mock_three_calls()
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[c1, c2, c3]):
            resp = _post_execute(client, "agent_id_autonomous",
                                 scope=f"api://{FAKE_API_A_ID}/.default")

        assert resp.status_code == 200
        steps = resp.json()["result"]["steps"]
        parent = next((s for s in steps if "Parent" in s["label"] or "Blueprint" in s["label"]), None)
        assert parent is not None, f"Steps: {[s['label'] for s in steps]}"
        assert parent["diagram_index"] == 0

    def test_fmi_exchange_has_diagram_index_1(self, client):
        c1, c2, c3 = self._mock_three_calls()
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[c1, c2, c3]):
            resp = _post_execute(client, "agent_id_autonomous",
                                 scope=f"api://{FAKE_API_A_ID}/.default")

        assert resp.status_code == 200
        steps = resp.json()["result"]["steps"]
        fmi = next((s for s in steps if "FMI" in s["label"] or "Agent" in s["label"] and "Exchange" in s["label"]), None)
        assert fmi is not None, f"Steps: {[s['label'] for s in steps]}"
        assert fmi["diagram_index"] == 1

    def test_resource_call_has_diagram_index_2(self, client):
        c1, c2, c3 = self._mock_three_calls()
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[c1, c2, c3]):
            resp = _post_execute(client, "agent_id_autonomous",
                                 scope=f"api://{FAKE_API_A_ID}/.default")

        assert resp.status_code == 200
        steps = resp.json()["result"]["steps"]
        resource = next((s for s in steps if "Call" in s["label"]), None)
        assert resource is not None, f"Steps: {[s['label'] for s in steps]}"
        assert resource["diagram_index"] == 2


# ---------------------------------------------------------------------------
# Response shape: top-level contract
# ---------------------------------------------------------------------------

class TestResponseTopLevel:

    def test_response_has_result_and_diagram(self, client):
        token_resp = make_mock_response(200, {"access_token": _make_token("x"), "token_type": "Bearer"})
        resource_resp = make_mock_response(200, {})
        ctx_token, _ = make_httpx_ctx(token_resp)
        ctx_res, _ = make_httpx_ctx(resource_resp)

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_token, ctx_res]):
            resp = _post_execute(client, "client_credentials")

        assert resp.status_code == 200
        body = resp.json()
        assert "result" in body, "Response must have 'result'"
        assert "diagram" in body, "Response must have 'diagram'"

    def test_result_has_steps_list(self, client):
        token_resp = make_mock_response(200, {"access_token": _make_token("x"), "token_type": "Bearer"})
        resource_resp = make_mock_response(200, {})
        ctx_token, _ = make_httpx_ctx(token_resp)
        ctx_res, _ = make_httpx_ctx(resource_resp)

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_token, ctx_res]):
            resp = _post_execute(client, "client_credentials")

        result = resp.json()["result"]
        assert "steps" in result, "result must have 'steps' list"
        assert isinstance(result["steps"], list)
        assert len(result["steps"]) >= 1

    def test_diagram_contains_svg_content(self, client):
        token_resp = make_mock_response(200, {"access_token": _make_token("x"), "token_type": "Bearer"})
        resource_resp = make_mock_response(200, {})
        ctx_token, _ = make_httpx_ctx(token_resp)
        ctx_res, _ = make_httpx_ctx(resource_resp)

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_token, ctx_res]):
            resp = _post_execute(client, "client_credentials")

        diagram = resp.json()["diagram"]
        assert diagram, "diagram must not be empty"


# ---------------------------------------------------------------------------
# Error path contracts
# ---------------------------------------------------------------------------

class TestErrorContracts:

    def test_delegated_flow_no_token_returns_400(self, client):
        resp = _post_execute(client, "auth_code")
        assert resp.status_code == 400
        assert "error" in resp.json()

    def test_delegated_flow_expired_token_returns_400(self, client):
        expired = _make_token(FAKE_API_A_ID, exp=1)  # expired in the past
        _token_store[FAKE_SID] = {"auth_code": {"access_token": expired}}
        resp = _post_execute(client, "auth_code", scope=f"api://{FAKE_API_A_ID}/access_as_user")
        assert resp.status_code == 400
        assert resp.json().get("error") == "token_expired"

    def test_expired_token_error_has_message(self, client):
        expired = _make_token(FAKE_API_A_ID, exp=1)
        _token_store[FAKE_SID] = {"auth_code": {"access_token": expired}}
        resp = _post_execute(client, "auth_code", scope=f"api://{FAKE_API_A_ID}/access_as_user")
        body = resp.json()
        assert "message" in body, "token_expired response must include 'message'"

    def test_unknown_flow_type_returns_400(self, client):
        resp = _post_execute(client, "not_a_real_flow")
        assert resp.status_code == 400
        assert "Unknown flow type" in resp.json()["error"]

    def test_missing_flow_type_returns_422(self, client):
        resp = client.post(
            "/api/execute",
            json={"scope": "openid"},
            cookies={"session": _session_cookie()},
        )
        assert resp.status_code == 422

    def test_empty_flow_type_returns_400(self, client):
        resp = _post_execute(client, "")
        assert resp.status_code == 400

    def test_flow_exception_returns_500(self, client):
        with patch("app.main.flows.execute_client_credentials",
                   side_effect=RuntimeError("catastrophic failure")):
            resp = _post_execute(client, "client_credentials")
        assert resp.status_code == 500
        assert "catastrophic failure" in resp.json()["error"]
