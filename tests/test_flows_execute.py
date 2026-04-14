"""Unit tests for async flow execution functions — httpx is mocked throughout."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.conftest import (
    FAKE_API_A_ID,
    FAKE_API_B_ID,
    FAKE_TENANT,
    make_jwt,
    make_mock_response,
    make_httpx_ctx,
)

# Pre-populated OIDC cache to skip the discovery HTTP call in most tests.
_OIDC_CACHE = {
    "token_endpoint": f"https://login.microsoftonline.com/{FAKE_TENANT}/oauth2/v2.0/token",
    "authorization_endpoint": f"https://login.microsoftonline.com/{FAKE_TENANT}/oauth2/v2.0/authorize",
    "issuer": f"https://login.microsoftonline.com/{FAKE_TENANT}/v2.0",
}


@pytest.fixture
def prefill_oidc(patch_settings):
    """Patch settings AND pre-populate the OIDC cache so tests skip discovery."""
    from app.auth import flows
    flows._oidc_cache.update(_OIDC_CACHE)
    return patch_settings


# ────────────────────────────────────────────────────────────────
# _post_token_endpoint
# ────────────────────────────────────────────────────────────────

class TestPostTokenEndpoint:
    async def test_returns_request_response_tokens_shape(self, prefill_oidc):
        from app.auth.flows import _post_token_endpoint

        token = make_jwt()
        ctx, _ = make_httpx_ctx(make_mock_response(200, {"access_token": token, "token_type": "Bearer"}))
        with patch("httpx.AsyncClient", return_value=ctx):
            result = await _post_token_endpoint(
                "https://login.example.com/token",
                {"grant_type": "client_credentials", "client_id": "abc", "client_secret": "s"},
            )

        assert "request" in result
        assert "response" in result
        assert "tokens" in result
        assert result["response"]["status"] == 200

    async def test_client_secret_masked(self, prefill_oidc):
        from app.auth.flows import _post_token_endpoint

        ctx, _ = make_httpx_ctx(make_mock_response(200, {"access_token": make_jwt()}))
        with patch("httpx.AsyncClient", return_value=ctx):
            result = await _post_token_endpoint(
                "https://login.example.com/token",
                {"client_id": "abc", "client_secret": "my-big-secret"},
            )

        assert result["request"]["body"]["client_secret"] == "[client_secret]"
        assert "my-big-secret" not in str(result)

    async def test_access_token_decoded_in_result(self, prefill_oidc):
        from app.auth.flows import _post_token_endpoint

        payload = {"sub": "app-sub", "aud": "api://test", "exp": 9_999_999_999}
        token = make_jwt(payload=payload)
        ctx, _ = make_httpx_ctx(make_mock_response(200, {"access_token": token}))
        with patch("httpx.AsyncClient", return_value=ctx):
            result = await _post_token_endpoint("https://x.com/token", {"x": "y"})

        assert result["tokens"]["access_token"]["payload"]["sub"] == "app-sub"

    async def test_non_json_response_handled_gracefully(self, prefill_oidc):
        from app.auth.flows import _post_token_endpoint

        bad_resp = MagicMock()
        bad_resp.status_code = 500
        bad_resp.json.side_effect = Exception("not json")
        bad_resp.text = "Internal Server Error"
        bad_resp.headers = {}
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=AsyncMock(post=AsyncMock(return_value=bad_resp)))
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            result = await _post_token_endpoint("https://x.com/token", {"x": "y"})

        assert result["response"]["body"] == {"raw": "Internal Server Error"}

    async def test_error_response_status_preserved(self, prefill_oidc):
        from app.auth.flows import _post_token_endpoint

        ctx, _ = make_httpx_ctx(make_mock_response(401, {"error": "invalid_client"}))
        with patch("httpx.AsyncClient", return_value=ctx):
            result = await _post_token_endpoint("https://x.com/token", {"x": "y"})

        assert result["response"]["status"] == 401


# ────────────────────────────────────────────────────────────────
# _call_resource
# ────────────────────────────────────────────────────────────────

class TestCallResource:
    async def test_graph_app_only_calls_organization_endpoint(self, prefill_oidc):
        from app.auth.flows import _call_resource

        # App-only token: no scp / upn
        app_token = make_jwt(payload={"sub": "app", "idtyp": "app", "exp": 9_999_999_999})
        ctx, client = make_httpx_ctx(make_mock_response(200, {"id": "tenant-id"}))
        with patch("httpx.AsyncClient", return_value=ctx):
            step = await _call_resource(
                access_token=app_token, scope="https://graph.microsoft.com/.default"
            )

        assert step["label"] == "Call Graph /organization"
        assert "/organization" in client.get.call_args[0][0]

    async def test_graph_delegated_calls_me_endpoint(self, prefill_oidc):
        from app.auth.flows import _call_resource

        # Delegated token: has scp
        user_token = make_jwt(payload={"sub": "user", "scp": "User.Read", "exp": 9_999_999_999})
        ctx, client = make_httpx_ctx(make_mock_response(200, {"displayName": "Alice"}))
        with patch("httpx.AsyncClient", return_value=ctx):
            step = await _call_resource(
                access_token=user_token, scope="https://graph.microsoft.com/User.Read"
            )

        assert step["label"] == "Call Graph /me"
        assert "/me" in client.get.call_args[0][0]

    async def test_api_a_scope_calls_api_a_endpoint(self, prefill_oidc):
        from app.auth.flows import _call_resource

        ctx, client = make_httpx_ctx(make_mock_response(200, {"user": "testuser"}))
        with patch("httpx.AsyncClient", return_value=ctx):
            step = await _call_resource(
                access_token=make_jwt(), scope=f"api://{FAKE_API_A_ID}/access_as_user"
            )

        assert step["label"] == "Call API A"
        assert "8001" in client.get.call_args[0][0]

    async def test_api_b_scope_calls_api_b_endpoint(self, prefill_oidc):
        from app.auth.flows import _call_resource

        ctx, client = make_httpx_ctx(make_mock_response(200, {"data": "secret"}))
        with patch("httpx.AsyncClient", return_value=ctx):
            step = await _call_resource(
                access_token=make_jwt(), scope=f"api://{FAKE_API_B_ID}/read"
            )

        assert step["label"] == "Call API B"
        assert "8002" in client.get.call_args[0][0]

    async def test_unknown_scope_returns_skip_step_without_network(self, prefill_oidc):
        from app.auth.flows import _call_resource

        # No httpx mock needed — function returns early
        step = await _call_resource(access_token="token", scope="api://unknown-app/.default")
        assert "Skipped" in step["label"]

    async def test_access_token_decoded_in_step_tokens(self, prefill_oidc):
        from app.auth.flows import _call_resource

        payload = {"sub": "user-99", "scp": "User.Read", "exp": 9_999_999_999}
        token = make_jwt(payload=payload)
        ctx, _ = make_httpx_ctx(make_mock_response(200, {"displayName": "Bob"}))
        with patch("httpx.AsyncClient", return_value=ctx):
            step = await _call_resource(
                access_token=token, scope="https://graph.microsoft.com/User.Read"
            )

        assert step["tokens"]["access_token"]["payload"]["sub"] == "user-99"

    async def test_connection_error_returns_error_step(self, prefill_oidc):
        from app.auth.flows import _call_resource
        import httpx as httpx_mod

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx_mod.ConnectError("Connection refused")
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=mock_client)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=ctx):
            step = await _call_resource(
                access_token=make_jwt(), scope=f"api://{FAKE_API_A_ID}/.default"
            )

        assert step["response"]["status"] == 0
        assert "error" in step["response"]["body"]


# ────────────────────────────────────────────────────────────────
# execute_client_credentials
# ────────────────────────────────────────────────────────────────

class TestExecuteClientCredentials:
    async def test_returns_steps_list(self, prefill_oidc):
        from app.auth.flows import execute_client_credentials

        token = make_jwt(payload={"sub": "app", "aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})
        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": token}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"data": "result"}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2]):
            result = await execute_client_credentials(scope=f"api://{FAKE_API_B_ID}/.default")

        assert "steps" in result
        assert len(result["steps"]) >= 2

    async def test_step_has_required_shape(self, prefill_oidc):
        from app.auth.flows import execute_client_credentials

        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": make_jwt()}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"ok": True}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2]):
            result = await execute_client_credentials(scope=f"api://{FAKE_API_B_ID}/.default")

        for step in result["steps"]:
            assert "label" in step
            assert "description" in step
            assert "tokens" in step
            assert "highlights" in step

    async def test_cc_step_label_present(self, prefill_oidc):
        from app.auth.flows import execute_client_credentials

        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": make_jwt()}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2]):
            result = await execute_client_credentials(scope=f"api://{FAKE_API_B_ID}/.default")

        labels = [s["label"] for s in result["steps"]]
        assert any("Client Credentials" in l for l in labels)

    async def test_scope_coercion_sent_to_token_endpoint(self, prefill_oidc):
        """Delegated scope is coerced to /.default before the POST."""
        from app.auth.flows import execute_client_credentials

        ctx1, client = make_httpx_ctx(make_mock_response(200, {"access_token": make_jwt()}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2]):
            # Pass a named (non-/.default) scope
            await execute_client_credentials(scope=f"api://{FAKE_API_B_ID}/read")

        import urllib.parse
        body_bytes = client.post.call_args[1].get("content", b"")
        body_str = body_bytes.decode() if isinstance(body_bytes, bytes) else str(body_bytes)
        decoded_body = urllib.parse.unquote(body_str)
        assert "/.default" in decoded_body

    async def test_oidc_discovery_step_added_on_cache_miss(self, patch_settings):
        """When the OIDC cache is empty, a discovery step is prepended."""
        from app.auth.flows import execute_client_credentials

        discovery_doc = {**_OIDC_CACHE, "jwks_uri": "https://login.example.com/keys"}
        ctx_disc, _ = make_httpx_ctx(make_mock_response(200, discovery_doc))
        ctx_tok, _ = make_httpx_ctx(make_mock_response(200, {"access_token": make_jwt()}))
        ctx_res, _ = make_httpx_ctx(make_mock_response(200, {"ok": True}))

        with patch("httpx.AsyncClient", side_effect=[ctx_disc, ctx_tok, ctx_res]):
            result = await execute_client_credentials(scope="https://graph.microsoft.com/.default")

        labels = [s["label"] for s in result["steps"]]
        assert "OIDC Discovery" in labels

    async def test_token_error_results_in_skipped_resource_call(self, prefill_oidc):
        from app.auth.flows import execute_client_credentials

        ctx, _ = make_httpx_ctx(make_mock_response(400, {"error": "invalid_client"}))

        with patch("httpx.AsyncClient", return_value=ctx):
            result = await execute_client_credentials(scope=f"api://{FAKE_API_B_ID}/.default")

        labels = [s["label"] for s in result["steps"]]
        assert any("Skipped" in l or "Call Resource" in l for l in labels)


# ────────────────────────────────────────────────────────────────
# execute_obo
# ────────────────────────────────────────────────────────────────

class TestExecuteObo:
    async def test_returns_steps_list(self, prefill_oidc):
        from app.auth.flows import execute_obo

        user_token = make_jwt(payload={"sub": "user-1", "scp": "access_as_user", "exp": 9_999_999_999})
        obo_token = make_jwt(payload={"sub": "user-1", "aud": f"api://{FAKE_API_B_ID}", "scp": "read", "exp": 9_999_999_999})

        # Calls: (1) GET API A /me, (2) POST token (OBO), (3) GET API B /data
        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"user": "testuser"}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"access_token": obo_token}))
        ctx3, _ = make_httpx_ctx(make_mock_response(200, {"data": "downstream-data"}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2, ctx3]):
            result = await execute_obo(
                user_access_token=user_token,
                scope=f"api://{FAKE_API_B_ID}/.default",
            )

        assert "steps" in result
        assert len(result["steps"]) >= 2

    async def test_obo_exchange_step_present(self, prefill_oidc):
        from app.auth.flows import execute_obo

        user_token = make_jwt(payload={"sub": "user-1", "scp": "access_as_user", "exp": 9_999_999_999})
        obo_token = make_jwt(payload={"sub": "user-1", "aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})

        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"user": "testuser"}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"access_token": obo_token}))
        ctx3, _ = make_httpx_ctx(make_mock_response(200, {"data": "result"}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2, ctx3]):
            result = await execute_obo(
                user_access_token=user_token,
                scope=f"api://{FAKE_API_B_ID}/.default",
            )

        labels = [s["label"] for s in result["steps"]]
        assert any("OBO" in l or "On-Behalf" in l for l in labels)

    async def test_obo_exchange_uses_user_token_as_assertion(self, prefill_oidc):
        from app.auth.flows import execute_obo

        user_token = make_jwt(payload={"sub": "user-99", "scp": "access_as_user", "exp": 9_999_999_999})

        ctx1, _ = make_httpx_ctx(make_mock_response(200, {}))
        ctx2, obo_client = make_httpx_ctx(make_mock_response(200, {"access_token": make_jwt()}))
        ctx3, _ = make_httpx_ctx(make_mock_response(200, {}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2, ctx3]):
            await execute_obo(
                user_access_token=user_token,
                scope=f"api://{FAKE_API_B_ID}/.default",
            )

        # The OBO POST body should contain the user token as assertion
        body_bytes = obo_client.post.call_args[1].get("content", b"")
        body_str = body_bytes.decode() if isinstance(body_bytes, bytes) else str(body_bytes)
        assert "assertion=" in body_str
        assert "on_behalf_of" in body_str


# ────────────────────────────────────────────────────────────────
# execute_agent_id_obo — via_api_a: prefix routing
# ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestExecuteAgentIdOboRouting:
    """Tests that via_api_a: prefix correctly routes to the chained path."""

    async def test_via_api_a_prefix_uses_chained_path(self, prefill_oidc):
        """via_api_a:<scope> should call API A before the downstream resource."""
        from app.auth.flows import execute_agent_id_obo

        user_token = make_jwt(payload={"sub": "user-1", "scp": "access_as_user", "exp": 9_999_999_999})
        parent_token = make_jwt(payload={"aud": "api://AzureADTokenExchange", "exp": 9_999_999_999})
        api_a_token = make_jwt(payload={"aud": f"api://{FAKE_API_A_ID}", "exp": 9_999_999_999})
        api_b_token = make_jwt(payload={"aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})

        # 5 calls: parent token, OBO→API A, Call API A, OBO→API B, Call API B
        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"access_token": api_a_token}))
        ctx3, _ = make_httpx_ctx(make_mock_response(200, {"user": "api-a-user"}))
        ctx4, _ = make_httpx_ctx(make_mock_response(200, {"access_token": api_b_token}))
        ctx5, _ = make_httpx_ctx(make_mock_response(200, {"data": "api-b-data"}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2, ctx3, ctx4, ctx5]):
            result = await execute_agent_id_obo(
                user_token=user_token,
                scope=f"via_api_a:api://{FAKE_API_B_ID}/.default",
            )

        labels = [s["label"] for s in result["steps"]]
        assert any("API A" in l and ("Call" in l or "OBO" in l) for l in labels), (
            f"Expected a 'Call API A' or 'OBO.*API A' step; got: {labels}"
        )

    async def test_via_api_a_strips_prefix_from_downstream_scope(self, prefill_oidc):
        """The downstream OBO exchange should use the bare scope, not via_api_a:scope."""
        from app.auth.flows import execute_agent_id_obo

        user_token = make_jwt(payload={"sub": "u1", "scp": "access_as_user", "exp": 9_999_999_999})
        parent_token = make_jwt(payload={"exp": 9_999_999_999})
        api_a_token = make_jwt(payload={"aud": f"api://{FAKE_API_A_ID}", "exp": 9_999_999_999})
        api_b_token = make_jwt(payload={"aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})

        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"access_token": api_a_token}))
        ctx3, _ = make_httpx_ctx(make_mock_response(200, {}))
        ctx4, obo_client = make_httpx_ctx(make_mock_response(200, {"access_token": api_b_token}))
        ctx5, _ = make_httpx_ctx(make_mock_response(200, {}))

        downstream = f"api://{FAKE_API_B_ID}/.default"
        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2, ctx3, ctx4, ctx5]):
            await execute_agent_id_obo(
                user_token=user_token,
                scope=f"via_api_a:{downstream}",
            )

        # The 4th httpx call is the downstream OBO — verify the scope is the bare value
        body_bytes = obo_client.post.call_args[1].get("content", b"")
        body_str = body_bytes.decode() if isinstance(body_bytes, bytes) else str(body_bytes)
        assert FAKE_API_B_ID in body_str, "Downstream OBO should request API B scope"
        assert "via_api_a" not in body_str, "via_api_a: prefix must be stripped before OBO call"

    async def test_direct_scope_skips_api_a(self, prefill_oidc):
        """A plain API B scope (no prefix) should NOT call API A first."""
        from app.auth.flows import execute_agent_id_obo

        user_token = make_jwt(payload={"sub": "u1", "scp": "access_as_user", "exp": 9_999_999_999})
        parent_token = make_jwt(payload={"exp": 9_999_999_999})
        api_b_token = make_jwt(payload={"aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})

        # 3 calls: parent token, OBO→API B, Call API B
        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"access_token": api_b_token}))
        ctx3, _ = make_httpx_ctx(make_mock_response(200, {"data": "b"}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2, ctx3]):
            result = await execute_agent_id_obo(
                user_token=user_token,
                scope=f"api://{FAKE_API_B_ID}/.default",
            )

        labels = [s["label"] for s in result["steps"]]
        assert not any("Call API A" in l for l in labels), (
            f"Direct scope should skip API A; got steps: {labels}"
        )


# ────────────────────────────────────────────────────────────────
# diagram_index — every step carries a rect index for the sequence diagram
# ────────────────────────────────────────────────────────────────

class TestDiagramIndex:
    """Each execute_* function must tag steps with diagram_index so the UI
    highlights the correct SVG rect regardless of whether OIDC Discovery or
    Token Handoff steps are inserted.

    Indices map to diagram rects:
      -1  = no rect (OIDC Discovery, Token Handoff)
    CC / agent_id_autonomous flows:    0=parent/CC, 1=exchange/call-API-A, ...
    obo / agent_id_obo flows:          0=Authorize, 1=Exchange come from
                                       auth_callback; execute_* starts at 2.
    """

    def test_oidc_discovery_step_diagram_index_is_minus_one(self, patch_settings):
        from app.auth.flows import _oidc_discovery_step
        step = _oidc_discovery_step()
        assert step.get("diagram_index") == -1, (
            f"OIDC Discovery step must have diagram_index=-1, got {step.get('diagram_index')!r}"
        )

    async def test_execute_client_credentials_diagram_indices(self, prefill_oidc):
        """CC step → diagram_index=0, Call Resource → diagram_index=1."""
        from app.auth.flows import execute_client_credentials

        token = make_jwt(payload={"aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})
        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": token}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"data": "ok"}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2]):
            result = await execute_client_credentials(scope=f"api://{FAKE_API_B_ID}/.default")

        steps = result["steps"]
        assert len(steps) == 2, f"Expected 2 steps (no OIDC prefill), got {len(steps)}: {[s['label'] for s in steps]}"
        assert steps[0].get("diagram_index") == 0, f"CC step should be index 0, got {steps[0].get('diagram_index')!r}"
        assert steps[1].get("diagram_index") == 1, f"Call Resource should be index 1, got {steps[1].get('diagram_index')!r}"

    async def test_execute_client_credentials_chain_diagram_indices(self, prefill_oidc):
        """CC API A=0, Call API A=1, CC downstream=2, Call downstream=3."""
        from app.auth.flows import execute_client_credentials_chain

        cc_token = make_jwt(payload={"aud": f"api://{FAKE_API_A_ID}", "exp": 9_999_999_999})
        downstream_token = make_jwt(payload={"aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})
        api_a_chain_resp = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {"access_token": downstream_token},
            "downstream_response": {"data": "b"},
            "downstream_url": "http://localhost:8002/data",
        }
        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": cc_token}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, api_a_chain_resp))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2]):
            result = await execute_client_credentials_chain(scope=f"chain:api://{FAKE_API_B_ID}/.default")

        steps = result["steps"]
        indices = [s.get("diagram_index") for s in steps]
        assert len(steps) == 4, f"Expected 4 steps, got {len(steps)}: {[s['label'] for s in steps]}"
        assert indices == [0, 1, 2, 3], f"Expected [0,1,2,3], got {indices}"

    async def test_execute_obo_diagram_indices(self, prefill_oidc):
        """OBO steps start at index 2 (S0/S1 are Authorize/Exchange from auth_callback)."""
        from app.auth.flows import execute_obo

        user_token = make_jwt(payload={"scp": "access_as_user", "exp": 9_999_999_999})
        obo_token = make_jwt(payload={"aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})
        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"data": "api-a"}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"access_token": obo_token}))
        ctx3, _ = make_httpx_ctx(make_mock_response(200, {"data": "api-b"}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2, ctx3]):
            result = await execute_obo(
                user_access_token=user_token, scope=f"api://{FAKE_API_B_ID}/.default"
            )

        steps = result["steps"]
        indices = [s.get("diagram_index") for s in steps]
        assert len(steps) == 3, f"Expected 3 steps, got {len(steps)}: {[s['label'] for s in steps]}"
        assert indices == [2, 3, 4], f"Expected [2,3,4], got {indices}"

    async def test_execute_agent_id_autonomous_diagram_indices(self, prefill_oidc):
        """Parent Token=0, FMI Exchange=1, Call Resource=2."""
        from app.auth.flows import execute_agent_id_autonomous

        parent_token = make_jwt(payload={"aud": "api://AzureADTokenExchange", "exp": 9_999_999_999})
        agent_token = make_jwt(payload={"aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})
        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"access_token": agent_token}))
        ctx3, _ = make_httpx_ctx(make_mock_response(200, {"data": "ok"}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2, ctx3]):
            result = await execute_agent_id_autonomous(scope=f"api://{FAKE_API_B_ID}/.default")

        steps = result["steps"]
        indices = [s.get("diagram_index") for s in steps]
        assert len(steps) == 3, f"Expected 3 steps, got {len(steps)}: {[s['label'] for s in steps]}"
        assert indices == [0, 1, 2], f"Expected [0,1,2], got {indices}"

    async def test_execute_agent_id_autonomous_chain_diagram_indices(self, prefill_oidc):
        """Parent=0, FMI Exchange=1, Call API A=2, CC downstream=3, Call downstream=4."""
        from app.auth.flows import execute_agent_id_autonomous_chain

        parent_token = make_jwt(payload={"aud": "api://AzureADTokenExchange", "exp": 9_999_999_999})
        api_a_token = make_jwt(payload={"aud": f"api://{FAKE_API_A_ID}", "exp": 9_999_999_999})
        downstream_token = make_jwt(payload={"aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})
        api_a_chain_resp = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {"access_token": downstream_token},
            "downstream_response": {"data": "b"},
            "downstream_url": "http://localhost:8002/data",
        }
        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"access_token": api_a_token}))
        ctx3, _ = make_httpx_ctx(make_mock_response(200, api_a_chain_resp))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2, ctx3]):
            result = await execute_agent_id_autonomous_chain(scope=f"chain:api://{FAKE_API_B_ID}/.default")

        steps = result["steps"]
        indices = [s.get("diagram_index") for s in steps]
        assert len(steps) == 5, f"Expected 5 steps, got {len(steps)}: {[s['label'] for s in steps]}"
        assert indices == [0, 1, 2, 3, 4], f"Expected [0,1,2,3,4], got {indices}"

    async def test_execute_agent_id_obo_direct_diagram_indices(self, prefill_oidc):
        """Direct path: Parent=2, OBO Exchange=3, Call Resource=4."""
        from app.auth.flows import execute_agent_id_obo

        user_token = make_jwt(payload={"sub": "u1", "scp": "access_as_user", "exp": 9_999_999_999})
        parent_token = make_jwt(payload={"exp": 9_999_999_999})
        api_b_token = make_jwt(payload={"aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})
        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"access_token": api_b_token}))
        ctx3, _ = make_httpx_ctx(make_mock_response(200, {"data": "b"}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2, ctx3]):
            result = await execute_agent_id_obo(
                user_token=user_token, scope=f"api://{FAKE_API_B_ID}/.default"
            )

        steps = result["steps"]
        indices = [s.get("diagram_index") for s in steps]
        assert len(steps) == 3, f"Expected 3 steps, got {len(steps)}: {[s['label'] for s in steps]}"
        assert indices == [2, 3, 4], f"Expected [2,3,4], got {indices}"

    async def test_execute_agent_id_obo_chained_diagram_indices(self, prefill_oidc):
        """Chained: Parent=2, OBO Agent→API A=3, Call API A=4, OBO API A→B=5, Call API B=6."""
        from app.auth.flows import execute_agent_id_obo

        user_token = make_jwt(payload={"sub": "u1", "scp": "access_as_user", "exp": 9_999_999_999})
        parent_token = make_jwt(payload={"exp": 9_999_999_999})
        api_a_token = make_jwt(payload={"aud": f"api://{FAKE_API_A_ID}", "exp": 9_999_999_999})
        api_b_token = make_jwt(payload={"aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})
        ctx1, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx2, _ = make_httpx_ctx(make_mock_response(200, {"access_token": api_a_token}))
        ctx3, _ = make_httpx_ctx(make_mock_response(200, {"user": "api-a-user"}))
        ctx4, _ = make_httpx_ctx(make_mock_response(200, {"access_token": api_b_token}))
        ctx5, _ = make_httpx_ctx(make_mock_response(200, {"data": "b"}))

        with patch("httpx.AsyncClient", side_effect=[ctx1, ctx2, ctx3, ctx4, ctx5]):
            result = await execute_agent_id_obo(
                user_token=user_token,
                scope=f"via_api_a:api://{FAKE_API_B_ID}/.default",
            )

        steps = result["steps"]
        indices = [s.get("diagram_index") for s in steps]
        assert len(steps) == 5, f"Expected 5 steps, got {len(steps)}: {[s['label'] for s in steps]}"
        assert indices == [2, 3, 4, 5, 6], f"Expected [2,3,4,5,6], got {indices}"
