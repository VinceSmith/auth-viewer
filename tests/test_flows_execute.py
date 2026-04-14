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
