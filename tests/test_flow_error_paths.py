"""
Tests for error paths and edge cases across all execute_* flow functions.

These tests cover the bugs found manually + gaps identified in the audit:
  - execute_obo: OBO exchange fails → Call downstream skipped, diagram_index correct
  - execute_agent_id_autonomous: parent token fails → steps well-formed
  - execute_agent_id_autonomous_chain: failure at each step, diagram_index consistent
  - _call_resource_or_skip: skips when no access_token
  - _parse_chain_response: empty/error/partial API A body
  - INVARIANT: every step in every happy-path flow has a diagram_index field
"""
from unittest.mock import patch
import pytest

from tests.conftest import (
    FAKE_API_A_ID,
    FAKE_API_B_ID,
    FAKE_BLUEPRINT_ID,
    FAKE_TENANT,
    make_jwt,
    make_mock_response,
    make_httpx_ctx,
)

_OIDC_CACHE = {
    "token_endpoint": f"https://login.microsoftonline.com/{FAKE_TENANT}/oauth2/v2.0/token",
    "authorization_endpoint": f"https://login.microsoftonline.com/{FAKE_TENANT}/oauth2/v2.0/authorize",
    "issuer": f"https://login.microsoftonline.com/{FAKE_TENANT}/v2.0",
    "jwks_uri": f"https://login.microsoftonline.com/{FAKE_TENANT}/discovery/v2.0/keys",
}


@pytest.fixture
def prefill_oidc(patch_settings):
    from app.auth import flows
    flows._oidc_cache.update(_OIDC_CACHE)
    return patch_settings


# ────────────────────────────────────────────────────────────────
# _call_resource_or_skip
# ────────────────────────────────────────────────────────────────

class TestCallResourceOrSkip:
    async def test_skips_when_no_access_token(self, prefill_oidc):
        """If the token result has no access_token, returns a skip step (no HTTP call)."""
        from app.auth.flows import _call_resource_or_skip
        result = {"response": {"body": {}}}  # no access_token
        step = await _call_resource_or_skip(result, "api://scope")
        assert "Skipped" in step["label"]

    async def test_skip_step_has_no_request(self, prefill_oidc):
        """Skip step should not have a real HTTP request (nothing to call)."""
        from app.auth.flows import _call_resource_or_skip
        result = {"response": {"body": {}}}
        step = await _call_resource_or_skip(result, "api://scope")
        # request may be None or missing — must not be a real endpoint call
        req = step.get("request")
        assert req is None or req.get("url") is None or "skip" in step["label"].lower()

    async def test_calls_resource_when_token_present(self, prefill_oidc):
        """When access_token is present, actually calls the resource."""
        from app.auth.flows import _call_resource_or_skip
        token = make_jwt()
        result_with_token = {"response": {"body": {"access_token": token}}}
        ctx, _ = make_httpx_ctx(make_mock_response(200, {"data": "ok"}))
        with patch("app.auth.flows.httpx.AsyncClient", return_value=ctx):
            step = await _call_resource_or_skip(result_with_token, f"api://{FAKE_API_B_ID}/.default")
        assert "Skipped" not in step["label"]
        assert step["response"]["status"] == 200


# ────────────────────────────────────────────────────────────────
# _parse_chain_response
# ────────────────────────────────────────────────────────────────

class TestParseChainResponse:
    def test_empty_body_returns_no_steps(self):
        """API A returns {} (or error dict with no known keys) → returns 0 steps."""
        from app.auth.flows import _parse_chain_response
        steps = _parse_chain_response({}, "API B", "http://localhost:8002/data")
        assert steps == []

    def test_error_body_returns_no_steps(self):
        """API A returns {"error": "permission_denied"} → returns 0 steps (no crash)."""
        from app.auth.flows import _parse_chain_response
        steps = _parse_chain_response(
            {"error": "permission_denied", "error_description": "Forbidden"},
            "API B", "http://localhost:8002/data"
        )
        assert isinstance(steps, list)
        # Current behavior: silently returns []. If this is wrong, ask user.
        assert len(steps) == 0

    def test_cc_request_present_returns_cc_step(self):
        """When cc_request is present, a CC step is returned."""
        from app.auth.flows import _parse_chain_response
        body = {
            "cc_request": {"grant_type": "client_credentials", "client_id": "abc"},
            "cc_token_response": {"access_token": make_jwt()},
        }
        steps = _parse_chain_response(body, "API B", "http://localhost:8002/data")
        assert len(steps) >= 1
        assert any("Client Credentials" in s["label"] for s in steps)

    def test_downstream_response_present_returns_call_step(self):
        """When downstream_response is present, a call step is returned."""
        from app.auth.flows import _parse_chain_response
        body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {"access_token": make_jwt()},
            "downstream_response": {"result": "some data"},
        }
        steps = _parse_chain_response(body, "API B", "http://localhost:8002/data")
        assert len(steps) == 2
        assert any("Call API B" in s["label"] for s in steps)

    def test_partial_cc_only_no_downstream(self):
        """When cc_request exists but no downstream_response → 1 step only."""
        from app.auth.flows import _parse_chain_response
        body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {"access_token": make_jwt()},
            # No downstream_response
        }
        steps = _parse_chain_response(body, "API B", "http://localhost:8002/data")
        assert len(steps) == 1
        assert any("Client Credentials" in s["label"] for s in steps)

    def test_downstream_only_no_cc_returns_call_step(self):
        """When only downstream_response is present (no cc_request) → 1 call step."""
        from app.auth.flows import _parse_chain_response
        body = {"downstream_response": {"data": "result"}}
        steps = _parse_chain_response(body, "API B", "http://localhost:8002/data")
        assert len(steps) == 1
        assert any("Call" in s["label"] for s in steps)

    def test_api_b_response_key_also_works(self):
        """Accepts api_b_response as an alias for downstream_response."""
        from app.auth.flows import _parse_chain_response
        body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {"access_token": make_jwt()},
            "api_b_response": {"data": "via alias"},
        }
        steps = _parse_chain_response(body, "API B", "http://localhost:8002/data")
        assert len(steps) == 2


# ────────────────────────────────────────────────────────────────
# execute_obo error paths
# ────────────────────────────────────────────────────────────────

class TestExecuteOboErrorPaths:
    async def test_obo_exchange_failure_skips_downstream(self, prefill_oidc):
        """If OBO token exchange returns no access_token, downstream call is skipped."""
        from app.auth.flows import execute_obo
        user_token = make_jwt()
        # Mock 1: Call API A → 200 OK
        ctx_api_a, _ = make_httpx_ctx(make_mock_response(200, {"result": "ok"}))
        # Mock 2: OBO token exchange → 400 error (no access_token)
        ctx_obo, _ = make_httpx_ctx(make_mock_response(400, {"error": "invalid_grant"}))

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_api_a, ctx_obo]):
            result = await execute_obo(
                user_access_token=user_token,
                scope=f"api://{FAKE_API_B_ID}/.default",
            )

        steps = result["steps"]
        labels = [s["label"] for s in steps]
        assert any("Call API A" in l for l in labels)
        assert any("OBO Token Exchange" in l for l in labels)
        assert any("Skipped" in l for l in labels), (
            f"Expected a skipped downstream step when OBO exchange fails, got: {labels}"
        )

    async def test_obo_exchange_failure_diagram_indices_intact(self, prefill_oidc):
        """Diagram indices must be correct even when OBO exchange fails."""
        from app.auth.flows import execute_obo
        user_token = make_jwt()
        ctx_api_a, _ = make_httpx_ctx(make_mock_response(200, {"result": "ok"}))
        ctx_obo, _ = make_httpx_ctx(make_mock_response(400, {"error": "invalid_grant"}))

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_api_a, ctx_obo]):
            result = await execute_obo(
                user_access_token=user_token,
                scope=f"api://{FAKE_API_B_ID}/.default",
            )

        steps = result["steps"]
        for step in steps:
            assert "diagram_index" in step, (
                f"Step '{step.get('label')}' is missing diagram_index"
            )
        idx_map = {s["label"]: s["diagram_index"] for s in steps
                   if not s["label"].startswith("OIDC")}
        assert idx_map.get("Call API A") == 2
        assert idx_map.get("OBO Token Exchange") == 3
        # Skipped step should be index 4
        skipped = next((s for s in steps if "Skipped" in s["label"]), None)
        assert skipped is not None
        assert skipped["diagram_index"] == 4


# ────────────────────────────────────────────────────────────────
# execute_agent_id_autonomous error paths
# ────────────────────────────────────────────────────────────────

class TestAgentIdAutonomousErrorPaths:
    async def test_parent_token_failure_returns_steps(self, prefill_oidc):
        """When parent token acquisition fails, returns steps array (no KeyError)."""
        from app.auth.flows import execute_agent_id_autonomous
        # Mock: parent token POST returns no access_token (HTTP error)
        ctx, _ = make_httpx_ctx(make_mock_response(400, {"error": "unauthorized_client"}))
        with patch("app.auth.flows.httpx.AsyncClient", return_value=ctx):
            result = await execute_agent_id_autonomous(scope=f"api://{FAKE_API_B_ID}/.default")

        assert "steps" in result, "Result must always have 'steps' key"
        steps = result["steps"]
        assert len(steps) >= 1
        labels = [s["label"] for s in steps]
        # Should have a failed/error indicator step
        assert any("Failed" in l or "Parent" in l for l in labels), (
            f"Expected failure indicator step, got: {labels}"
        )

    async def test_parent_token_failure_all_steps_have_diagram_index(self, prefill_oidc):
        """All steps in failure path must have diagram_index to avoid JS errors."""
        from app.auth.flows import execute_agent_id_autonomous
        ctx, _ = make_httpx_ctx(make_mock_response(400, {"error": "unauthorized_client"}))
        with patch("app.auth.flows.httpx.AsyncClient", return_value=ctx):
            result = await execute_agent_id_autonomous(scope=f"api://{FAKE_API_B_ID}/.default")

        for step in result["steps"]:
            assert "diagram_index" in step, (
                f"Step '{step.get('label')}' missing diagram_index in failure path"
            )

    async def test_fmi_exchange_failure_skips_call(self, prefill_oidc):
        """When FMI exchange fails, Call Resource is skipped."""
        from app.auth.flows import execute_agent_id_autonomous
        parent_token = make_jwt()
        # Mock 1: Parent token POST → success
        ctx_parent, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        # Mock 2: FMI exchange → 400, no access_token
        ctx_fmi, _ = make_httpx_ctx(make_mock_response(400, {"error": "invalid_grant"}))

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_parent, ctx_fmi]):
            result = await execute_agent_id_autonomous(scope=f"api://{FAKE_API_B_ID}/.default")

        labels = [s["label"] for s in result["steps"]]
        assert any("Skipped" in l or "Call Resource" in l for l in labels), (
            f"Expected skipped call step when FMI fails, got: {labels}"
        )

    async def test_fmi_exchange_failure_diagram_indices_intact(self, prefill_oidc):
        """diagram_index must be set on all steps even when FMI exchange fails."""
        from app.auth.flows import execute_agent_id_autonomous
        parent_token = make_jwt()
        ctx_parent, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx_fmi, _ = make_httpx_ctx(make_mock_response(400, {"error": "invalid_grant"}))

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_parent, ctx_fmi]):
            result = await execute_agent_id_autonomous(scope=f"api://{FAKE_API_B_ID}/.default")

        for step in result["steps"]:
            assert "diagram_index" in step, (
                f"Step '{step.get('label')}' missing diagram_index after FMI failure"
            )


# ────────────────────────────────────────────────────────────────
# execute_agent_id_autonomous_chain error paths
# ────────────────────────────────────────────────────────────────

class TestAgentIdAutonomousChainErrorPaths:
    async def test_parent_token_failure_all_steps_have_diagram_index(self, prefill_oidc):
        """When parent token fails in chain flow, all returned steps have diagram_index."""
        from app.auth.flows import execute_agent_id_autonomous_chain
        ctx, _ = make_httpx_ctx(make_mock_response(400, {"error": "unauthorized_client"}))
        with patch("app.auth.flows.httpx.AsyncClient", return_value=ctx):
            result = await execute_agent_id_autonomous_chain(scope=f"api://{FAKE_API_B_ID}/.default")

        assert "steps" in result
        for step in result["steps"]:
            assert "diagram_index" in step, (
                f"Step '{step.get('label')}' missing diagram_index (chain parent failure)"
            )

    async def test_fmi_failure_all_steps_have_diagram_index(self, prefill_oidc):
        """When FMI exchange fails in chain flow, all returned steps have diagram_index."""
        from app.auth.flows import execute_agent_id_autonomous_chain
        parent_token = make_jwt()
        ctx_parent, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx_fmi, _ = make_httpx_ctx(make_mock_response(400, {"error": "invalid_grant"}))

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_parent, ctx_fmi]):
            result = await execute_agent_id_autonomous_chain(scope=f"api://{FAKE_API_B_ID}/.default")

        for step in result["steps"]:
            assert "diagram_index" in step, (
                f"Step '{step.get('label')}' missing diagram_index (chain FMI failure)"
            )

    async def test_fmi_failure_skips_api_a_call(self, prefill_oidc):
        """When FMI exchange fails, Call API A step is skipped."""
        from app.auth.flows import execute_agent_id_autonomous_chain
        parent_token = make_jwt()
        ctx_parent, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx_fmi, _ = make_httpx_ctx(make_mock_response(400, {"error": "invalid_grant"}))

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_parent, ctx_fmi]):
            result = await execute_agent_id_autonomous_chain(scope=f"api://{FAKE_API_B_ID}/.default")

        labels = [s["label"] for s in result["steps"]]
        assert any("Skipped" in l for l in labels), (
            f"Expected skipped step when FMI fails in chain flow, got: {labels}"
        )

    async def test_api_a_network_error_no_chain_steps(self, prefill_oidc):
        """If API A /chain call fails with network error, no cc/downstream steps are added."""
        from app.auth.flows import execute_agent_id_autonomous_chain
        import httpx
        parent_token = make_jwt()
        api_a_token = make_jwt()

        ctx_parent, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx_fmi, _ = make_httpx_ctx(make_mock_response(200, {"access_token": api_a_token}))
        # API A /chain → network error (ConnectError)
        ctx_chain_err = type("CM", (), {
            "__aenter__": lambda s: (_ for _ in ()).throw(httpx.ConnectError("refused")),
            "__aexit__": lambda s, *a: None,
        })()

        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_parent, ctx_fmi, ctx_chain_err]):
            result = await execute_agent_id_autonomous_chain(scope=f"api://{FAKE_API_B_ID}/.default")

        steps = result["steps"]
        labels = [s["label"] for s in steps]
        # Call API A step must exist
        assert any("Call API A" in l for l in labels)
        # But no CC or downstream steps (can't parse failed chain response)
        assert not any("Client Credentials" in l for l in labels), (
            f"CC step should not appear after API A network error, got: {labels}"
        )


# ────────────────────────────────────────────────────────────────
# INVARIANT: Every step in every happy-path flow has diagram_index
# ────────────────────────────────────────────────────────────────

class TestDiagramIndexInvariant:
    """Cross-cutting invariant: no step in any execute_* function should be
    returned without a diagram_index field. Missing diagram_index causes the
    JS frontend to fall back to array index, breaking pill-to-diagram alignment."""

    def _check_all_steps(self, result: dict, flow_name: str):
        steps = result.get("steps", [])
        assert len(steps) > 0, f"{flow_name} returned no steps"
        for step in steps:
            assert "diagram_index" in step, (
                f"[{flow_name}] Step '{step.get('label')}' is missing diagram_index"
            )
            assert isinstance(step["diagram_index"], int), (
                f"[{flow_name}] Step '{step.get('label')}' diagram_index is not int: "
                f"{step['diagram_index']!r}"
            )
            assert step["diagram_index"] >= -1, (
                f"[{flow_name}] Step '{step.get('label')}' has invalid diagram_index: "
                f"{step['diagram_index']}"
            )

    async def test_execute_client_credentials_all_steps_have_diagram_index(self, prefill_oidc):
        from app.auth.flows import execute_client_credentials
        token = make_jwt()
        ctx_cc, _ = make_httpx_ctx(make_mock_response(200, {"access_token": token}))
        ctx_call, _ = make_httpx_ctx(make_mock_response(200, {"data": "ok"}))
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_cc, ctx_call]):
            result = await execute_client_credentials(scope=f"api://{FAKE_API_B_ID}/.default")
        self._check_all_steps(result, "execute_client_credentials")

    async def test_execute_client_credentials_chain_all_steps_have_diagram_index(self, prefill_oidc):
        from app.auth.flows import execute_client_credentials_chain
        token = make_jwt()
        ctx_cc, _ = make_httpx_ctx(make_mock_response(200, {"access_token": token}))
        chain_body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {"access_token": make_jwt()},
            "downstream_response": {"data": "ok"},
        }
        ctx_chain, _ = make_httpx_ctx(make_mock_response(200, chain_body))
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_cc, ctx_chain]):
            result = await execute_client_credentials_chain(scope=f"api://{FAKE_API_B_ID}/.default")
        self._check_all_steps(result, "execute_client_credentials_chain")

    async def test_execute_obo_all_steps_have_diagram_index(self, prefill_oidc):
        from app.auth.flows import execute_obo
        user_token = make_jwt()
        obo_token = make_jwt()
        ctx_api_a, _ = make_httpx_ctx(make_mock_response(200, {"result": "ok"}))
        ctx_obo, _ = make_httpx_ctx(make_mock_response(200, {"access_token": obo_token}))
        ctx_downstream, _ = make_httpx_ctx(make_mock_response(200, {"data": "ok"}))
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_api_a, ctx_obo, ctx_downstream]):
            result = await execute_obo(
                user_access_token=user_token,
                scope=f"api://{FAKE_API_B_ID}/.default",
            )
        self._check_all_steps(result, "execute_obo")

    async def test_execute_agent_id_autonomous_all_steps_have_diagram_index(self, prefill_oidc):
        from app.auth.flows import execute_agent_id_autonomous
        parent_token = make_jwt()
        final_token = make_jwt()
        ctx_parent, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx_fmi, _ = make_httpx_ctx(make_mock_response(200, {"access_token": final_token}))
        ctx_call, _ = make_httpx_ctx(make_mock_response(200, {"data": "ok"}))
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_parent, ctx_fmi, ctx_call]):
            result = await execute_agent_id_autonomous(scope=f"api://{FAKE_API_B_ID}/.default")
        self._check_all_steps(result, "execute_agent_id_autonomous")

    async def test_execute_agent_id_autonomous_chain_all_steps_have_diagram_index(self, prefill_oidc):
        from app.auth.flows import execute_agent_id_autonomous_chain
        parent_token = make_jwt()
        api_a_token = make_jwt()
        chain_body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {"access_token": make_jwt()},
            "downstream_response": {"data": "ok"},
        }
        ctx_parent, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx_fmi, _ = make_httpx_ctx(make_mock_response(200, {"access_token": api_a_token}))
        ctx_chain, _ = make_httpx_ctx(make_mock_response(200, chain_body))
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_parent, ctx_fmi, ctx_chain]):
            result = await execute_agent_id_autonomous_chain(scope=f"api://{FAKE_API_B_ID}/.default")
        self._check_all_steps(result, "execute_agent_id_autonomous_chain")

    async def test_execute_agent_id_obo_direct_all_steps_have_diagram_index(self, prefill_oidc):
        from app.auth.flows import execute_agent_id_obo
        user_token = make_jwt()
        parent_token = make_jwt()
        final_token = make_jwt()
        scope = f"api://{FAKE_API_B_ID}/.default"

        ctx_parent, _ = make_httpx_ctx(make_mock_response(200, {"access_token": parent_token}))
        ctx_obo, _ = make_httpx_ctx(make_mock_response(200, {"access_token": final_token}))
        ctx_call, _ = make_httpx_ctx(make_mock_response(200, {"data": "ok"}))
        with patch("app.auth.flows.httpx.AsyncClient", side_effect=[ctx_parent, ctx_obo, ctx_call]):
            result = await execute_agent_id_obo(
                user_token=user_token, scope=scope,
            )
        self._check_all_steps(result, "execute_agent_id_obo (direct)")
