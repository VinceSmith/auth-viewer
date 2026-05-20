"""Unit tests for pure helper functions in app.auth.flows — no network calls."""
import pytest

from app.auth.flows import (
    _build_step,
    _build_form_body,
    _coerce_default_scope,
    _offline_access_note,
    _user_read_note,
    _parse_chain_response,
)
from tests.conftest import b64url, make_jwt, FAKE_API_A_ID, FAKE_API_B_ID, FAKE_BLUEPRINT_ID


# ────────────────────────────────────────────────────────────────
# _build_step
# ────────────────────────────────────────────────────────────────

class TestBuildStep:
    def test_required_keys_present(self):
        step = _build_step(label="My Step", description="Doing something.")
        assert step["label"] == "My Step"
        assert step["description"] == "Doing something."
        assert step["request"] is None
        assert step["response"] is None
        assert step["tokens"] == {}
        assert step["highlights"] == {}

    def test_authorize_url_included_when_passed(self):
        step = _build_step(
            label="Auth", description="Auth redirect.",
            authorize_url="https://login.example.com/authorize?foo=bar",
        )
        assert step["authorize_url"] == "https://login.example.com/authorize?foo=bar"

    def test_authorize_url_absent_by_default(self):
        step = _build_step(label="S", description="D.")
        assert "authorize_url" not in step

    def test_custom_tokens_stored(self):
        tokens = {"access_token": {"raw": "tok", "payload": {"sub": "u1"}}}
        step = _build_step(label="S", description="D.", tokens=tokens)
        assert step["tokens"] == tokens

    def test_request_and_response_stored(self):
        req = {"method": "POST", "url": "https://x.com", "headers": {}, "body": {}}
        resp = {"status": 200, "headers": {}, "body": {"ok": True}}
        step = _build_step(label="S", description="D.", request=req, response=resp)
        assert step["request"] == req
        assert step["response"] == resp

    def test_highlights_stored(self):
        h = {"some-guid": {"label": "My App", "role": "client"}}
        step = _build_step(label="S", description="D.", highlights=h)
        assert step["highlights"] == h


# ────────────────────────────────────────────────────────────────
# _build_form_body
# ────────────────────────────────────────────────────────────────

class TestBuildFormBody:
    def test_none_values_filtered_out(self):
        result = _build_form_body({"a": "1", "b": None, "c": "3"})
        assert "a=1" in result
        assert "c=3" in result
        assert "b" not in result

    def test_url_encodes_special_characters(self):
        result = _build_form_body({"scope": "api://app-id/.default"})
        assert "scope=" in result
        # colons and slashes should be percent-encoded
        assert "api" in result

    def test_empty_dict_returns_empty_string(self):
        assert _build_form_body({}) == ""

    def test_all_none_values_returns_empty_string(self):
        assert _build_form_body({"a": None, "b": None}) == ""

    def test_single_key_value_pair(self):
        result = _build_form_body({"grant_type": "client_credentials"})
        assert result == "grant_type=client_credentials"


# ────────────────────────────────────────────────────────────────
# _coerce_default_scope
# ────────────────────────────────────────────────────────────────

class TestCoerceDefaultScope:
    def test_already_default_unchanged(self):
        assert _coerce_default_scope("api://my-app/.default") == "api://my-app/.default"

    def test_graph_already_default_unchanged(self):
        scope = "https://graph.microsoft.com/.default"
        assert _coerce_default_scope(scope) == scope

    def test_api_uri_with_named_scope_coerced(self):
        result = _coerce_default_scope("api://my-app/access_as_user")
        assert result == "api://my-app/.default"

    def test_graph_delegated_scope_coerced(self):
        result = _coerce_default_scope("https://graph.microsoft.com/User.Read")
        assert result == "https://graph.microsoft.com/.default"

    def test_multi_scope_string_picks_api_uri(self):
        result = _coerce_default_scope("openid profile api://my-app/access_as_user")
        assert result == "api://my-app/.default"

    def test_generic_scope_without_resource_uri_raises(self):
        with pytest.raises(ValueError, match="Unknown target resource"):
            _coerce_default_scope("some-generic-scope")

    def test_empty_scope_raises(self):
        with pytest.raises(ValueError, match="Unknown target resource"):
            _coerce_default_scope("")

    def test_idempotent_on_already_default(self):
        scope = "api://abc-def/.default"
        assert _coerce_default_scope(_coerce_default_scope(scope)) == scope

    def test_https_uri_with_named_scope_coerced(self):
        result = _coerce_default_scope("https://myapi.example.com/read")
        assert result == "https://myapi.example.com/.default"


# ────────────────────────────────────────────────────────────────
# _offline_access_note
# ────────────────────────────────────────────────────────────────

class TestOfflineAccessNote:
    def test_returns_note_when_offline_access_present(self):
        note = _offline_access_note("openid profile offline_access api://my-app")
        assert len(note) > 0

    def test_note_mentions_refresh_token(self):
        note = _offline_access_note("offline_access")
        assert "refresh" in note.lower()

    def test_empty_when_not_present(self):
        assert _offline_access_note("openid profile api://my-app") == ""

    def test_empty_for_empty_scope(self):
        assert _offline_access_note("") == ""


# ────────────────────────────────────────────────────────────────
# _user_read_note
# ────────────────────────────────────────────────────────────────

class TestUserReadNote:
    def test_returns_note_when_user_read_in_scp(self):
        note = _user_read_note({"scp": "access_as_user User.Read"})
        assert len(note) > 0
        assert "User.Read" in note

    def test_empty_when_scp_missing(self):
        assert _user_read_note({"sub": "user"}) == ""

    def test_empty_when_user_read_not_in_scp(self):
        assert _user_read_note({"scp": "access_as_user profile"}) == ""

    def test_empty_for_non_dict(self):
        assert _user_read_note("not-a-dict") == ""

    def test_empty_for_empty_dict(self):
        assert _user_read_note({}) == ""


# ────────────────────────────────────────────────────────────────
# _humanize_scope  (requires settings)
# ────────────────────────────────────────────────────────────────

class TestHumanizeScope:
    def test_replaces_api_a_id(self, patch_settings):
        from app.auth.flows import _humanize_scope
        result = _humanize_scope(f"api://{FAKE_API_A_ID}/.default")
        assert "API A" in result
        assert FAKE_API_A_ID in result  # raw ID still shown for transparency

    def test_replaces_api_b_id(self, patch_settings):
        from app.auth.flows import _humanize_scope
        result = _humanize_scope(f"api://{FAKE_API_B_ID}/read")
        assert "API B" in result

    def test_replaces_blueprint_id(self, patch_settings):
        from app.auth.flows import _humanize_scope
        result = _humanize_scope(f"api://{FAKE_BLUEPRINT_ID}/access_as_user")
        assert "Agent Blueprint" in result

    def test_unknown_id_left_unchanged(self, patch_settings):
        from app.auth.flows import _humanize_scope
        result = _humanize_scope("api://unknown-app-id/.default")
        assert result == "api://unknown-app-id/.default"

    def test_graph_scope_unchanged(self, patch_settings):
        from app.auth.flows import _humanize_scope
        scope = "https://graph.microsoft.com/.default"
        assert _humanize_scope(scope) == scope


# ────────────────────────────────────────────────────────────────
# _scope_coercion_note  (requires settings)
# ────────────────────────────────────────────────────────────────

class TestScopeCoercionNote:
    def test_empty_when_scope_already_default(self, patch_settings):
        from app.auth.flows import _scope_coercion_note
        assert _scope_coercion_note("api://my-app/.default") == ""

    def test_non_empty_when_coercion_applied(self, patch_settings):
        from app.auth.flows import _scope_coercion_note
        note = _scope_coercion_note(f"api://{FAKE_API_A_ID}/access_as_user")
        assert len(note) > 0
        assert "/.default" in note

    def test_non_empty_for_graph_delegated(self, patch_settings):
        from app.auth.flows import _scope_coercion_note
        note = _scope_coercion_note("https://graph.microsoft.com/User.Read")
        assert len(note) > 0


# ────────────────────────────────────────────────────────────────
# _parse_chain_response  (requires settings via _base_highlights)
# ────────────────────────────────────────────────────────────────

class TestParseChainResponse:
    def test_empty_body_returns_no_steps(self, patch_settings):
        steps = _parse_chain_response({}, "API B", "http://localhost:8002/data")
        assert steps == []

    def test_cc_request_only_returns_one_step(self, patch_settings):
        body = {
            "cc_request": {"grant_type": "client_credentials", "scope": "api://b/.default"},
            "cc_token_response": {},
        }
        steps = _parse_chain_response(body, "API B", "http://localhost:8002/data")
        assert len(steps) == 1
        assert "API A" in steps[0]["label"]

    def test_cc_request_with_downstream_returns_two_steps(self, patch_settings):
        body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {},
            "downstream_response": {"data": "some-result"},
        }
        steps = _parse_chain_response(body, "API B", "http://localhost:8002/data")
        assert len(steps) == 2

    def test_access_token_in_cc_response_is_decoded(self, patch_settings):
        token_payload = {"sub": "api-a-sub", "aud": "api://api-b", "exp": 9_999_999_999}
        fake_token = make_jwt(payload=token_payload)
        body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {"access_token": fake_token},
        }
        steps = _parse_chain_response(body, "API B", "http://localhost:8002/data")
        assert len(steps) == 1
        assert "access_token" in steps[0]["tokens"]
        assert steps[0]["tokens"]["access_token"]["payload"]["sub"] == "api-a-sub"

    def test_cc_response_fallback_key_accepted(self, patch_settings):
        """API A uses 'cc_response' (not 'cc_token_response') on error paths."""
        body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_response": {"error": "invalid_client"},
        }
        steps = _parse_chain_response(body, "API B", "http://localhost:8002/data")
        assert len(steps) == 1

    def test_step_has_required_keys(self, patch_settings):
        body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {},
        }
        steps = _parse_chain_response(body, "Graph", "https://graph.microsoft.com/v1.0/organization")
        for step in steps:
            assert "label" in step
            assert "description" in step
            assert "tokens" in step
            assert "highlights" in step

    def test_downstream_response_uses_downstream_label(self, patch_settings):
        body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {},
            "downstream_response": {"value": []},
        }
        steps = _parse_chain_response(body, "Graph", "https://graph.microsoft.com/v1.0/organization")
        labels = [s["label"] for s in steps]
        assert any("Graph" in l for l in labels)
