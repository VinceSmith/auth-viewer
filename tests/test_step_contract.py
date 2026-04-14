"""Contract tests — lock down the step dict shape that app.js depends on.

These tests verify that every step returned by flows.py helper functions
contains exactly the keys the frontend JavaScript accesses by name.
A failing test here means a regression that would silently break the UI.

The required step keys come directly from app.js usage:
  step.label, step.description, step.request, step.response,
  step.tokens, step.highlights, step.authorize_url (optional)

The required token item keys:
  token.raw, token.header, token.payload (decoded tokens)
  token.raw, token.note               (opaque tokens like refresh_token)
"""

import pytest

from app.auth.flows import _build_step, _parse_chain_response
from app.auth.token_utils import decode_jwt, format_token_response
from app.auth.types import StepDict, TokenResponse, JwtDecoded
from tests.conftest import make_jwt, FAKE_API_A_ID, FAKE_API_B_ID

# ── Required top-level keys that app.js reads from every step ──
REQUIRED_STEP_KEYS = {"label", "description", "request", "response", "tokens", "highlights"}

# ── Required keys inside a decoded-token entry ──
REQUIRED_DECODED_TOKEN_KEYS = {"raw", "header", "payload"}

# ── Required keys inside an opaque-token entry (refresh_token) ──
REQUIRED_OPAQUE_TOKEN_KEYS = {"raw", "note"}

# ── Required top-level keys from format_token_response / _post_token_endpoint ──
REQUIRED_TOKEN_RESPONSE_KEYS = {"request", "response", "tokens"}


# ────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────

def assert_valid_step(step: dict) -> None:
    """Assert that *step* conforms to the StepDict contract."""
    missing = REQUIRED_STEP_KEYS - step.keys()
    assert not missing, f"Step missing required keys: {missing!r}. Got: {list(step.keys())}"
    assert isinstance(step["label"], str) and step["label"], "label must be a non-empty string"
    assert isinstance(step["description"], str), "description must be a string"
    assert isinstance(step["tokens"], dict), "tokens must be a dict"
    assert isinstance(step["highlights"], dict), "highlights must be a dict"


def assert_valid_decoded_token(token_entry: dict, name: str) -> None:
    """Assert that *token_entry* is a properly decoded (non-opaque) token."""
    missing = REQUIRED_DECODED_TOKEN_KEYS - token_entry.keys()
    assert not missing, (
        f"Decoded token '{name}' missing keys: {missing!r}. Got: {list(token_entry.keys())}"
    )
    assert isinstance(token_entry["raw"], str), f"{name}.raw must be a string"
    assert isinstance(token_entry["header"], dict), f"{name}.header must be a dict"
    assert isinstance(token_entry["payload"], dict), f"{name}.payload must be a dict"


def assert_valid_opaque_token(token_entry: dict, name: str) -> None:
    """Assert that *token_entry* is a properly formed opaque token (e.g. refresh_token)."""
    missing = REQUIRED_OPAQUE_TOKEN_KEYS - token_entry.keys()
    assert not missing, (
        f"Opaque token '{name}' missing keys: {missing!r}. Got: {list(token_entry.keys())}"
    )


# ────────────────────────────────────────────────────────────────
# decode_jwt contract
# ────────────────────────────────────────────────────────────────

class TestDecodeJwtContract:
    def test_valid_jwt_returns_header_and_payload(self):
        result: JwtDecoded = decode_jwt(make_jwt())
        assert "header" in result
        assert "payload" in result
        assert isinstance(result["header"], dict)
        assert isinstance(result["payload"], dict)

    def test_error_result_has_error_key(self):
        result = decode_jwt("not.a.jwt.at.all")
        # On error, must have either 'error' at top level OR decode_error inside header/payload
        has_error = (
            "error" in result
            or "decode_error" in result.get("header", {})
            or "decode_error" in result.get("payload", {})
        )
        assert has_error

    def test_payload_sub_accessible_from_result(self):
        """Verify the access pattern app.js uses: result.payload.sub"""
        token = make_jwt(payload={"sub": "test-user", "exp": 9_999_999_999})
        result = decode_jwt(token)
        assert result["payload"]["sub"] == "test-user"


# ────────────────────────────────────────────────────────────────
# format_token_response contract
# ────────────────────────────────────────────────────────────────

class TestFormatTokenResponseContract:
    def _make_result(self, response_body: dict) -> TokenResponse:
        return format_token_response(
            request_method="POST",
            request_url="https://login.example.com/token",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body={"grant_type": "client_credentials", "client_id": "app"},
            response_status=200,
            response_headers={},
            response_body=response_body,
        )

    def test_required_top_level_keys_present(self):
        result = self._make_result({})
        missing = REQUIRED_TOKEN_RESPONSE_KEYS - result.keys()
        assert not missing, f"TokenResponse missing: {missing!r}"

    def test_request_has_method_url_headers_body(self):
        result = self._make_result({})
        req = result["request"]
        for key in ("method", "url", "headers", "body"):
            assert key in req, f"request missing '{key}'"

    def test_response_has_status_headers_body(self):
        result = self._make_result({})
        resp = result["response"]
        for key in ("status", "headers", "body"):
            assert key in resp, f"response missing '{key}'"

    def test_access_token_entry_conforms_to_decoded_shape(self):
        token = make_jwt(payload={"sub": "u", "exp": 9_999_999_999})
        result = self._make_result({"access_token": token})
        assert "access_token" in result["tokens"]
        assert_valid_decoded_token(result["tokens"]["access_token"], "access_token")

    def test_id_token_entry_conforms_to_decoded_shape(self):
        token = make_jwt(payload={"sub": "u", "name": "Alice", "exp": 9_999_999_999})
        result = self._make_result({"id_token": token})
        assert "id_token" in result["tokens"]
        assert_valid_decoded_token(result["tokens"]["id_token"], "id_token")

    def test_refresh_token_entry_conforms_to_opaque_shape(self):
        result = self._make_result({"refresh_token": "r" * 60})
        assert "refresh_token" in result["tokens"]
        assert_valid_opaque_token(result["tokens"]["refresh_token"], "refresh_token")

    def test_no_tokens_when_response_is_error(self):
        result = self._make_result({"error": "invalid_client", "error_description": "Bad creds"})
        assert result["tokens"] == {}


# ────────────────────────────────────────────────────────────────
# _build_step contract
# ────────────────────────────────────────────────────────────────

class TestBuildStepContract:
    def test_minimal_step_satisfies_contract(self):
        step: StepDict = _build_step(label="My Step", description="Does something.")
        assert_valid_step(step)

    def test_step_with_all_fields_satisfies_contract(self):
        step: StepDict = _build_step(
            label="Full Step",
            description="Has everything.",
            request={"method": "POST", "url": "https://x.com", "headers": {}, "body": {}},
            response={"status": 200, "headers": {}, "body": {"ok": True}},
            tokens={"access_token": {
                "raw": make_jwt(),
                "header": {"typ": "JWT"},
                "payload": {"sub": "u"},
            }},
            highlights={"some-guid": {"label": "Client", "role": "client"}},
        )
        assert_valid_step(step)

    def test_step_with_authorize_url_satisfies_contract(self):
        step: StepDict = _build_step(
            label="Auth Step",
            description="Redirects.",
            authorize_url="https://login.example.com/authorize?foo=bar",
        )
        assert_valid_step(step)
        assert step["authorize_url"] == "https://login.example.com/authorize?foo=bar"

    def test_label_is_non_empty_string(self):
        step = _build_step(label="X", description="Y")
        assert isinstance(step["label"], str)
        assert len(step["label"]) > 0

    def test_tokens_is_dict_not_none(self):
        """JS does `for (const [name, token] of Object.entries(step.tokens))` — must be a dict."""
        step = _build_step(label="S", description="D.")
        assert step["tokens"] is not None
        assert isinstance(step["tokens"], dict)

    def test_highlights_is_dict_not_none(self):
        """JS iterates highlights — must be a dict, never None."""
        step = _build_step(label="S", description="D.")
        assert step["highlights"] is not None
        assert isinstance(step["highlights"], dict)


# ────────────────────────────────────────────────────────────────
# _parse_chain_response contract
# ────────────────────────────────────────────────────────────────

class TestParseChainResponseContract:
    def test_all_returned_steps_satisfy_contract(self, patch_settings):
        body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {"access_token": make_jwt(payload={"sub": "u", "exp": 9_999_999_999})},
            "downstream_response": {"data": "result"},
        }
        steps = _parse_chain_response(body, "API B", "http://localhost:8002/data")
        assert len(steps) > 0
        for step in steps:
            assert_valid_step(step)

    def test_decoded_tokens_in_steps_have_correct_shape(self, patch_settings):
        token = make_jwt(payload={"sub": "api-a", "aud": f"api://{FAKE_API_B_ID}", "exp": 9_999_999_999})
        body = {
            "cc_request": {"grant_type": "client_credentials"},
            "cc_token_response": {"access_token": token},
        }
        steps = _parse_chain_response(body, "API B", "http://localhost:8002/data")
        for step in steps:
            for name, tok in step["tokens"].items():
                if "note" in tok:
                    assert_valid_opaque_token(tok, name)
                else:
                    assert_valid_decoded_token(tok, name)


# ────────────────────────────────────────────────────────────────
# STEP_FILLS consistency
# ────────────────────────────────────────────────────────────────

class TestStepFillsConsistency:
    def test_step_fills_exported_from_diagrams(self):
        from app.diagrams import STEP_FILLS
        assert isinstance(STEP_FILLS, list)
        assert len(STEP_FILLS) >= 6, "Need at least 6 step colours for the longest flow"

    def test_each_fill_is_rgb_triple(self):
        from app.diagrams import STEP_FILLS
        for i, fill in enumerate(STEP_FILLS):
            assert len(fill) == 3, f"STEP_FILLS[{i}] must be (r, g, b)"
            r, g, b = fill
            for v in (r, g, b):
                assert 0 <= v <= 255, f"STEP_FILLS[{i}] component out of range: {v}"

    def test_diagram_strings_only_use_known_colours(self):
        """Every rgb(...) colour used in a diagram string must be in STEP_FILLS."""
        import re
        from app.diagrams import STEP_FILLS, DIAGRAMS

        known = {f"rgb({r},{g},{b})" for r, g, b in STEP_FILLS}
        pattern = re.compile(r"rgb\(\d+,\d+,\d+\)")
        for flow, diagram in DIAGRAMS.items():
            for match in pattern.finditer(diagram):
                colour = match.group()
                assert colour in known, (
                    f"Diagram '{flow}' uses hardcoded colour {colour!r} "
                    f"that is not in STEP_FILLS. Add it to STEP_FILLS in diagrams.py "
                    f"and reference it via the _S* variables."
                )

    def test_step_fills_serialisable_to_json(self):
        """Verify the template injection won't crash at startup."""
        import json
        from app.diagrams import STEP_FILLS
        serialised = json.dumps(STEP_FILLS)
        roundtripped = json.loads(serialised)
        assert roundtripped == [list(t) for t in STEP_FILLS]
