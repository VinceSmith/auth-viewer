"""Unit tests for app.auth.token_utils — pure functions, no network."""
import base64
import json
from datetime import datetime, timezone

import pytest

from app.auth.token_utils import decode_jwt, format_token_response, _sanitize_headers
from tests.conftest import b64url, make_jwt


# ────────────────────────────────────────────────────────────────
# decode_jwt
# ────────────────────────────────────────────────────────────────

class TestDecodeJwt:
    def test_valid_jwt_returns_header_and_payload(self):
        header = {"typ": "JWT", "alg": "RS256", "kid": "my-key"}
        payload = {"sub": "user-123", "aud": "api://my-app", "iss": "https://login.example.com"}
        result = decode_jwt(make_jwt(header, payload))
        assert result["header"] == header
        assert result["payload"]["sub"] == "user-123"
        assert result["payload"]["aud"] == "api://my-app"

    def test_timestamp_claims_get_utc_annotations(self):
        now_ts = 1_700_000_000
        exp_ts = 9_999_999_999
        payload = {"sub": "x", "iat": now_ts, "exp": exp_ts, "nbf": now_ts}
        result = decode_jwt(make_jwt(payload=payload))["payload"]
        assert "_iat_utc" in result
        assert "_exp_utc" in result
        assert "_nbf_utc" in result
        expected = datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat()
        assert result["_iat_utc"] == expected

    def test_non_timestamp_claims_not_annotated(self):
        payload = {"sub": "user", "email": "user@example.com"}
        result = decode_jwt(make_jwt(payload=payload))["payload"]
        assert "_email_utc" not in result

    def test_missing_time_claims_dont_add_utc(self):
        payload = {"sub": "user"}
        result = decode_jwt(make_jwt(payload=payload))["payload"]
        assert "_exp_utc" not in result
        assert "_iat_utc" not in result
        assert "_nbf_utc" not in result

    def test_invalid_jwt_too_few_parts(self):
        result = decode_jwt("notajwt")
        assert "error" in result

    def test_invalid_jwt_single_segment(self):
        result = decode_jwt(b64url({"typ": "JWT"}))
        assert "error" in result

    def test_bad_base64_returns_decode_error(self):
        result = decode_jwt("INVALID!!!.INVALID!!!.sig")
        has_error = (
            "decode_error" in result.get("header", {})
            or "decode_error" in result.get("payload", {})
        )
        assert has_error

    def test_both_header_and_payload_present(self):
        result = decode_jwt(make_jwt())
        assert "header" in result
        assert "payload" in result

    def test_non_integer_time_claims_not_annotated(self):
        payload = {"sub": "u", "exp": "not-a-number"}
        result = decode_jwt(make_jwt(payload=payload))["payload"]
        assert "_exp_utc" not in result


# ────────────────────────────────────────────────────────────────
# format_token_response
# ────────────────────────────────────────────────────────────────

class TestFormatTokenResponse:
    def _call(self, **overrides) -> dict:
        defaults = dict(
            request_method="POST",
            request_url="https://login.example.com/token",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body={"grant_type": "client_credentials", "client_id": "my-app"},
            response_status=200,
            response_headers={},
            response_body={},
        )
        defaults.update(overrides)
        return format_token_response(**defaults)

    def test_returns_required_top_level_keys(self):
        result = self._call()
        assert "request" in result
        assert "response" in result
        assert "tokens" in result

    def test_request_body_values_present(self):
        result = self._call(request_body={"grant_type": "client_credentials", "client_id": "abc"})
        assert result["request"]["body"]["grant_type"] == "client_credentials"
        assert result["request"]["body"]["client_id"] == "abc"

    def test_client_secret_is_masked(self):
        result = self._call(request_body={"client_id": "abc", "client_secret": "super-secret"})
        assert result["request"]["body"]["client_secret"] == "[client_secret]"
        assert "super-secret" not in str(result)

    def test_access_token_is_decoded(self):
        payload = {"sub": "user-123", "aud": "api://my-app", "exp": 9_999_999_999}
        token = make_jwt(payload=payload)
        result = self._call(response_body={"access_token": token})
        assert "access_token" in result["tokens"]
        assert result["tokens"]["access_token"]["payload"]["sub"] == "user-123"
        assert result["tokens"]["access_token"]["raw"] == token

    def test_id_token_is_decoded(self):
        payload = {"sub": "user-456", "name": "Test User"}
        token = make_jwt(payload=payload)
        result = self._call(response_body={"id_token": token})
        assert "id_token" in result["tokens"]
        assert result["tokens"]["id_token"]["payload"]["name"] == "Test User"

    def test_refresh_token_is_opaque_with_note(self):
        result = self._call(response_body={"refresh_token": "r" * 50})
        rt = result["tokens"]["refresh_token"]
        assert "note" in rt
        assert "..." in rt["raw"]

    def test_short_refresh_token_not_truncated(self):
        result = self._call(response_body={"refresh_token": "short"})
        assert result["tokens"]["refresh_token"]["raw"] == "short"

    def test_no_tokens_in_error_response(self):
        result = self._call(response_status=400, response_body={"error": "invalid_client"})
        assert result["tokens"] == {}

    def test_response_status_preserved(self):
        result = self._call(response_status=401, response_body={"error": "unauthorized"})
        assert result["response"]["status"] == 401

    def test_authorization_header_is_truncated(self):
        long_auth = "Bearer " + "x" * 100
        result = self._call(request_headers={"Authorization": long_auth})
        auth = result["request"]["headers"]["Authorization"]
        assert auth.endswith("...")
        assert len(auth) <= 23  # 20 chars + "..."

    def test_multiple_tokens_all_decoded(self):
        access = make_jwt(payload={"sub": "u1", "exp": 9_999_999_999})
        id_tok = make_jwt(payload={"sub": "u2", "name": "Alice", "exp": 9_999_999_999})
        result = self._call(response_body={"access_token": access, "id_token": id_tok})
        assert "access_token" in result["tokens"]
        assert "id_token" in result["tokens"]


# ────────────────────────────────────────────────────────────────
# _sanitize_headers
# ────────────────────────────────────────────────────────────────

class TestSanitizeHeaders:
    def test_long_authorization_header_truncated(self):
        result = _sanitize_headers({"Authorization": "Bearer " + "t" * 100})
        assert result["Authorization"].endswith("...")
        assert len(result["Authorization"]) <= 23

    def test_short_authorization_not_truncated(self):
        result = _sanitize_headers({"Authorization": "Bearer short"})
        assert result["Authorization"] == "Bearer short"

    def test_non_sensitive_headers_pass_through(self):
        result = _sanitize_headers({"Content-Type": "application/json", "Accept": "*/*"})
        assert result["Content-Type"] == "application/json"
        assert result["Accept"] == "*/*"

    def test_empty_headers_returns_empty_dict(self):
        assert _sanitize_headers({}) == {}

    def test_lowercase_authorization_also_truncated(self):
        result = _sanitize_headers({"authorization": "Bearer " + "x" * 100})
        assert result["authorization"].endswith("...")
