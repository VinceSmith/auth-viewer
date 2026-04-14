"""Tests for pure helper functions in app/main.py."""
import time
from unittest.mock import patch, MagicMock

import pytest

import app.main as main_module
from app.main import (
    TtlDict,
    _decode_jwt_payload,
    _is_token_expired,
    _aud_from_scope,
)


# ---------------------------------------------------------------------------
# TtlDict
# ---------------------------------------------------------------------------

class TestTtlDict:
    def test_set_and_get(self):
        d = TtlDict(ttl=60)
        d["k"] = "v"
        assert d["k"] == "v"

    def test_contains_before_expiry(self):
        d = TtlDict(ttl=60)
        d["k"] = 1
        assert "k" in d

    def test_expired_key_raises_keyerror(self):
        d = TtlDict(ttl=0.001)
        d["k"] = "v"
        time.sleep(0.01)
        with pytest.raises(KeyError):
            _ = d["k"]

    def test_expired_key_not_in_contains(self):
        d = TtlDict(ttl=0.001)
        d["k"] = "v"
        time.sleep(0.01)
        assert "k" not in d

    def test_get_returns_default_for_missing(self):
        d = TtlDict(ttl=60)
        assert d.get("missing") is None
        assert d.get("missing", 42) == 42

    def test_get_returns_default_for_expired(self):
        d = TtlDict(ttl=0.001)
        d["k"] = "v"
        time.sleep(0.01)
        assert d.get("k", "default") == "default"

    def test_pop_existing(self):
        d = TtlDict(ttl=60)
        d["k"] = "v"
        assert d.pop("k") == "v"
        assert "k" not in d

    def test_pop_missing_with_default(self):
        d = TtlDict(ttl=60)
        assert d.pop("missing", "x") == "x"

    def test_pop_missing_raises(self):
        d = TtlDict(ttl=60)
        with pytest.raises(KeyError):
            d.pop("missing")

    def test_pop_expired_with_default(self):
        d = TtlDict(ttl=0.001)
        d["k"] = "v"
        time.sleep(0.01)
        assert d.pop("k", "x") == "x"

    def test_setdefault_sets_if_missing(self):
        d = TtlDict(ttl=60)
        val = d.setdefault("k", {})
        assert val == {}
        assert d["k"] == {}

    def test_setdefault_does_not_overwrite(self):
        d = TtlDict(ttl=60)
        d["k"] = 1
        d.setdefault("k", 99)
        assert d["k"] == 1

    def test_evict_on_write(self):
        d = TtlDict(ttl=0.001)
        d["a"] = 1
        time.sleep(0.01)
        d["b"] = 2   # should trigger eviction of "a"
        assert "a" not in d._data
        assert "b" in d._data

    def test_del_item(self):
        d = TtlDict(ttl=60)
        d["k"] = 1
        del d["k"]
        assert "k" not in d


# ---------------------------------------------------------------------------
# _decode_jwt_payload
# ---------------------------------------------------------------------------

def _make_jwt(payload_dict: dict) -> str:
    """Tiny helper — builds a syntactically valid (unsigned) JWT."""
    import base64, json
    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    return f"{b64({'alg':'none'})}.{b64(payload_dict)}.sig"


class TestDecodeJwtPayload:
    def test_returns_payload_dict(self):
        token = _make_jwt({"sub": "u1", "exp": 9999999999})
        payload = _decode_jwt_payload(token)
        assert payload["sub"] == "u1"

    def test_returns_empty_for_garbage(self):
        assert _decode_jwt_payload("not.a.jwt") == {}

    def test_returns_empty_for_single_segment(self):
        assert _decode_jwt_payload("onlyone") == {}

    def test_returns_empty_for_blank(self):
        assert _decode_jwt_payload("") == {}


# ---------------------------------------------------------------------------
# _is_token_expired
# ---------------------------------------------------------------------------

class TestIsTokenExpired:
    def test_expired_token(self):
        token = _make_jwt({"exp": int(time.time()) - 10})
        assert _is_token_expired(token) is True

    def test_valid_token(self):
        token = _make_jwt({"exp": int(time.time()) + 3600})
        assert _is_token_expired(token) is False

    def test_no_exp_claim_returns_false(self):
        token = _make_jwt({"sub": "u1"})
        assert _is_token_expired(token) is False

    def test_garbage_token_returns_false(self):
        assert _is_token_expired("not.a.jwt") is False


# ---------------------------------------------------------------------------
# _aud_from_scope
# ---------------------------------------------------------------------------

class TestAudFromScope:
    @pytest.fixture(autouse=True)
    def _patch_settings(self, monkeypatch):
        fake = MagicMock()
        fake.api_a_app_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        fake.api_b_app_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        fake.client_id = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        monkeypatch.setattr(main_module, "settings", fake)

    def test_api_uri_scope(self):
        scope = "api://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/access_as_user"
        assert _aud_from_scope(scope) == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    def test_graph_scope(self):
        assert _aud_from_scope("https://graph.microsoft.com/User.Read") == "https://graph.microsoft.com"

    def test_known_app_id_in_scope(self):
        scope = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/access_as_user"
        assert _aud_from_scope(scope) == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    def test_unknown_scope_returns_empty(self):
        assert _aud_from_scope("openid profile email") == ""

    def test_empty_scope_returns_empty(self):
        assert _aud_from_scope("") == ""

    def test_multiple_scopes_picks_api_uri(self):
        scope = "openid api://bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/read"
        assert _aud_from_scope(scope) == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
