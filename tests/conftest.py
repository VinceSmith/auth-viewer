"""Shared fixtures and helpers for auth-viewer unit tests."""
import base64
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

# ── Stable fake IDs used across all tests ──
FAKE_TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
FAKE_CLIENT_ID = "cccccccc-1111-2222-3333-444444444444"
FAKE_API_A_ID = "aaaaa111-1111-1111-1111-111111111111"
FAKE_API_B_ID = "bbbbb222-2222-2222-2222-222222222222"
FAKE_BLUEPRINT_ID = "bpbpbpbp-3333-3333-3333-333333333333"
FAKE_AGENT_ID = "agagagag-4444-4444-4444-444444444444"


def b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def make_jwt(
    header: dict | None = None,
    payload: dict | None = None,
    sig: str = "fakesig",
) -> str:
    """Build a fake (unsigned) JWT for testing."""
    h = header or {"typ": "JWT", "alg": "RS256", "kid": "test-kid"}
    p = payload or {
        "iss": f"https://login.microsoftonline.com/{FAKE_TENANT}/v2.0",
        "sub": "test-subject",
        "aud": f"api://{FAKE_API_A_ID}",
        "exp": 9_999_999_999,
        "iat": 1_700_000_000,
        "scp": "access_as_user",
    }
    return f"{b64url(h)}.{b64url(p)}.{sig}"


@pytest.fixture
def patch_settings(monkeypatch):
    """Replace flows.settings with a deterministic MagicMock for the duration of the test."""
    from app.auth import flows

    fake = MagicMock()
    fake.tenant_id = FAKE_TENANT
    fake.client_id = FAKE_CLIENT_ID
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
    fake.agent_identity_id = FAKE_AGENT_ID
    fake.agent_identity_tenant_id = FAKE_TENANT
    fake.redirect_uri = "http://localhost:8000/auth/callback"
    fake.authority = f"https://login.microsoftonline.com/{FAKE_TENANT}"
    fake.agent_token_endpoint = (
        f"https://login.microsoftonline.com/{FAKE_TENANT}/oauth2/v2.0/token"
    )
    monkeypatch.setattr(flows, "settings", fake)
    return fake


@pytest.fixture(autouse=True)
def clear_module_caches():
    """Clear module-level caches in flows.py before and after every test."""
    from app.auth import flows

    flows._oidc_cache.clear()
    flows._graph_cc_cache.update({"access_token": "", "expires_at": 0.0})
    yield
    flows._oidc_cache.clear()


def make_mock_response(status_code: int, json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.headers = {}
    resp.text = json.dumps(json_data)
    return resp


def make_httpx_ctx(mock_resp: MagicMock) -> tuple[MagicMock, AsyncMock]:
    """Return (ctx_manager, mock_client) where ctx_manager mocks httpx.AsyncClient()."""
    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp
    mock_client.get.return_value = mock_resp
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_client)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx, mock_client
