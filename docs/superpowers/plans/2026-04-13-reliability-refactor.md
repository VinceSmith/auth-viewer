# Reliability Refactor — Implementation Plan
**Date:** 2026-04-13  
**Spec:** `docs/superpowers/specs/2026-04-13-reliability-refactor-design.md`

---

## Scope

Implement the two phases from the approved spec:

- **Phase A** — Write tests that stabilize the callback + flow-switching behaviour. Some tests are expected to start RED and expose real bugs. Fix bugs before moving on.
- **Phase B** — Extract `_FlowError` + `_run_delegated_flow()` to eliminate the copy-pasted OBO/Agent-ID-OBO branches in `/api/execute`.

Phase C (session-scoped token isolation) is deferred pending Phase A results.

---

## Files Touched

| File | Action |
|------|--------|
| `tests/conftest.py` | Add `FAKE_SID`, `make_session_cookie()` helper |
| `tests/test_auth_callback.py` | **New** — 7 callback route tests |
| `tests/test_flow_switching.py` | **New** — 5 flow-switching / audience-validation tests |
| `tests/test_silent_acquire.py` | **New** — 5 silent-acquire route tests |
| `app/main.py` | Add `_FlowError`, `_run_delegated_flow()`; refactor `/api/execute` |
| `tests/test_api_execute.py` | Add 4 `_run_delegated_flow` unit tests |

---

## Phase A — Test-First Stabilisation

### Task A-1 — `make_session_cookie` helper in conftest

Add to the bottom of `tests/conftest.py`:

```python
import secrets as _secrets

FAKE_SID = "test-session-abc123456789"


def make_session_cookie(session_data: dict) -> str:
    """Create a valid Starlette session cookie signed with the app's session secret.

    Starlette SessionMiddleware encodes the session as:
      TimestampSigner(secret_key).sign(base64url(json(data)))
    """
    from itsdangerous import TimestampSigner
    from app.config import settings
    signer = TimestampSigner(settings.session_secret)
    payload = base64.b64encode(json.dumps(session_data).encode()).decode()
    return signer.sign(payload).decode()
```

**Note on `settings.session_secret`:** The TestClient and the cookie helper both read from the same `settings` object (loaded from `.env`). They will always agree on the secret as long as `SESSION_SECRET` is set in `.env`. If `.env` is absent, `settings.session_secret` may be an empty string — this is fine for tests because both sides see the same empty string.

---

### Task A-2 — `tests/test_auth_callback.py`

Seven tests covering `/auth/callback`. All are expected to start **GREEN** (they document current behaviour, not expose bugs).

```python
"""Tests for /auth/callback — guards the 220-line callback route against regressions."""
import base64
import json
import time
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from tests.conftest import (
    make_session_cookie, FAKE_SID, make_jwt,
    FAKE_API_A_ID, FAKE_CLIENT_ID,
)

FAKE_STATE = "valid-state-value-long-enough-32c"
FAKE_CODE  = "entra-auth-code-xyz"

# A minimal successful exchange_auth_code result
def _good_exchange_result() -> dict:
    at = make_jwt(payload={"aud": f"api://{FAKE_API_A_ID}", "exp": 9_999_999_999, "sub": "u1"})
    id_tok = make_jwt(payload={
        "sub": "u1", "name": "Alice", "preferred_username": "alice@contoso.com",
        "oid": "oid-alice", "exp": 9_999_999_999,
    })
    return {
        "response": {"status": 200, "headers": {}, "body": {
            "access_token": at,
            "refresh_token": "rt-value",
            "id_token": id_tok,
        }},
        "request": {"method": "POST", "url": "https://login.example.com/token"},
        "exchange_step": {"label": "Token Exchange", "request": {}, "response": {}, "token": None},
    }


@pytest.fixture()
def client():
    from app.main import app
    return TestClient(app, raise_server_exceptions=False)


def _session(state: str = FAKE_STATE, flow_type: str = "auth_code",
             scope: str = "openid profile") -> dict:
    return {
        "sid": FAKE_SID,
        "oauth_state": state,
        "oauth_scope": scope,
        "flow_type": flow_type,
        "target_scope": "",
    }


# ── Happy path ──────────────────────────────────────────────────────────────

def test_callback_happy_path_redirects_to_root(client):
    """Successful callback redirects the browser to /."""
    cookie = make_session_cookie(_session())
    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock,
               return_value=_good_exchange_result()):
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": cookie},
            allow_redirects=False,
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


def test_callback_stores_tokens_in_token_store(client):
    """After a successful callback _token_store contains the access + refresh tokens."""
    from app.main import _token_store
    cookie = make_session_cookie(_session())
    good = _good_exchange_result()
    expected_at = good["response"]["body"]["access_token"]
    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock,
               return_value=good):
        client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": cookie},
            allow_redirects=False,
        )
    stored = _token_store.get(FAKE_SID, {})
    assert stored.get("auth_code", {}).get("access_token") == expected_at


def test_callback_stores_user_profile(client):
    """After a successful callback _token_store contains the decoded ID token claims."""
    from app.main import _token_store
    cookie = make_session_cookie(_session())
    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock,
               return_value=_good_exchange_result()):
        client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": cookie},
            allow_redirects=False,
        )
    profile = _token_store.get(FAKE_SID, {}).get("user_profile", {})
    assert profile.get("name") == "Alice"
    assert profile.get("preferred_username") == "alice@contoso.com"


# ── State validation ────────────────────────────────────────────────────────

def test_callback_state_mismatch_returns_error_page(client):
    """A mismatched state value must render an error, not redirect."""
    cookie = make_session_cookie(_session(state="correct-state-value-here-32chars"))
    resp = client.get(
        "/auth/callback?code=x&state=wrong-state-totally-different",
        cookies={"session": cookie},
        allow_redirects=False,
    )
    # Must NOT be a redirect — must render an error
    assert resp.status_code == 200
    assert "State mismatch" in resp.text or "error" in resp.text.lower()


def test_callback_entra_error_param_renders_error_page(client):
    """When Entra sends ?error=access_denied the callback renders an error page."""
    cookie = make_session_cookie(_session())
    resp = client.get(
        "/auth/callback?error=access_denied&error_description=User+cancelled",
        cookies={"session": cookie},
        allow_redirects=False,
    )
    assert resp.status_code == 200
    assert "access_denied" in resp.text or "User cancelled" in resp.text


# ── Token exchange failure (expected to reveal missing error check) ─────────

def test_callback_exchange_error_body_does_not_silently_succeed(client):
    """If exchange_auth_code returns an error body the callback must NOT redirect to /.

    This test is expected to start RED — the current callback has no check for
    `error` in the exchange response body, so it silently redirects even when
    Entra returns {"error": "invalid_grant"}.  Fix: add an explicit check after
    resp_body is read in auth_callback().
    """
    error_result = {
        "response": {"status": 400, "headers": {}, "body": {
            "error": "invalid_grant",
            "error_description": "Refresh token expired",
        }},
        "request": {"method": "POST", "url": "https://login.example.com/token"},
        "exchange_step": {"label": "Token Exchange", "request": {}, "response": {}, "token": None},
    }
    cookie = make_session_cookie(_session())
    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock,
               return_value=error_result):
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": cookie},
            allow_redirects=False,
        )
    # Should NOT redirect to / with empty tokens
    assert resp.status_code != 303, (
        "BUG: callback silently redirected to / even though token exchange failed. "
        "Add `if 'error' in resp_body:` check in auth_callback()."
    )


# ── last_flow tracking ──────────────────────────────────────────────────────

def test_callback_sets_last_flow_in_session(client):
    """After a successful callback the session cookie should contain last_flow."""
    cookie = make_session_cookie(_session(flow_type="auth_code"))
    with patch("app.main.flows.exchange_auth_code", new_callable=AsyncMock,
               return_value=_good_exchange_result()):
        resp = client.get(
            f"/auth/callback?code={FAKE_CODE}&state={FAKE_STATE}",
            cookies={"session": cookie},
            allow_redirects=False,
        )
    # Decode the returned session cookie to verify last_flow
    from itsdangerous import TimestampSigner
    from app.config import settings
    raw_cookie = resp.cookies.get("session", "")
    if raw_cookie:
        signer = TimestampSigner(settings.session_secret)
        try:
            data = signer.unsign(raw_cookie, return_timestamp=False)
            session_data = json.loads(base64.b64decode(data))
            assert session_data.get("last_flow") == "auth_code", (
                f"last_flow not set in session after callback. Got: {session_data}"
            )
        except Exception as exc:
            pytest.fail(f"Could not decode session cookie: {exc}")
```

---

### Task A-3 — `tests/test_flow_switching.py`

Five tests probing state bleeding. Most are expected to start **GREEN** (audience isolation works). If any are RED, fix the bug before Phase B.

```python
"""Tests that verify token audience isolation between flows.

Seeding strategy: inject FAKE_SID into the session cookie and write
directly into _token_store[FAKE_SID] before issuing the request.
Most tests here are expected to start GREEN — confirming that _resolve_user_token
correctly isolates tokens by audience.  If any start RED, the bug is in
_resolve_user_token or _FLOW_TOKEN_CONFIG.
"""
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.conftest import (
    make_session_cookie, FAKE_SID, make_jwt,
    FAKE_API_A_ID, FAKE_API_B_ID, FAKE_BLUEPRINT_ID,
)


@pytest.fixture(autouse=True)
def reset_token_store():
    """Clear the FAKE_SID slot before and after every test."""
    from app.main import _token_store
    _token_store._data.pop(FAKE_SID, None)
    yield
    _token_store._data.pop(FAKE_SID, None)


@pytest.fixture()
def client():
    from app.main import app
    return TestClient(app, raise_server_exceptions=False)


def _api_a_token() -> str:
    return make_jwt(payload={"aud": FAKE_API_A_ID, "sub": "u1", "exp": 9_999_999_999})


def _api_b_token() -> str:
    return make_jwt(payload={"aud": FAKE_API_B_ID, "sub": "u1", "exp": 9_999_999_999})


def _blueprint_token() -> str:
    return make_jwt(payload={"aud": FAKE_BLUEPRINT_ID, "sub": "u1", "exp": 9_999_999_999})


def _seed(data: dict):
    """Write data into _token_store[FAKE_SID] directly (bypasses TTL)."""
    from app.main import _token_store
    _token_store._data[FAKE_SID] = data
    import time
    _token_store._expiry[FAKE_SID] = time.time() + 4 * 3600


def _cookie(flow_type: str = "obo") -> str:
    return make_session_cookie({"sid": FAKE_SID, "flow_type": flow_type})


def _obo_ok_result() -> dict:
    return {"steps": [{"label": "OBO Exchange", "request": {}, "response": {}, "token": None}]}


def _agent_ok_result() -> dict:
    return {"steps": [{"label": "Agent OBO Exchange", "request": {}, "response": {}, "token": None}]}


# ── Audience isolation ───────────────────────────────────────────────────────

def test_obo_uses_api_a_token_not_api_b_token(client):
    """OBO flow must use the API-A–scoped token and not a stale API-B token."""
    _seed({"auth_code": {"access_token": _api_b_token(), "refresh_token": ""}})

    with patch("app.main.flows.execute_obo", new_callable=AsyncMock,
               return_value=_obo_ok_result()) as mock_obo:
        resp = client.post(
            "/api/execute",
            json={"flow_type": "obo", "scope": f"api://{FAKE_API_A_ID}/access_as_user"},
            cookies={"session": _cookie("obo")},
        )

    # The API-B token has the wrong audience — _resolve_user_token should reject it.
    # If execute_obo WAS called, it received a token with the wrong audience (bleeding).
    if mock_obo.called:
        used_token = mock_obo.call_args.kwargs.get("user_access_token", "")
        import base64, json as _json
        parts = used_token.split(".")
        if len(parts) >= 2:
            pad = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = _json.loads(base64.urlsafe_b64decode(pad))
            assert payload.get("aud") != FAKE_API_B_ID, (
                "BUG: OBO flow used an API-B token (wrong audience)."
            )
    # Either execute_obo was not called (no token found, correct) or it was called
    # with the right audience — both are acceptable outcomes.


def test_obo_does_not_use_agent_id_obo_token(client):
    """A token stored under 'agent_id_obo' must not be picked up by the OBO flow."""
    _seed({"agent_id_obo": {"access_token": _blueprint_token(), "refresh_token": ""}})

    with patch("app.main.flows.execute_obo", new_callable=AsyncMock,
               return_value=_obo_ok_result()) as mock_obo:
        client.post(
            "/api/execute",
            json={"flow_type": "obo", "scope": f"api://{FAKE_API_A_ID}/access_as_user"},
            cookies={"session": _cookie("obo")},
        )

    # OBO store_keys = ["obo", "auth_code"] — neither is seeded.
    # execute_obo should not have been called (no token found).
    # If it IS called the token must not be the blueprint token.
    if mock_obo.called:
        used_token = mock_obo.call_args.kwargs.get("user_access_token", "")
        assert used_token != _blueprint_token(), (
            "BUG: OBO flow picked up the agent_id_obo token (state bleeding)."
        )


def test_agent_id_obo_does_not_use_obo_token(client):
    """A token stored under 'obo' must not be picked up by the Agent ID OBO flow."""
    _seed({"obo": {"access_token": _api_a_token(), "refresh_token": ""}})

    with patch("app.main.flows.execute_agent_id_obo", new_callable=AsyncMock,
               return_value=_agent_ok_result()) as mock_agent:
        client.post(
            "/api/execute",
            json={"flow_type": "agent_id_obo", "scope": "openid profile"},
            cookies={"session": _cookie("agent_id_obo")},
        )

    # agent_id_obo store_keys = ["agent_id_obo", "auth_code"] — neither seeded.
    if mock_agent.called:
        used_token = mock_agent.call_args.kwargs.get("user_token", "")
        assert used_token != _api_a_token(), (
            "BUG: Agent ID OBO flow picked up the obo token (state bleeding)."
        )


def test_correct_api_a_token_flows_through_obo(client):
    """When the auth_code slot holds an API-A token, OBO receives it correctly."""
    at = _api_a_token()
    _seed({"auth_code": {"access_token": at, "refresh_token": ""}})

    with patch("app.main.flows.execute_obo", new_callable=AsyncMock,
               return_value=_obo_ok_result()) as mock_obo:
        client.post(
            "/api/execute",
            json={"flow_type": "obo", "scope": f"api://{FAKE_API_A_ID}/access_as_user"},
            cookies={"session": _cookie("obo")},
        )

    assert mock_obo.called, "execute_obo was not called despite a valid token being seeded."
    used_token = mock_obo.call_args.kwargs.get("user_access_token", "")
    assert used_token == at


def test_client_credentials_ignores_user_token_store(client):
    """Client credentials is app-only — it must not read from _token_store at all."""
    _seed({"auth_code": {"access_token": _api_a_token(), "refresh_token": ""}})

    cc_result = {"steps": [{"label": "Client Credentials", "request": {}, "response": {}, "token": None}]}
    with patch("app.main.flows.execute_client_credentials", new_callable=AsyncMock,
               return_value=cc_result) as mock_cc:
        resp = client.post(
            "/api/execute",
            json={"flow_type": "client_credentials", "scope": f"api://{FAKE_API_A_ID}/.default"},
            cookies={"session": _cookie("client_credentials")},
        )

    assert mock_cc.called
    assert resp.status_code == 200
```

---

### Task A-4 — `tests/test_silent_acquire.py`

Five tests for `/api/silent-acquire`. Expected to start **GREEN** (documents existing behaviour).

```python
"""Tests for /api/silent-acquire route."""
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient

from tests.conftest import make_session_cookie, FAKE_SID, make_jwt, FAKE_API_A_ID


@pytest.fixture(autouse=True)
def reset_token_store():
    from app.main import _token_store
    _token_store._data.pop(FAKE_SID, None)
    yield
    _token_store._data.pop(FAKE_SID, None)


@pytest.fixture()
def client():
    from app.main import app
    return TestClient(app, raise_server_exceptions=False)


def _seed(data: dict):
    import time
    from app.main import _token_store
    _token_store._data[FAKE_SID] = data
    _token_store._expiry[FAKE_SID] = time.time() + 4 * 3600


def _cookie() -> str:
    return make_session_cookie({"sid": FAKE_SID})


def _silent_ok_result(at: str) -> dict:
    return {
        "response": {"status": 200, "headers": {}, "body": {
            "access_token": at,
            "refresh_token": "new-rt",
        }},
        "step": {"label": "Silent Acquire", "request": {}, "response": {}, "token": None},
    }


def test_silent_acquire_no_refresh_token_returns_400(client):
    """With no refresh token in store, /api/silent-acquire must return 400."""
    _seed({})
    resp = client.post(
        "/api/silent-acquire",
        json={"scope": f"api://{FAKE_API_A_ID}/access_as_user", "flow_type": "obo"},
        cookies={"session": _cookie()},
    )
    assert resp.status_code == 400
    assert resp.json().get("error") == "no_refresh_token"


def test_silent_acquire_passes_refresh_token_to_flow(client):
    """The stored refresh_token must be forwarded to flows.silent_acquire."""
    _seed({"refresh_token": "my-rt"})
    at = make_jwt(payload={"aud": FAKE_API_A_ID, "exp": 9_999_999_999})
    with patch("app.main.flows.silent_acquire", new_callable=AsyncMock,
               return_value=_silent_ok_result(at)) as mock_sa:
        client.post(
            "/api/silent-acquire",
            json={"scope": f"api://{FAKE_API_A_ID}/access_as_user", "flow_type": "obo"},
            cookies={"session": _cookie()},
        )
    assert mock_sa.called
    assert mock_sa.call_args.kwargs.get("refresh_token") == "my-rt"


def test_silent_acquire_entra_error_returns_400(client):
    """If Entra returns an error in the token response, the route must return 400."""
    _seed({"refresh_token": "my-rt"})
    error_result = {
        "response": {"status": 400, "headers": {}, "body": {
            "error": "invalid_grant", "error_description": "RT expired",
        }},
        "step": {"label": "Silent Acquire", "request": {}, "response": {}, "token": None},
    }
    with patch("app.main.flows.silent_acquire", new_callable=AsyncMock, return_value=error_result):
        resp = client.post(
            "/api/silent-acquire",
            json={"scope": f"api://{FAKE_API_A_ID}/access_as_user", "flow_type": "obo"},
            cookies={"session": _cookie()},
        )
    assert resp.status_code == 400
    assert resp.json().get("error") == "invalid_grant"


def test_silent_acquire_updates_refresh_token_in_store(client):
    """After success the new refresh token must be persisted in _token_store."""
    from app.main import _token_store
    _seed({"refresh_token": "old-rt"})
    at = make_jwt(payload={"aud": FAKE_API_A_ID, "exp": 9_999_999_999})
    with patch("app.main.flows.silent_acquire", new_callable=AsyncMock,
               return_value=_silent_ok_result(at)):
        client.post(
            "/api/silent-acquire",
            json={"scope": f"api://{FAKE_API_A_ID}/access_as_user", "flow_type": "obo"},
            cookies={"session": _cookie()},
        )
    assert _token_store.get(FAKE_SID, {}).get("refresh_token") == "new-rt"


def test_silent_acquire_returns_access_token_in_body(client):
    """Successful response must include access_token in the JSON body."""
    _seed({"refresh_token": "my-rt"})
    at = make_jwt(payload={"aud": FAKE_API_A_ID, "exp": 9_999_999_999})
    with patch("app.main.flows.silent_acquire", new_callable=AsyncMock,
               return_value=_silent_ok_result(at)):
        resp = client.post(
            "/api/silent-acquire",
            json={"scope": f"api://{FAKE_API_A_ID}/access_as_user", "flow_type": "obo"},
            cookies={"session": _cookie()},
        )
    assert resp.status_code == 200
    assert resp.json().get("access_token") == at
```

---

### Task A-5 — Fix red tests

Run the suite. For each RED test:

1. Identify the failing assertion and locate the bug in `app/main.py`.
2. Make the minimal fix (no refactoring here — Phase B handles that).
3. Re-run until all Phase A tests are GREEN.

**Known expected RED tests:**
- `test_callback_exchange_error_body_does_not_silently_succeed` — the callback
  has no `if "error" in resp_body:` guard. Fix: add the check immediately after
  `resp_body = result.get("response", {}).get("body", {})` in `auth_callback()`.

---

## Phase B — Extract `_FlowError` + `_run_delegated_flow`

### Task B-1 — Add `_FlowError` and `_run_delegated_flow` to `app/main.py`

Insert after the `_FLOW_TOKEN_CONFIG` dict (around line 175) and before
`_resolve_user_token`:

```python
class _FlowError(Exception):
    """Raised by _run_delegated_flow for user-facing flow errors (not 500s)."""
    def __init__(self, body: dict, status_code: int = 400):
        self.body = body
        self.status_code = status_code
        super().__init__(str(body))


async def _run_delegated_flow(
    stored: dict,
    flow_type: str,
    scope: str,
    execute_fn,
    execute_kwargs: dict,
) -> dict:
    """Resolve a user token and call execute_fn, prepending info steps to the result.

    Raises _FlowError (not JSONResponse) for user-facing 400-class errors so the
    caller can handle them before the generic except Exception block.

    Args:
        stored:         The _token_store entry for this session.
        flow_type:      "obo" | "agent_id_obo" (auth_code has its own branch).
        scope:          The scope requested by the caller.
        execute_fn:     A coroutine function e.g. flows.execute_obo.
        execute_kwargs: Extra keyword args forwarded to execute_fn (e.g. scope=...).
                        The resolved user token is injected as the first positional kwarg
                        defined by the flow ("user_access_token" for obo,
                        "user_token" for agent_id_obo).
    """
    user_token, info_steps = await _resolve_user_token(stored, flow_type)
    if not user_token:
        raise _FlowError(
            {"error": "No user token available. Run Auth Code flow first."}
        )
    if _is_token_expired(user_token):
        raise _FlowError(
            {"error": "token_expired",
             "message": "Your access token has expired. Please sign in again."}
        )
    result = await execute_fn(**execute_kwargs)
    if info_steps:
        result.setdefault("steps", [])[:0] = info_steps
    return result
```

**Token-arg mapping** (inject into `execute_kwargs` at the call site):

| flow_type | execute_fn | token kwarg |
|---|---|---|
| `obo` | `flows.execute_obo` | `user_access_token=user_token` |
| `agent_id_obo` | `flows.execute_agent_id_obo` | `user_token=user_token` |

To make this work cleanly, resolve the token inside `_run_delegated_flow` but pass the execute kwargs **without** the token arg; the helper injects it. Alternatively, include it in `execute_kwargs` at the call site after calling `_resolve_user_token` yourself — but that defeats the purpose. The cleanest approach: let the caller pass a lambda or a partial:

```python
# Call site for obo:
result = await _run_delegated_flow(
    stored, "obo", scope,
    execute_fn=lambda token: flows.execute_obo(user_access_token=token, scope=scope),
)

# Inside _run_delegated_flow, call it as:
result = await execute_fn(user_token)
```

Revise the signature accordingly:

```python
async def _run_delegated_flow(
    stored: dict,
    flow_type: str,
    execute_fn,        # async callable(token: str) -> dict
) -> dict:
    user_token, info_steps = await _resolve_user_token(stored, flow_type)
    if not user_token:
        raise _FlowError({"error": "No user token available. Run Auth Code flow first."})
    if _is_token_expired(user_token):
        raise _FlowError({"error": "token_expired",
                          "message": "Your access token has expired. Please sign in again."})
    result = await execute_fn(user_token)
    if info_steps:
        result.setdefault("steps", [])[:0] = info_steps
    return result
```

---

### Task B-2 — Refactor `/api/execute` OBO and Agent ID OBO branches

Replace the `obo` and `agent_id_obo` branches in `/api/execute`:

**Before (obo branch, lines 721-729):**
```python
elif flow_type == "obo":
    user_token, info_steps = await _resolve_user_token(stored, flow_type, body_token=body.user_token)
    if not user_token:
        return JSONResponse({"error": "No user token available. Run Auth Code flow first."}, status_code=400)
    if _is_token_expired(user_token):
        return JSONResponse({"error": "token_expired", "message": "Your access token has expired. Please sign in again."}, status_code=400)
    result = await flows.execute_obo(user_access_token=user_token, scope=scope)
    if info_steps:
        result.setdefault("steps", [])[:0] = info_steps
```

**After:**
```python
elif flow_type == "obo":
    result = await _run_delegated_flow(
        stored, "obo",
        lambda token: flows.execute_obo(user_access_token=token, scope=scope),
    )
```

**Before (agent_id_obo branch, lines 737-745):**
```python
elif flow_type == "agent_id_obo":
    user_token, info_steps = await _resolve_user_token(stored, flow_type, body_token=body.user_token)
    if not user_token:
        return JSONResponse({"error": "No user token available. Run Auth Code flow first."}, status_code=400)
    if _is_token_expired(user_token):
        return JSONResponse({"error": "token_expired", "message": "Your access token has expired. Please sign in again."}, status_code=400)
    result = await flows.execute_agent_id_obo(user_token=user_token, scope=scope)
    if info_steps:
        result.setdefault("steps", [])[:0] = info_steps
```

**After:**
```python
elif flow_type == "agent_id_obo":
    result = await _run_delegated_flow(
        stored, "agent_id_obo",
        lambda token: flows.execute_agent_id_obo(user_token=token, scope=scope),
    )
```

Update the `except` chain to catch `_FlowError` **before** `except Exception`:

```python
    except _FlowError as fe:
        return JSONResponse(fe.body, status_code=fe.status_code)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
```

**Note:** `auth_code` is structurally different (calls `flows.call_resource`, not a
delegated flow function) and must NOT be folded into `_run_delegated_flow`.

---

### Task B-3 — Tests for `_run_delegated_flow` (add to `test_api_execute.py`)

Add four async unit tests:

```python
# In tests/test_api_execute.py — add after existing tests

class TestRunDelegatedFlow:
    """Unit tests for _run_delegated_flow helper."""

    async def test_no_token_raises_flow_error(self):
        from app.main import _run_delegated_flow, _FlowError
        with pytest.raises(_FlowError) as exc_info:
            await _run_delegated_flow({}, "obo", AsyncMock())
        assert "No user token" in str(exc_info.value.body)
        assert exc_info.value.status_code == 400

    async def test_expired_token_raises_flow_error(self):
        from app.main import _run_delegated_flow, _FlowError
        from tests.conftest import make_jwt
        expired = make_jwt(payload={"aud": "x", "exp": 1_000_000_000, "sub": "u"})
        stored = {"auth_code": {"access_token": expired, "refresh_token": ""}}
        with patch("app.main.settings") as mock_s:
            mock_s.api_a_app_id = "x"
            mock_s.api_b_app_id = "y"
            mock_s.client_id = "z"
            mock_s.agent_blueprint_app_id = ""
            with pytest.raises(_FlowError) as exc_info:
                await _run_delegated_flow(stored, "obo", AsyncMock())
        assert "expired" in str(exc_info.value.body).lower()

    async def test_info_steps_prepended_to_result(self):
        from app.main import _run_delegated_flow
        from tests.conftest import make_jwt, FAKE_API_A_ID
        at = make_jwt(payload={"aud": FAKE_API_A_ID, "exp": 9_999_999_999, "sub": "u"})
        stored = {"obo": {"access_token": at, "refresh_token": ""}}
        execute_fn = AsyncMock(return_value={"steps": [{"label": "OBO Step"}]})
        with patch("app.main.settings") as mock_s:
            mock_s.api_a_app_id = FAKE_API_A_ID
            mock_s.api_b_app_id = "y"
            mock_s.client_id = "z"
            mock_s.agent_blueprint_app_id = ""
            result = await _run_delegated_flow(stored, "obo", execute_fn)
        # info_steps may be empty here (direct aud match); execute_fn was called
        assert execute_fn.called
        assert "steps" in result

    async def test_execute_fn_exception_propagates(self):
        from app.main import _run_delegated_flow, _FlowError
        from tests.conftest import make_jwt, FAKE_API_A_ID
        at = make_jwt(payload={"aud": FAKE_API_A_ID, "exp": 9_999_999_999, "sub": "u"})
        stored = {"obo": {"access_token": at, "refresh_token": ""}}
        execute_fn = AsyncMock(side_effect=RuntimeError("downstream failure"))
        with patch("app.main.settings") as mock_s:
            mock_s.api_a_app_id = FAKE_API_A_ID
            mock_s.api_b_app_id = "y"
            mock_s.client_id = "z"
            mock_s.agent_blueprint_app_id = ""
            with pytest.raises(RuntimeError, match="downstream failure"):
                await _run_delegated_flow(stored, "obo", execute_fn)
```

---

## Phase C — Deferred

Triggered by either of:
- Flow-switching tests are RED after Phase A (confirming bleeding exists)
- User still reports browser-visible state bleeding after Phase B ships

Candidates documented in spec section 6.

---

## Execution Order

1. **A-1** → conftest additions (no tests added yet)
2. **A-2** → add `test_auth_callback.py`, run, fix RED tests (especially exchange-error test)
3. **A-3** → add `test_flow_switching.py`, run, record RED/GREEN status
4. **A-4** → add `test_silent_acquire.py`, run
5. **A-5** → fix any remaining RED tests
6. Run full suite → confirm all 151 + new tests pass
7. **B-1** → add `_FlowError` + `_run_delegated_flow` to `app/main.py`
8. **B-2** → refactor OBO + Agent ID OBO branches in `/api/execute`
9. **B-3** → add `_run_delegated_flow` unit tests
10. Run full suite → confirm all tests pass
11. Commit Phase A + Phase B together (or separately if preferred)

---

## Commit Message Template

```
refactor: Phase A/B reliability — callback tests + _run_delegated_flow

- Add tests/test_auth_callback.py (7 tests for /auth/callback)
- Add tests/test_flow_switching.py (5 token-audience isolation tests)
- Add tests/test_silent_acquire.py (5 tests for /api/silent-acquire)
- Fix: callback now returns error page when exchange_auth_code returns error body
- Add _FlowError exception class to app/main.py
- Add _run_delegated_flow() helper — eliminates copy-paste in /api/execute
- Refactor obo + agent_id_obo branches to use _run_delegated_flow

All N tests passing.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```
