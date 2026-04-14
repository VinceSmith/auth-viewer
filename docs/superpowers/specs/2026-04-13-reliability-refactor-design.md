# Reliability Refactor Design
**Date:** 2026-04-13
**Project:** auth-viewer (Entra OAuth Explorer)

## Problem Statement

The project suffers from two categories of regressions:

1. **Duplicated flow logic** — Auth Code, OBO, and Agent ID OBO share a structural pattern
   (resolve token → validate expiry → execute → prepend info steps), but the code is
   copy-pasted in `/api/execute`. A fix in one branch must be manually repeated in the
   others; it's easy to miss one.

2. **State bleeding between flows** — `_token_store` and session cookies persist across
   flow switches. Old tokens from a previous flow can silently satisfy audience validation
   for a new flow, causing the wrong token to be used. `last_flow` in session state is
   not always updated at the right time.

The most dangerous gap: the **`/auth/callback` route (220 lines) has zero direct tests**,
despite being the most complex and highest-risk route in the application.

## Proposed Approach

Three phases, executed in order. Phase A runs first; phases B and C are only implemented
after Phase A tests pass and we have a clear picture of actual bugs.

---

## Phase A — Test-First Stabilization

**Principle:** Write tests that expose current bugs before touching production code.
Every test starts RED. We fix code to make it GREEN.

### New test files

#### `tests/test_auth_callback.py`

Uses `fastapi.testclient.TestClient` with session middleware. Mocks:
- `app.main.flows.exchange_auth_code` → controlled token response
- `app.main.flows.fetch_signin_logs` → not called during callback; no mock needed

> **Note on test colour:** These tests are primarily **documentation** — the callback
> route already handles most scenarios. They are expected to start GREEN. Their value
> is locking in existing behavior so regressions are caught. The state-bleeding tests
> in `test_flow_switching.py` are the ones expected to start RED.

Scenarios:
- **Happy path**: valid OAuth state in session matches `?code=...&state=...` → tokens stored
  in `_token_store`, redirect to `/`
- **State mismatch**: `state` param doesn't match session `oauth_state` → 400 or error page
- **Missing state**: no `oauth_state` in session → 400 or error page
- **Replayed state**: same state used twice → second use fails (state consumed on first use)
- **Token exchange failure**: Entra returns `{"error": "invalid_grant"}` → user sees error,
  no tokens stored, no crash
- **Multi-tab**: two pending states registered; first callback succeeds; second pending state
  still present and usable
- **`last_flow` set correctly**: after successful callback, `session["last_flow"]` is `"auth_code"`

#### `tests/test_flow_switching.py`

Uses TestClient to simulate multi-flow sessions. Mocks `flows.execute_*` functions to
return controlled step dicts.

**How to seed `_token_store` in TestClient tests:**
TestClient sessions are isolated from the module-level `_token_store`. To simulate a
logged-in user, tests must:
1. Make a GET to `/` with a session cookie to get a `sid` established, OR
2. Import and write to `app.main._token_store` directly before the request:
   ```python
   from app.main import _token_store
   _token_store[sid] = {"auth_code": {"access_token": fake_token, ...}}
   ```
   where `sid` is injected via the `SessionMiddleware` test cookie.

The preferred pattern for these tests is option 2 with a helper fixture that:
- Generates a stable fake `sid`
- Injects it into the TestClient session via `cookies={"session": encode_session({"sid": sid})}`
- Writes a fake token to `_token_store[sid]` before each test
- Clears `_token_store[sid]` after each test

> **Expected colours:** Most flow-switching tests are expected to start **RED** — they
> expose the actual state-bleeding bug. If they start GREEN, that's worth noting
> explicitly (the bug may be in the browser JS layer, not the Python layer).

Scenarios:
- **Auth Code tokens don't bleed into Client Credentials**: seed `_token_store[sid]["auth_code"]`
  with a fake token → execute `client_credentials` → assert `flows.execute_client_credentials`
  was called with no user token argument
- **OBO doesn't receive Agent ID OBO's token**: seed `_token_store[sid]["agent_id_obo"]` →
  execute `obo` → assert the token passed to `flows.execute_obo` is NOT the agent_id_obo token
- **Stale `last_flow` in session doesn't corrupt new flow**: manually set session
  `last_flow = "obo"`, then execute `auth_code` → result is correct auth_code behavior
- **No user token produces clean 400 (not 500 or bleed)**: empty `_token_store` →
  execute `obo` → 400 with `"No user token available"`, no exception raised

#### `tests/test_silent_acquire.py`

Tests `/api/silent-acquire` in isolation using TestClient.

Scenarios:
- **No refresh token** → 400 with message containing "No refresh token"
- **Expired refresh token** → Entra error response surfaces to caller (not swallowed)
- **Successful acquire** → new token stored under correct flow-specific key in `_token_store`
- **scope passed through correctly** → mock verifies `flows.refresh_token` called with
  the scope from request body

### Implementation rule for Phase A

**Do not change production code** until a test is written and run. For tests expected
to start RED (flow-switching tests): confirm they fail before fixing. For tests expected
to start GREEN (callback tests): confirm they pass immediately, which validates they're
testing the right thing. Do not refactor while making tests pass.

---

## Phase B — Extract Shared Delegated Flow Logic

**Precondition:** All Phase A tests pass.

**Goal:** Eliminate the copy-paste pattern in `/api/execute` for OBO and Agent ID OBO.

### Scope: OBO and Agent ID OBO only (auth_code excluded)

`auth_code` is structurally different from OBO:
- `auth_code` calls `flows.call_resource()` which returns a **single step dict**, not
  a `{"steps": [...]}` container. The result is assembled manually.
- `obo` and `agent_id_obo` both call functions that return `{"steps": [...]}` directly,
  then prepend `info_steps`.

These two patterns cannot share the same abstraction without a special-case that defeats
the purpose. **`_run_delegated_flow()` covers `obo` and `agent_id_obo` only.** auth_code
stays as its own branch.

### New helper: `_run_delegated_flow()`

Location: `app/main.py` (alongside other helpers near line 115).

```python
class _FlowError(Exception):
    """Raised by _run_delegated_flow to signal a user-facing error response."""
    def __init__(self, body: dict, status_code: int):
        self.body = body
        self.status_code = status_code


async def _run_delegated_flow(
    flow_type: str,
    stored: dict,
    body_token: str,
    scope: str,
    execute_fn: Callable[[str], Awaitable[dict]],
) -> tuple[dict, list[dict]]:
    """
    Shared handler for OBO and Agent ID OBO flows.
    Raises _FlowError on user-facing errors (no token, expired token).
    Returns (result_dict, info_steps) on success.
    """
```

Steps internally:
1. `user_token, info_steps = await _resolve_user_token(stored, flow_type, body_token=body_token, scope_hint=scope)`
2. If no token → `raise _FlowError({"error": "No user token available. Run Auth Code flow first."}, 400)`
3. If expired → `raise _FlowError({"error": "token_expired", "message": "..."}, 400)`
4. `result = await execute_fn(user_token)`
5. If `info_steps`: `result.setdefault("steps", [])[:0] = info_steps`
6. Return `(result, info_steps)`

### Call site pattern in `/api/execute`

The existing `except Exception as e` block already wraps the whole try body. Add
`_FlowError` handling before the generic catch:

```python
    except _FlowError as e:
        return JSONResponse(e.body, status_code=e.status_code)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
```

Inside the try, the two unified branches become:

```python
        elif flow_type == "obo":
            result, _ = await _run_delegated_flow(
                flow_type, stored, body.user_token, scope,
                lambda tok: flows.execute_obo(user_access_token=tok, scope=scope),
            )

        elif flow_type == "agent_id_obo":
            result, _ = await _run_delegated_flow(
                flow_type, stored, body.user_token, scope,
                lambda tok: flows.execute_agent_id_obo(user_token=tok, scope=scope),
            )
```

`auth_code` retains its existing form unchanged.

### New tests in `tests/test_api_execute.py`

Add tests for `_run_delegated_flow` directly (call it as an async function, no TestClient):
- No token → raises `_FlowError` with status 400
- Expired token → raises `_FlowError` with `"token_expired"` in body
- `info_steps` are prepended (not appended) to result steps
- `execute_fn` exception propagates as-is (not wrapped in `_FlowError`)

### Files changed

- `app/main.py`: add `_run_delegated_flow()`, simplify 3 branches (~30 lines net change)
- `tests/test_api_execute.py`: add ~8 new tests

---

## Phase C — Session State Isolation

**Precondition:** Phase A and B complete.

**Deferred, but with a concrete trigger:**
Phase C proceeds if **either** of these conditions is met after Phase A:
1. One or more `test_flow_switching.py` tests **fail** — the failure message will
   identify which token key was incorrectly selected, pointing directly at the
   buggy line in `_resolve_user_token()`.
2. The flow-switching tests all pass but the user reports the state bleeding still
   occurs in a real browser session. In that case, Phase C adds logging to
   `_resolve_user_token()` to instrument which store key was selected, then
   a browser-driven manual test to capture the trace.

If neither condition is met (tests pass AND browser is clean), Phase C is closed as
"no action needed."

**Candidate fixes (selected after trigger condition reveals root cause):**
- Soft reset: clear only the previous flow's token slots when flow type changes
- Hard reset: clear all token slots on any flow switch
- Stricter audience validation: fix `_resolve_user_token` to reject tokens whose
  audience doesn't match the expected audience for the requested flow

---

## What Is Explicitly Out of Scope

- Multi-instance / distributed cache behavior (Redis, etc.)
- Real Entra network integration tests
- Frontend (app.js) refactoring
- Rewriting `TtlDict` — it's working correctly
- Resource API A / B changes

---

## Test Strategy Summary

| File | Tests added | Purpose |
|------|------------|---------|
| `test_auth_callback.py` | ~10 | Expose callback bugs, lock in behavior |
| `test_flow_switching.py` | ~8 | Expose state bleeding between flows |
| `test_silent_acquire.py` | ~5 | Lock in refresh token behavior |
| `test_api_execute.py` | ~8 more | Lock in `_run_delegated_flow` contract |

All new tests use mocked httpx / flows — no live Entra calls. All must pass within
the existing `pytest tests/ -q` run.

---

## Success Criteria

1. `python -m pytest tests/ -q` passes with all new tests included
2. The state bleeding scenarios in `test_flow_switching.py` either:
   a. Pass immediately (bug doesn't exist as described), or
   b. Fail and point to exact root cause, enabling a targeted fix
3. `/auth/callback` behavior is documented in executable tests, not just comments
4. No duplicated delegated-flow token-resolution pattern remains in `/api/execute`
