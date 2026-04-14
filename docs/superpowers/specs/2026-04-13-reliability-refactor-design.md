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
- `app.main.flows.exchange_code_for_token` → controlled token response
- `app.main.flows.fetch_user_profile` → controlled profile response (if it exists)

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

Uses TestClient to simulate multi-flow sessions. Mocks `flows.*` functions to return
controlled step dicts.

Scenarios:
- **Auth Code tokens don't bleed into Client Credentials**: execute auth_code → execute
  client_credentials → assert client_credentials result has no auth_code token in steps
- **OBO tokens don't bleed into Agent ID OBO**: execute OBO → execute agent_id_obo →
  assert agent_id_obo did not receive OBO's user token
- **Stale `last_flow` doesn't corrupt new flow**: set `session["last_flow"] = "obo"`,
  then execute `auth_code` → result is correct auth_code behavior
- **No user token produces clean 400**: switch from auth_code (logged in) to obo (fresh
  session) → 400 with `"No user token available"`, not a 500 or a bleed

#### `tests/test_silent_acquire.py`

Tests `/api/silent-acquire` in isolation using TestClient.

Scenarios:
- **No refresh token** → 400 with message containing "No refresh token"
- **Expired refresh token** → Entra error response surfaces to caller (not swallowed)
- **Successful acquire** → new token stored under correct flow-specific key in `_token_store`
- **scope passed through correctly** → mock verifies `flows.refresh_token` called with
  the scope from request body

### Implementation rule for Phase A

**Do not change production code** until a test is written and confirmed RED. Then make
the minimal change to turn it GREEN. Do not refactor while making tests pass.

---

## Phase B — Extract Shared Delegated Flow Logic

**Precondition:** All Phase A tests pass.

**Goal:** Eliminate the copy-paste pattern in `/api/execute` for delegated flows.

### New helper: `_run_delegated_flow()`

Location: `app/main.py` (alongside other helpers near line 115).

```python
async def _run_delegated_flow(
    flow_type: str,
    stored: dict,
    body_token: str,
    scope: str,
    execute_fn: Callable,
) -> tuple[dict, list[dict]] | JSONResponse:
    """
    Shared handler for delegated flows (auth_code, obo, agent_id_obo).
    On error: returns a JSONResponse (400/500) directly — caller must check with
    `isinstance(result, JSONResponse)` and return it immediately.
    On success: returns (result_dict, info_steps_list).
    """
```

Steps internally:
1. `user_token, info_steps = await _resolve_user_token(stored, flow_type, body_token=body_token, scope_hint=scope)`
2. If no token → return `JSONResponse({"error": "..."}, 400)`
3. If expired → return `JSONResponse({"error": "token_expired", ...}, 400)`
4. `result = await execute_fn(user_token)`
5. If `info_steps`: prepend to `result["steps"]`
6. Return `(result, info_steps)`

The caller pattern in `/api/execute`:
```python
outcome = await _run_delegated_flow(...)
if isinstance(outcome, JSONResponse):
    return outcome
result, _ = outcome
```

### Call site changes in `/api/execute`

Before (3 copies):
```python
elif flow_type == "obo":
    user_token, info_steps = await _resolve_user_token(...)
    if not user_token: return JSONResponse(...)
    if _is_token_expired(user_token): return JSONResponse(...)
    result = await flows.execute_obo(...)
    if info_steps: result.setdefault("steps", [])[:0] = info_steps
```

After (1 call):
```python
elif flow_type == "obo":
    return await _run_delegated_flow(
        flow_type, stored, body.user_token, scope,
        lambda tok: flows.execute_obo(user_access_token=tok, scope=scope)
    )
```

### New tests in `tests/test_api_execute.py`

Add tests for `_run_delegated_flow` directly:
- No token → returns JSONResponse 400
- Expired token → returns JSONResponse 400 with `"token_expired"`
- `info_steps` are prepended to result steps, not appended
- `execute_fn` exception propagates correctly (not swallowed)

### Files changed

- `app/main.py`: add `_run_delegated_flow()`, simplify 3 branches (~30 lines net change)
- `tests/test_api_execute.py`: add ~8 new tests

---

## Phase C — Session State Isolation (deferred)

**Precondition:** Phase A and B complete. Phase A tests will clarify the exact nature of
the state bleeding bug. The fix for Phase C will be determined based on what those tests
reveal.

**Candidate fixes (to be decided after Phase A):**
- Soft reset: clear only the previous flow's token slots when flow type changes
- Hard reset: clear all token slots when any flow switch occurs
- No reset in `_token_store`: fix the bug at the point where tokens are selected
  (i.e., stricter audience validation in `_resolve_user_token`)

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
