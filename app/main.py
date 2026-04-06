"""FastAPI application — Entra OAuth Explorer."""

import json
import base64
import secrets
import time as _time

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.diagrams import get_diagram, DIAGRAMS
from app.auth import flows

app = FastAPI(title="Entra OAuth Explorer")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Server-side store for results that are too large for session cookies.
# Keyed by a random result_id; the session only stores the small ID string.
_result_store: dict[str, dict] = {}
# Also store raw tokens server-side (they're ~1.5KB each, too big for cookies)
_token_store: dict[str, dict] = {}
# Pending OAuth states → associated session data.
# Allows callbacks from any recent login to succeed even if a newer login
# overwrote the session cookie (e.g. multiple tabs, double-click, SSO race).
_pending_states: dict[str, dict] = {}
# Accumulated subject → human-readable name mappings discovered from tokens
_subject_store: dict[str, str] = {}
# Test support: latest callback result (avoids session-cookie dependency)
_test_latest_callback: dict | None = None
_test_callback_counter: int = 0


def _decode_jwt_payload(token: str) -> dict:
    """Decode a JWT's payload without verification. Returns {} on failure."""
    try:
        payload_b64 = token.split(".")[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}


def _is_token_expired(token: str) -> bool:
    """Check if a JWT's exp claim is in the past."""
    payload = _decode_jwt_payload(token)
    exp = payload.get("exp")
    if exp and isinstance(exp, (int, float)):
        return _time.time() > exp
    return False


# Per-flow audience + scope mapping for delegated flows
_FLOW_TOKEN_CONFIG: dict[str, dict] = {
    "auth_code": {
        "store_keys": ["auth_code"],
        # No audience validation needed — auth_code just calls whatever scope was requested
    },
    "obo": {
        "store_keys": ["obo", "auth_code"],
        "expected_aud": lambda: settings.api_a_app_id,
        "silent_scope": lambda: f"openid profile {settings.api_a_scope}" if settings.api_a_scope else "",
    },
    "agent_id_obo": {
        "store_keys": ["agent_id_obo", "auth_code"],
        "expected_aud": lambda: settings.agent_blueprint_app_id,
        "silent_scope": lambda: f"openid profile {settings.agent_blueprint_scope}" if settings.agent_blueprint_scope else "",
    },
}


async def _resolve_user_token(
    stored: dict, flow_type: str, *, body_token: str = "",
) -> tuple[str, list[dict]]:
    """Resolve a valid user token for a delegated flow.

    Returns (token, info_steps) where info_steps may include cache-hit,
    audience-mismatch, or silent-acquire steps for the UI.
    """
    config = _FLOW_TOKEN_CONFIG.get(flow_type, {})
    store_keys = config.get("store_keys", ["auth_code"])
    info_steps: list[dict] = []

    aud_fn = config.get("expected_aud")
    aud_names = {
        settings.api_a_app_id: "API A",
        settings.api_b_app_id: "API B",
        settings.client_id: "Client",
        getattr(settings, "agent_blueprint_app_id", ""): "Blueprint",
    }

    # Try stored tokens in order of preference
    token = body_token
    source_key = ""
    if not token:
        for key in store_keys:
            tokens = stored.get(key) or {}
            candidate = tokens.get("access_token", "")
            if not candidate:
                continue
            # Validate audience if this flow requires a specific one
            if aud_fn and not body_token:
                expected_aud = aud_fn()
                actual_aud = _decode_jwt_payload(candidate).get("aud", "")
                if expected_aud and actual_aud != expected_aud:
                    # Wrong audience — skip this key and try the next one
                    continue
            token = candidate
            source_key = key
            break

    # If no token found and we skipped some due to audience mismatch, record it
    # (only if we actually had candidates — means all had wrong audience)
    if not token and not body_token and aud_fn:
        for key in store_keys:
            tokens = stored.get(key) or {}
            candidate = tokens.get("access_token", "")
            if candidate:
                expected_aud = aud_fn()
                actual_aud = _decode_jwt_payload(candidate).get("aud", "")
                if expected_aud and actual_aud != expected_aud:
                    actual_name = aud_names.get(actual_aud, actual_aud)
                    expected_name = aud_names.get(expected_aud, expected_aud)
                    info_steps.append(flows._build_step(
                        label="Token Audience Mismatch",
                        description=f"A stored access token was found (from '{key}') "
                                    f"but its audience is {actual_name} ('{actual_aud}'), which "
                                    f"does not match what this flow requires: {expected_name} "
                                    f"('{expected_aud}'). The token will be discarded "
                                    f"and a new one acquired via refresh token. Each API has its own "
                                    f"audience — tokens are not interchangeable between APIs.",
                        highlights=flows._base_highlights(),
                    ))
                    break  # Only show the first mismatch

    # Silent acquire fallback
    if not token:
        rt = stored.get("refresh_token", "")
        if not rt:
            # Try refresh token from nested token dicts
            for key in ["auth_code", "obo", "agent_id_obo"]:
                rt = (stored.get(key) or {}).get("refresh_token", "")
                if rt:
                    break
        scope_fn = config.get("silent_scope")
        if rt and scope_fn:
            scope = scope_fn()
            if scope:
                silent = await flows.silent_acquire(refresh_token=rt, scope=scope)
                new_token = silent.get("response", {}).get("body", {}).get("access_token", "")
                if new_token:
                    token = new_token
                    silent_step = silent.get("step")
                    if silent_step:
                        info_steps.append(silent_step)
                    # Store for future reuse
                    new_rt = silent.get("response", {}).get("body", {}).get("refresh_token", rt)
                    stored[flow_type if flow_type in ("obo", "agent_id_obo") else "auth_code"] = {
                        "access_token": token,
                        "refresh_token": new_rt,
                    }
    elif not body_token and source_key:
        # Token was found in cache with correct audience — show cache hit
        payload = _decode_jwt_payload(token)
        aud = payload.get("aud", "unknown")
        aud_display = aud_names.get(aud, aud)
        exp_utc = ""
        if "exp" in payload:
            from datetime import datetime, timezone
            exp_utc = datetime.fromtimestamp(payload["exp"], tz=timezone.utc).strftime("%H:%M:%S UTC")
        info_steps.append(flows._build_step(
            label="Token Cache Hit",
            description=f"A stored access token was found (from '{source_key}') with the "
                        f"correct audience: {aud_display} ('{aud}'). No new token request needed. "
                        f"{'Expires: ' + exp_utc + '.' if exp_utc else ''}",
            highlights=flows._base_highlights(),
        ))

    return token, info_steps


def _extract_subjects(result: dict) -> None:
    """Scan a flow result for token payloads and accumulate sub → name mappings."""
    steps = result.get("steps", [])
    if not steps:
        # Single-step results may have tokens at the top level
        steps = [result]
    # Build a lookup of known app IDs → friendly names for resolving opaque subs
    _known_ids: dict[str, str] = {}
    for app_id, label in [
        (settings.client_id, "Client App"),
        (settings.api_a_app_id, "API A"),
        (settings.api_b_app_id, "API B"),
        (settings.agent_blueprint_app_id, "Agent Blueprint"),
        (settings.agent_identity_id, "Agent Identity"),
    ]:
        if app_id:
            _known_ids[app_id] = label
    # Index existing names for dedup (same user gets different pairwise subs per audience)
    known_names = set(_subject_store.values())
    for step in steps:
        tokens = step.get("tokens", {})
        for token_key in ("access_token", "id_token"):
            tok = tokens.get(token_key)
            if not tok or not isinstance(tok, dict):
                continue
            payload = tok.get("payload", {})
            sub = payload.get("sub") or payload.get("oid")
            if not sub:
                continue
            # Already mapped?
            if sub in _subject_store:
                continue
            # Find best human-readable name
            name = (
                payload.get("name")
                or payload.get("preferred_username")
                or payload.get("upn")
                or payload.get("app_displayname")
            )
            if not name:
                # For app-only / agent tokens: resolve appid/azp to a known label
                appid = payload.get("appid") or payload.get("azp") or ""
                name = _known_ids.get(appid)
            if not name:
                # Agent ID fmi_path subs contain the agent identity GUID at the end
                # e.g. "/eid1/c/pub/t/.../b5f31ee4-80b3-4d24-9c9d-c706b14e584d"
                for known_id, label in _known_ids.items():
                    if known_id in sub:
                        name = label
                        break
            if not name:
                continue
            # Skip if same name already tracked under a different sub
            # (Entra pairwise subs differ per audience for the same user)
            if name in known_names:
                # Still store the mapping — different pairwise sub, same entity
                _subject_store[sub] = name
                continue
            _subject_store[sub] = name
            known_names.add(name)


# ---------------------------------------------------------------------------
# UI routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Require sign-in: redirect to get ID token if no profile yet
    sid = request.session.get("sid", "")
    stored = _token_store.get(sid, {})
    if not stored.get("user_profile"):
        return RedirectResponse("/auth/login?scope=openid+profile+offline_access", status_code=302)
    return templates.TemplateResponse(request, "index.html", {
        "settings": settings,
        "flow_types": list(DIAGRAMS.keys()),
    })


# ---------------------------------------------------------------------------
# Sign out
# ---------------------------------------------------------------------------

@app.get("/auth/logout")
async def auth_logout(request: Request):
    """Clear session and token store, effectively signing the user out."""
    sid = request.session.get("sid", "")
    _token_store.pop(sid, None)
    request.session.clear()
    return JSONResponse({"signed_out": True})


# ---------------------------------------------------------------------------
# Auth Code redirect flow
# ---------------------------------------------------------------------------

@app.get("/auth/login")
async def auth_login(
    request: Request, scope: str = "",
    flow_type: str = "", target_scope: str = "",
    prompt: str = "",
):
    """Start an authorization code flow by redirecting the user to Entra."""
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    # For OBO flows, override scope to target the correct audience
    if flow_type == "obo":
        request.session["oauth_scope"] = f"openid profile offline_access {settings.api_a_scope}"
        request.session["flow_type"] = "obo"
        request.session["target_scope"] = target_scope
    elif flow_type == "agent_id_obo":
        request.session["oauth_scope"] = f"openid profile offline_access {settings.agent_blueprint_scope}"
        request.session["flow_type"] = "agent_id_obo"
        request.session["target_scope"] = target_scope
    else:
        request.session["oauth_scope"] = scope or f"openid profile offline_access {settings.api_a_scope}"
        # Ensure offline_access is present so we get a refresh token
        if "offline_access" not in request.session["oauth_scope"]:
            request.session["oauth_scope"] = request.session["oauth_scope"].replace("openid", "openid offline_access", 1)
        request.session["flow_type"] = "auth_code"
        request.session["target_scope"] = ""
        request.session["call_scope"] = request.session["oauth_scope"]

    result = await flows.build_auth_code_url(
        scope=request.session["oauth_scope"],
        state=state,
        prompt=prompt or None,
    )
    # Store the request details and step for display after callback
    request.session["auth_request"] = result["request"]
    # Store authorize_step and discovery_step server-side (too large for cookies)
    step_id = secrets.token_urlsafe(16)
    _result_store[f"step_{step_id}"] = result["authorize_step"]
    _result_store[f"discovery_{step_id}"] = result.get("discovery_step")
    request.session["authorize_step_id"] = step_id

    # Stash essential login data in the session cookie so the callback can
    # recover even after a server restart (which wipes in-memory dicts).
    pending_logins: dict = request.session.get("pending_logins", {})
    pending_logins[state] = {
        "oauth_scope": request.session["oauth_scope"],
        "flow_type": request.session["flow_type"],
        "target_scope": request.session.get("target_scope", ""),
        "authorize_step_id": request.session.get("authorize_step_id"),
    }
    # Keep only last 5 to stay well within cookie size limits
    while len(pending_logins) > 5:
        pending_logins.pop(next(iter(pending_logins)))
    request.session["pending_logins"] = pending_logins

    # Also stash in-memory for faster lookup (includes auth_request display data)
    _pending_states[state] = {
        **pending_logins[state],
        "auth_request": request.session.get("auth_request"),
    }
    while len(_pending_states) > 10:
        _pending_states.pop(next(iter(_pending_states)))

    return RedirectResponse(result["authorize_url"])


@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = "", state: str = "", error: str = "", error_description: str = ""):
    """Handle the OAuth redirect callback."""
    global _test_latest_callback, _test_callback_counter
    if error:
        _test_callback_counter += 1
        _test_latest_callback = {
            "error": f"{error}: {error_description}",
            "flow_type": request.session.get("flow_type", "unknown"),
            "counter": _test_callback_counter,
            "ts": _time.time(),
        }
        return templates.TemplateResponse(request, "index.html", {
            "settings": settings,
            "flow_types": list(DIAGRAMS.keys()),
            "error": f"{error}: {error_description}",
        })

    # Validate state — try three sources:
    #  1. Session cookie (happy path — single concurrent login)
    #  2. Session pending_logins dict (survives server restarts)
    #  3. In-memory _pending_states (includes display-only auth_request)
    expected_state = request.session.get("oauth_state")
    pending = None
    if state != expected_state:
        # Check session-based pending logins first (survives --reload)
        pending_logins: dict = request.session.get("pending_logins", {})
        pending = pending_logins.pop(state, None)
        request.session["pending_logins"] = pending_logins
        # Merge in-memory data (has auth_request for display) if available
        mem = _pending_states.pop(state, None)
        if pending and mem:
            pending["auth_request"] = mem.get("auth_request")
        elif not pending:
            pending = mem  # pure in-memory fallback
        if not pending:
            return templates.TemplateResponse(request, "index.html", {
                "settings": settings,
                "flow_types": list(DIAGRAMS.keys()),
                "error": f"State mismatch: expected {expected_state!r}, got {state!r}. "
                          "This usually means another sign-in was started (second tab, "
                          "double-click) before this one completed.",
            })
    else:
        # Clean up the used state from both stores
        pending_logins = request.session.get("pending_logins", {})
        pending_logins.pop(state, None)
        request.session["pending_logins"] = pending_logins
        _pending_states.pop(state, None)

    # If the session state was overwritten (pending fallback), restore the
    # original session data so flow_type, scope, verifier, etc. are correct.
    if pending:
        request.session["oauth_scope"] = pending["oauth_scope"]
        request.session["flow_type"] = pending["flow_type"]
        request.session["target_scope"] = pending["target_scope"]
        if pending.get("auth_request"):
            request.session["auth_request"] = pending["auth_request"]
        if pending.get("authorize_step_id"):
            request.session["authorize_step_id"] = pending["authorize_step_id"]

    # Exchange code for tokens
    scope = request.session.get("oauth_scope", "openid profile")
    result = await flows.exchange_auth_code(
        code=code, scope=scope,
    )

    flow_type = request.session.get("flow_type", "auth_code")

    # Store tokens server-side for later use (refresh, OBO)
    resp_body = result.get("response", {}).get("body", {})
    session_id = request.session.get("sid") or secrets.token_urlsafe(16)
    request.session["sid"] = session_id
    if session_id not in _token_store:
        _token_store[session_id] = {}
    # Store under the flow type so each OBO variant gets the right audience token
    # Skip storing access_token for profile-only logins (no resource scope)
    oauth_scope = request.session.get("oauth_scope", "")
    has_resource_scope = "api://" in oauth_scope or "https://" in oauth_scope
    token_key = flow_type if flow_type in ("obo", "agent_id_obo") else "auth_code"
    # Always stash refresh token (even from profile-only login) for silent acquire
    rt = resp_body.get("refresh_token", "")
    if rt:
        _token_store[session_id].setdefault("refresh_token", rt)
    if has_resource_scope:
        _token_store[session_id][token_key] = {
            "access_token": resp_body.get("access_token", ""),
            "refresh_token": rt,
        }

    # Store ID token claims for the profile avatar
    raw_id_token = resp_body.get("id_token", "")
    if raw_id_token:
        from app.auth.token_utils import decode_jwt
        decoded = decode_jwt(raw_id_token)
        payload = decoded.get("payload", {})
        _token_store[session_id]["user_profile"] = {
            "name": payload.get("name", ""),
            "preferred_username": payload.get("preferred_username", ""),
            "oid": payload.get("oid", ""),
        }
        _token_store[session_id]["id_token_decoded"] = decoded
        _token_store[session_id]["id_token_raw"] = raw_id_token

    # Include the initial /authorize step and exchange step in the result
    auth_request = request.session.get("auth_request")
    if auth_request:
        result["authorize_request"] = auth_request

    # Assemble steps array for the step-through visualizer
    authorize_step_id = request.session.pop("authorize_step_id", None)
    authorize_step = _result_store.pop(f"step_{authorize_step_id}", None) if authorize_step_id else None
    discovery_step = _result_store.pop(f"discovery_{authorize_step_id}", None) if authorize_step_id else None
    exchange_step = result.get("exchange_step")
    auth_steps = []
    if discovery_step:
        auth_steps.append(discovery_step)
    if authorize_step:
        auth_steps.append(authorize_step)
    if exchange_step:
        auth_steps.append(exchange_step)

    # For OBO flows, chain additional steps after the initial auth code exchange
    target_scope = request.session.pop("target_scope", "")
    user_token = resp_body.get("access_token", "")

    if flow_type == "obo" and user_token:
        obo_result = await flows.execute_obo(
            user_access_token=user_token, scope=target_scope,
        )
        # Replace OBO's generic "User Token (Input)" step with a handoff step
        # that explains the auth code exchange just produced the token
        obo_steps = obo_result.get("steps", [])
        # Strip OIDC Discovery and User Token (Input) — already shown in auth_steps
        obo_steps = [s for s in obo_steps if s.get("label") not in ("OIDC Discovery", "User Token (Input)")]
        handoff = flows._build_step(
            label="Token Handoff → OBO",
            description="The access token from the Auth Code exchange (above) is scoped "
                        "to API A. This token now becomes the OBO assertion — it will be "
                        "exchanged for a downstream token. The audience was determined by "
                        "the scope requested in the /authorize redirect.",
            tokens={"access_token": {
                "raw": user_token,
                **flows.decode_jwt(user_token),
            }},
            highlights=flows._base_highlights(),
        )
        result["steps"] = auth_steps + [handoff] + obo_steps
    elif flow_type == "agent_id_obo" and user_token:
        agent_result = await flows.execute_agent_id_obo(
            user_token=user_token, scope=target_scope,
        )
        # Replace Agent ID OBO's generic "User Token (Input)" with a handoff step
        agent_steps = agent_result.get("steps", [])
        # Strip OIDC Discovery and User Token (Input) — already shown in auth_steps
        agent_steps = [s for s in agent_steps if s.get("label") not in ("OIDC Discovery", "User Token (Input)")]
        handoff = flows._build_step(
            label="Token Handoff → Agent ID OBO",
            description="The access token from the Auth Code exchange (above) is scoped "
                        "to the Agent Blueprint API. This token will be used as the OBO "
                        "assertion in the agent exchange. The Blueprint audience was "
                        "requested in the /authorize scope to enable the agent identity flow.",
            tokens={"access_token": {
                "raw": user_token,
                **flows.decode_jwt(user_token),
            }},
            highlights=flows._base_highlights(),
        )
        result["steps"] = auth_steps + [handoff] + agent_steps
    else:
        result["steps"] = auth_steps
        # Auth code (no OBO): call the resource with the acquired token
        if user_token and has_resource_scope:
            call_scope = request.session.pop("call_scope", "") or scope
            resource_step = await flows.call_resource(
                access_token=user_token, scope=call_scope,
            )
            result["steps"].append(resource_step)

    # Extract subjects from decoded tokens
    _extract_subjects(result)

    # For profile-only logins (no resource scope), store result but redirect to home
    if not has_resource_scope:
        # Add a bootstrap explanation step so the user understands what just happened
        bootstrap_step = flows._build_step(
            label="Session Bootstrap",
            description="This Auth Code flow was triggered automatically to establish your session. "
                        "The scopes 'openid profile offline_access' make this an OpenID Connect "
                        "authentication request — it authenticates the user, not authorize access "
                        "to a resource. Entra ID still returns an access token alongside the ID "
                        "token because it auto-grants the Graph User.Read scope to all "
                        "confidential clients, even when only OIDC scopes are requested. "
                        "The 'offline_access' scope also returns a "
                        "refresh token, which can silently acquire access tokens for any API the "
                        "client has permission to access — without another sign-in.",
            highlights=flows._base_highlights(),
        )
        result["steps"] = [bootstrap_step] + result.get("steps", [])
        result_id = secrets.token_urlsafe(16)
        _result_store[result_id] = {"result": result, "flow_type": "profile_login"}
        request.session["result_id"] = result_id
        request.session["last_flow"] = "profile_login"
        return RedirectResponse("/", status_code=303)

    # Store full result server-side (too large for cookie)
    result_id = secrets.token_urlsafe(16)
    _result_store[result_id] = {"result": result, "flow_type": flow_type}
    request.session["result_id"] = result_id
    request.session["last_flow"] = flow_type

    # Test support: store latest callback result for test script access
    _test_callback_counter += 1
    _test_latest_callback = {
        "result": result,
        "flow_type": flow_type,
        "raw_tokens": _token_store.get(session_id, {}),
        "counter": _test_callback_counter,
        "ts": _time.time(),
    }

    return RedirectResponse("/", status_code=303)


# ---------------------------------------------------------------------------
# API endpoints (called by frontend JS)
# ---------------------------------------------------------------------------

@app.post("/api/execute")
async def api_execute(request: Request):
    """Execute a token flow and return the result."""
    body = await request.json()
    flow_type = body.get("flow_type", "")
    scope = body.get("scope", "")

    try:
        sid = request.session.get("sid", "")
        stored = _token_store.get(sid, {})

        if flow_type == "auth_code":
            user_token, info_steps = await _resolve_user_token(stored, flow_type, body_token=body.get("user_token", ""))
            if not user_token:
                return JSONResponse({"error": "No user token available. Sign in first."}, status_code=400)
            if _is_token_expired(user_token):
                return JSONResponse({"error": "token_expired", "message": "Your access token has expired. Please sign in again."}, status_code=400)
            resource_step = await flows.call_resource(access_token=user_token, scope=scope)
            result = {"steps": info_steps + [resource_step]}

        elif flow_type == "client_credentials":
            result = await flows.execute_client_credentials(scope=scope)

        elif flow_type == "client_credentials_chain":
            result = await flows.execute_client_credentials_chain(scope=scope)

        elif flow_type == "obo":
            user_token, info_steps = await _resolve_user_token(stored, flow_type, body_token=body.get("user_token", ""))
            if not user_token:
                return JSONResponse({"error": "No user token available. Run Auth Code flow first."}, status_code=400)
            if _is_token_expired(user_token):
                return JSONResponse({"error": "token_expired", "message": "Your access token has expired. Please sign in again."}, status_code=400)
            result = await flows.execute_obo(user_access_token=user_token, scope=scope)
            if info_steps:
                result.setdefault("steps", [])[:0] = info_steps

        elif flow_type == "agent_id_autonomous":
            result = await flows.execute_agent_id_autonomous(scope=scope)

        elif flow_type == "agent_id_autonomous_chain":
            result = await flows.execute_agent_id_autonomous_chain(scope=scope)

        elif flow_type == "agent_id_obo":
            user_token, info_steps = await _resolve_user_token(stored, flow_type, body_token=body.get("user_token", ""))
            if not user_token:
                return JSONResponse({"error": "No user token available. Run Auth Code flow first."}, status_code=400)
            if _is_token_expired(user_token):
                return JSONResponse({"error": "token_expired", "message": "Your access token has expired. Please sign in again."}, status_code=400)
            result = await flows.execute_agent_id_obo(user_token=user_token, scope=scope)
            if info_steps:
                result.setdefault("steps", [])[:0] = info_steps

        else:
            return JSONResponse({"error": f"Unknown flow type: {flow_type}"}, status_code=400)

    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    # Extract subjects from decoded tokens
    _extract_subjects(result)

    diagram = get_diagram(flow_type)
    return JSONResponse({"result": result, "diagram": diagram})


@app.get("/api/signin-logs")
async def api_signin_logs(after: str = ""):
    """Fetch recent sign-in logs from Microsoft Graph for our app."""
    try:
        entries = await flows.fetch_signin_logs(after=after)
        return JSONResponse({"entries": entries})
    except Exception as e:
        return JSONResponse({"entries": [], "error": str(e)})


@app.post("/api/silent-acquire")
async def api_silent_acquire(request: Request):
    """Silently acquire an access token using the stored refresh token.

    This avoids a full browser redirect through Entra /authorize when
    the user already has a session (profile login completed).
    """
    body = await request.json()
    scope = body.get("scope", "")
    flow_type = body.get("flow_type", "auth_code")

    sid = request.session.get("sid", "")
    stored = _token_store.get(sid, {})
    rt = (stored.get("refresh_token")
          or (stored.get("auth_code") or {}).get("refresh_token", ""))
    if not rt:
        return JSONResponse({"error": "no_refresh_token"}, status_code=400)

    # Use refresh token to get a new access token for the requested scope
    # For agent_id_obo, override to Blueprint scope (the agent exchange needs
    # a token with aud=Blueprint, not the downstream target).
    if flow_type == "agent_id_obo" and settings.agent_blueprint_scope:
        scope = f"openid profile offline_access {settings.agent_blueprint_scope}"
    result = await flows.silent_acquire(refresh_token=rt, scope=scope)
    resp_body = result.get("response", {}).get("body", {})

    if "error" in resp_body:
        return JSONResponse({"error": resp_body.get("error"),
                             "message": resp_body.get("error_description", "")},
                            status_code=400)

    # Store the refreshed refresh token (but NOT the access token under the
    # flow key — let _resolve_user_token in /api/execute do its own silent
    # acquire so the step appears properly in the UI).
    new_at = resp_body.get("access_token", "")
    new_rt = resp_body.get("refresh_token", rt)
    stored["refresh_token"] = new_rt

    # Update ID token if a new one was returned
    raw_id = resp_body.get("id_token", "")
    if raw_id:
        from app.auth.token_utils import decode_jwt
        decoded = decode_jwt(raw_id)
        payload = decoded.get("payload", {})
        stored["user_profile"] = {
            "name": payload.get("name", ""),
            "preferred_username": payload.get("preferred_username", ""),
            "oid": payload.get("oid", ""),
        }
        stored["id_token_decoded"] = decoded
        stored["id_token_raw"] = raw_id

    return JSONResponse({"result": result, "access_token": new_at})


@app.get("/api/highlights")
async def api_highlights():
    """Return a map of known IDs/subs → human-readable labels."""
    highlights = {}
    mapping = [
        (settings.client_id, "Client App"),
        (settings.api_a_app_id, "API A"),
        (settings.api_b_app_id, "API B"),
        (settings.agent_blueprint_app_id, "Agent Blueprint"),
        (settings.agent_identity_id, "Agent Identity"),
        ("fb60f99c-7a34-4190-8149-302f77469936", "AzureADTokenExchange"),
    ]
    for value, label in mapping:
        if value:
            highlights[value] = {"label": label}
    # Add discovered subjects (opaque pairwise subs → friendly names)
    for sub_id, name in _subject_store.items():
        if sub_id not in highlights:
            highlights[sub_id] = {"label": name}
    return JSONResponse(highlights)


@app.get("/api/diagram/{flow_type}")
async def api_diagram(flow_type: str):
    """Return the Mermaid diagram for a flow type."""
    return JSONResponse({"diagram": get_diagram(flow_type)})


@app.get("/api/session")
async def api_session(request: Request):
    """Return current session token state (for UI)."""
    sid = request.session.get("sid", "")
    stored = _token_store.get(sid, {})
    obo_tokens = stored.get("obo") or stored.get("auth_code") or {}
    agent_tokens = stored.get("agent_id_obo") or {}
    auth_code_tokens = stored.get("auth_code") or {}
    obo_at = obo_tokens.get("access_token", "")
    agent_at = agent_tokens.get("access_token", "")
    auth_code_at = auth_code_tokens.get("access_token", "")
    any_at = obo_at or agent_at or auth_code_at
    any_rt = (stored.get("refresh_token")
              or obo_tokens.get("refresh_token")
              or agent_tokens.get("refresh_token")
              or auth_code_tokens.get("refresh_token"))
    return JSONResponse({
        "has_access_token": bool(any_at),
        "has_id_token": bool(stored.get("id_token_raw")),
        "has_refresh_token": bool(any_rt),
        "token_expired": _is_token_expired(any_at) if any_at else False,
        "last_flow": request.session.get("last_flow"),
    })


@app.get("/api/me")
async def api_me(request: Request):
    """Return the signed-in user's profile and decoded ID token."""
    sid = request.session.get("sid", "")
    stored = _token_store.get(sid, {})
    profile = stored.get("user_profile")
    if not profile:
        return JSONResponse({"signed_in": False})
    return JSONResponse({
        "signed_in": True,
        "profile": profile,
        "id_token": stored.get("id_token_decoded"),
        "id_token_raw": stored.get("id_token_raw", ""),
    })


@app.get("/api/last-result")
async def api_last_result(request: Request):
    """Return the last flow result (used after Auth Code redirect)."""
    result_id = request.session.pop("result_id", None)
    if result_id and result_id in _result_store:
        stored = _result_store.pop(result_id)
        flow = stored.get("flow_type", "auth_code")
        return JSONResponse({
            "result": stored["result"],
            "diagram": get_diagram(flow),
            "flow_type": flow,
        })
    return JSONResponse({"result": None})


# ---------------------------------------------------------------------------
# Test endpoints (for automated test script — not for production)
# ---------------------------------------------------------------------------

@app.get("/api/test/latest")
async def test_latest():
    """Return the latest callback result without requiring a session cookie."""
    if _test_latest_callback is None:
        return JSONResponse({"error": "No callback result yet"}, status_code=404)
    return JSONResponse(_test_latest_callback)
