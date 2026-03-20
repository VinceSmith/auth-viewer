"""FastAPI application — Entra OAuth Explorer."""

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


def _extract_subjects(result: dict) -> None:
    """Scan a flow result for token payloads and accumulate sub → name mappings."""
    steps = result.get("steps", [])
    if not steps:
        # Single-step results may have tokens at the top level
        steps = [result]
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
            # Already mapped by GUID?
            if sub in _subject_store:
                continue
            # Find best human-readable name
            name = (
                payload.get("name")
                or payload.get("preferred_username")
                or payload.get("upn")
                or payload.get("app_displayname")
                or payload.get("appid")  # fallback for app-only tokens
            )
            if not name:
                continue
            # Skip if same name already tracked under a different sub
            # (Entra pairwise subs differ per audience for the same user)
            if name in known_names:
                continue
            _subject_store[sub] = name
            known_names.add(name)


# ---------------------------------------------------------------------------
# UI routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "settings": settings,
        "flow_types": list(DIAGRAMS.keys()),
    })


# ---------------------------------------------------------------------------
# Auth Code redirect flow
# ---------------------------------------------------------------------------

@app.get("/auth/login")
async def auth_login(
    request: Request, scope: str = "", use_pkce: bool = False,
    flow_type: str = "", target_scope: str = "",
    prompt: str = "",
):
    """Start an authorization code flow by redirecting the user to Entra."""
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    # For OBO flows, override scope to target the correct audience
    if flow_type == "obo":
        request.session["oauth_scope"] = f"openid profile {settings.api_a_scope}"
        request.session["flow_type"] = "obo"
        request.session["target_scope"] = target_scope
    elif flow_type == "agent_id_obo":
        request.session["oauth_scope"] = f"openid profile {settings.agent_blueprint_scope}"
        request.session["flow_type"] = "agent_id_obo"
        request.session["target_scope"] = target_scope
    else:
        request.session["oauth_scope"] = scope or f"openid profile {settings.api_a_scope}"
        if use_pkce:
            request.session["flow_type"] = "auth_code_pkce"
        else:
            request.session["flow_type"] = "auth_code"
        request.session["target_scope"] = ""

    if use_pkce and flow_type not in ("obo", "agent_id_obo"):
        verifier, challenge = flows.generate_pkce_pair()
        request.session["pkce_verifier"] = verifier
    else:
        challenge = None
        request.session["pkce_verifier"] = None

    result = flows.build_auth_code_url(
        scope=request.session["oauth_scope"],
        state=state,
        use_pkce=use_pkce,
        code_challenge=challenge,
        prompt=prompt or None,
    )
    # Store the request details and step for display after callback
    request.session["auth_request"] = result["request"]
    # Store authorize_step server-side (too large for cookies)
    step_id = secrets.token_urlsafe(16)
    _result_store[f"step_{step_id}"] = result["authorize_step"]
    request.session["authorize_step_id"] = step_id

    # Stash essential login data in the session cookie so the callback can
    # recover even after a server restart (which wipes in-memory dicts).
    pending_logins: dict = request.session.get("pending_logins", {})
    pending_logins[state] = {
        "oauth_scope": request.session["oauth_scope"],
        "flow_type": request.session["flow_type"],
        "target_scope": request.session.get("target_scope", ""),
        "pkce_verifier": request.session.get("pkce_verifier"),
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
        return templates.TemplateResponse("index.html", {
            "request": request,
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
            return templates.TemplateResponse("index.html", {
                "request": request,
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
        request.session["pkce_verifier"] = pending["pkce_verifier"]
        if pending.get("auth_request"):
            request.session["auth_request"] = pending["auth_request"]
        if pending.get("authorize_step_id"):
            request.session["authorize_step_id"] = pending["authorize_step_id"]

    # Exchange code for tokens
    scope = request.session.get("oauth_scope", "openid profile")
    verifier = request.session.get("pkce_verifier")
    result = await flows.exchange_auth_code(
        code=code, scope=scope, code_verifier=verifier,
    )

    flow_type = request.session.get("flow_type", "auth_code")

    # Store tokens server-side for later use (refresh, OBO)
    resp_body = result.get("response", {}).get("body", {})
    session_id = request.session.get("sid") or secrets.token_urlsafe(16)
    request.session["sid"] = session_id
    _token_store[session_id] = {
        "access_token": resp_body.get("access_token", ""),
        "refresh_token": resp_body.get("refresh_token", ""),
    }

    # Include the initial /authorize step and exchange step in the result
    auth_request = request.session.get("auth_request")
    if auth_request:
        result["authorize_request"] = auth_request

    # Assemble steps array for the step-through visualizer
    authorize_step_id = request.session.pop("authorize_step_id", None)
    authorize_step = _result_store.pop(f"step_{authorize_step_id}", None) if authorize_step_id else None
    exchange_step = result.get("exchange_step")
    auth_steps = []
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
        # Prepend auth code steps, skip OBO's "User Token (Input)" step
        obo_steps = obo_result.get("steps", [])[1:]  # skip step 0
        result["steps"] = auth_steps + obo_steps
    elif flow_type == "agent_id_obo" and user_token:
        agent_result = await flows.execute_agent_id_obo(
            user_token=user_token, scope=target_scope,
        )
        # Prepend auth code steps, skip Agent ID OBO's "User Token (Input)" step
        agent_steps = agent_result.get("steps", [])[1:]  # skip step 0
        result["steps"] = auth_steps + agent_steps
    else:
        result["steps"] = auth_steps

    # Extract subjects from decoded tokens
    _extract_subjects(result)

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
        stored_tokens = _token_store.get(sid, {})

        if flow_type == "client_credentials":
            result = await flows.execute_client_credentials(scope=scope)

        elif flow_type == "obo":
            user_token = body.get("user_token") or stored_tokens.get("access_token", "")
            if not user_token:
                return JSONResponse({"error": "No user token available. Run Auth Code flow first."}, status_code=400)
            result = await flows.execute_obo(user_access_token=user_token, scope=scope)

        elif flow_type == "device_code_start":
            result = await flows.start_device_code_flow(scope=scope)
            # Store device_code for polling
            device_code = result.get("response", {}).get("body", {}).get("device_code")
            if device_code:
                request.session["device_code"] = device_code
            return JSONResponse({"result": result, "diagram": get_diagram("device_code")})

        elif flow_type == "device_code_poll":
            device_code = body.get("device_code") or request.session.get("device_code", "")
            if not device_code:
                return JSONResponse({"error": "No device code available. Start device code flow first."}, status_code=400)
            result = await flows.poll_device_code(device_code=device_code)
            # Store tokens server-side if successful
            resp_body = result.get("response", {}).get("body", {})
            if "access_token" in resp_body:
                sid = request.session.get("sid") or secrets.token_urlsafe(16)
                request.session["sid"] = sid
                _token_store[sid] = {
                    "access_token": resp_body.get("access_token", ""),
                    "refresh_token": resp_body.get("refresh_token", ""),
                }

        elif flow_type == "refresh_token":
            refresh_token = body.get("refresh_token") or stored_tokens.get("refresh_token", "")
            if not refresh_token:
                return JSONResponse({"error": "No refresh token available. Run Auth Code flow first."}, status_code=400)
            result = await flows.execute_refresh(refresh_token=refresh_token, scope=scope)
            # Update stored tokens server-side
            resp_body = result.get("response", {}).get("body", {})
            if "access_token" in resp_body:
                sid = request.session.get("sid") or secrets.token_urlsafe(16)
                request.session["sid"] = sid
                _token_store[sid] = {
                    "access_token": resp_body.get("access_token", ""),
                    "refresh_token": resp_body.get("refresh_token", ""),
                }

        elif flow_type == "agent_id_autonomous":
            result = await flows.execute_agent_id_autonomous(scope=scope)

        elif flow_type == "agent_id_obo":
            user_token = body.get("user_token") or stored_tokens.get("access_token", "")
            if not user_token:
                return JSONResponse({"error": "No user token available. Run Auth Code flow first."}, status_code=400)
            result = await flows.execute_agent_id_obo(user_token=user_token, scope=scope)

        else:
            return JSONResponse({"error": f"Unknown flow type: {flow_type}"}, status_code=400)

    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    # Extract subjects from decoded tokens
    _extract_subjects(result)

    diagram = get_diagram(flow_type)
    return JSONResponse({"result": result, "diagram": diagram})


@app.get("/api/highlights")
async def api_highlights():
    """Return the highlight color map for known IDs."""
    # Color roles — each role gets a consistent color
    role_colors = {
        "tenant": "#ff6b6b",
        "client": "#4ecdc4",
        "resource_a": "#45b7d1",
        "resource_b": "#96ceb4",
        "blueprint": "#dda0dd",
        "agent": "#ffd93d",
        "token_exchange": "#ff8a65",
        "subject": "#b39ddb",
    }
    highlights = {}
    mapping = [
        (settings.tenant_id, "Tenant ID", "tenant"),
        (settings.client_id, "Client App", "client"),
        (settings.api_a_app_id, "API A", "resource_a"),
        (settings.api_b_app_id, "API B", "resource_b"),
        (settings.agent_blueprint_app_id, "Agent Blueprint", "blueprint"),
        (settings.agent_identity_id, "Agent Identity", "agent"),
        ("fb60f99c-7a34-4190-8149-302f77469936", "AzureADTokenExchange", "token_exchange"),
    ]
    for value, label, role in mapping:
        if value:
            highlights[value] = {
                "label": label,
                "role": role,
                "color": role_colors.get(role, "#ffffff"),
            }
    # Add discovered subjects
    for sub_id, name in _subject_store.items():
        if sub_id not in highlights:
            highlights[sub_id] = {
                "label": f"Subject: {name}",
                "role": "subject",
                "color": role_colors.get("subject", "#ffffff"),
            }
    return JSONResponse(highlights)


@app.get("/api/diagram/{flow_type}")
async def api_diagram(flow_type: str):
    """Return the Mermaid diagram for a flow type."""
    return JSONResponse({"diagram": get_diagram(flow_type)})


@app.get("/api/session")
async def api_session(request: Request):
    """Return current session token state (for UI)."""
    sid = request.session.get("sid", "")
    tokens = _token_store.get(sid, {})
    return JSONResponse({
        "has_access_token": bool(tokens.get("access_token")),
        "has_refresh_token": bool(tokens.get("refresh_token")),
        "last_flow": request.session.get("last_flow"),
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
