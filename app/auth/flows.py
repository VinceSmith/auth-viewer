"""Raw REST implementations of all OAuth 2.0 / Entra ID token flows."""

import secrets
import hashlib
import base64
import urllib.parse

import httpx

from app.config import settings
from app.auth.token_utils import format_token_response, decode_jwt


# ---------------------------------------------------------------------------
# Step builder — unified step format for the step-through visualizer
# ---------------------------------------------------------------------------

def _build_step(
    *, label: str, description: str,
    request: dict | None = None, response: dict | None = None,
    tokens: dict | None = None,
    highlights: dict | None = None,
) -> dict:
    """Build a single step dict for the step-through visualizer."""
    return {
        "label": label,
        "description": description,
        "request": request,
        "response": response,
        "tokens": tokens or {},
        "highlights": highlights or {},
    }


def _base_highlights() -> dict:
    """Return highlights for well-known GUIDs from config."""
    h = {}
    if settings.tenant_id:
        h[settings.tenant_id] = {"label": "Tenant ID", "role": "tenant"}
    if settings.client_id:
        h[settings.client_id] = {"label": "Client App", "role": "client"}
    if settings.api_a_app_id:
        h[settings.api_a_app_id] = {"label": "API A", "role": "resource_a"}
    if settings.api_b_app_id:
        h[settings.api_b_app_id] = {"label": "API B", "role": "resource_b"}
    if settings.agent_blueprint_app_id:
        h[settings.agent_blueprint_app_id] = {"label": "Agent Blueprint", "role": "blueprint"}
    if settings.agent_identity_id:
        h[settings.agent_identity_id] = {"label": "Agent Identity", "role": "agent"}
    # Well-known Microsoft first-party app for Workload Identity Federation
    h["fb60f99c-7a34-4190-8149-302f77469936"] = {"label": "AzureADTokenExchange", "role": "token_exchange"}
    return h


def _result_to_step(result: dict, *, label: str, description: str) -> dict:
    """Convert an existing format_token_response result dict into a step."""
    return _build_step(
        label=label,
        description=description,
        request=result.get("request"),
        response=result.get("response"),
        tokens=result.get("tokens", {}),
        highlights=_base_highlights(),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_form_body(params: dict) -> str:
    """URL-encode form body, filtering out None values."""
    return urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})


async def _post_token_endpoint(
    url: str, params: dict, extra_headers: dict | None = None,
) -> dict:
    """POST to a token endpoint and return a formatted result dict."""
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if extra_headers:
        headers.update(extra_headers)

    body = _build_form_body(params)

    async with httpx.AsyncClient() as client:
        resp = await client.post(url, content=body, headers=headers)

    try:
        resp_json = resp.json()
    except Exception:
        resp_json = {"raw": resp.text}

    return format_token_response(
        request_method="POST",
        request_url=url,
        request_headers=headers,
        request_body=params,
        response_status=resp.status_code,
        response_headers=resp.headers,
        response_body=resp_json,
    )


def _coerce_default_scope(scope: str) -> str:
    """Coerce a scope to /.default format for client_credentials flows.

    client_credentials requires resource/.default — delegated scopes like
    'openid profile api://xxx/access_as_user' are invalid. Extract the
    resource URI and append /.default.
    """
    if scope.endswith("/.default"):
        return scope
    # If scope contains multiple space-separated values, find the resource URI
    parts = scope.split()
    for part in parts:
        if part.startswith(("api://", "https://")):
            # Strip any trailing scope name (e.g. /access_as_user) and add /.default
            base = part.rsplit("/", 1)[0] if "/" in part.split("://", 1)[-1] else part
            return f"{base}/.default"
    # Fallback: just append /.default
    return f"{scope}/.default"


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------

def generate_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


# ---------------------------------------------------------------------------
# 1. Authorization Code — build the /authorize URL
# ---------------------------------------------------------------------------

def build_auth_code_url(
    *, scope: str, state: str, use_pkce: bool = False,
    code_challenge: str | None = None,
    prompt: str | None = None,
) -> dict:
    """Return the authorize URL and the parameters used (for display)."""
    params = {
        "client_id": settings.client_id,
        "response_type": "code",
        "redirect_uri": settings.redirect_uri,
        "scope": scope,
        "state": state,
        "response_mode": "query",
    }
    if prompt:
        params["prompt"] = prompt
    if use_pkce and code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"

    url = f"{settings.authorize_endpoint}?{urllib.parse.urlencode(params)}"

    pkce_label = " + PKCE" if use_pkce else ""
    authorize_step = _build_step(
        label=f"Authorize Redirect{pkce_label}",
        description=f"Browser redirects to Entra ID /authorize endpoint. "
                    f"User authenticates and consents to the requested scopes.",
        request={
            "method": "GET",
            "url": settings.authorize_endpoint,
            "headers": {},
            "body": params,
        },
        response={
            "status": 302,
            "headers": {"Location": f"{settings.redirect_uri}?code=<authorization_code>&state={state}"},
            "body": {"note": "Entra ID redirects browser back with authorization code in query string"},
        },
        highlights=_base_highlights(),
    )

    return {
        "authorize_url": url,
        "request": {
            "method": "GET",
            "url": settings.authorize_endpoint,
            "headers": {},
            "body": params,
        },
        "authorize_step": authorize_step,
    }


# ---------------------------------------------------------------------------
# 2. Authorization Code — exchange code for tokens
# ---------------------------------------------------------------------------

async def exchange_auth_code(
    *, code: str, scope: str, code_verifier: str | None = None,
) -> dict:
    """Exchange an authorization code for tokens."""
    params = {
        "client_id": settings.client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri,
        "scope": scope,
        "client_secret": settings.client_secret,
    }
    # PKCE: also send code_verifier alongside client_secret.
    # Modern best practice (RFC 9126) recommends PKCE for confidential clients too.
    if code_verifier:
        params["code_verifier"] = code_verifier

    result = await _post_token_endpoint(settings.token_endpoint, params)

    exchange_step = _result_to_step(
        result,
        label="Token Exchange",
        description="Client exchanges the authorization code for tokens by "
                    "POSTing to the /token endpoint with client credentials."
                    + (" Includes PKCE code_verifier." if code_verifier else ""),
    )
    result["exchange_step"] = exchange_step
    return result


# ---------------------------------------------------------------------------
# 3. Client Credentials
# ---------------------------------------------------------------------------

async def execute_client_credentials(*, scope: str) -> dict:
    """Acquire an app-only token via client credentials."""
    params = {
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "grant_type": "client_credentials",
        "scope": _coerce_default_scope(scope),
    }
    result = await _post_token_endpoint(settings.token_endpoint, params)
    result["steps"] = [
        _result_to_step(
            result,
            label="Client Credentials",
            description="App authenticates directly with client_id + client_secret. "
                        "No user involvement. Returns an app-only access token.",
        ),
    ]
    return result


# ---------------------------------------------------------------------------
# 4. On-Behalf-Of (OBO)
# ---------------------------------------------------------------------------

async def execute_obo(
    *, user_access_token: str, scope: str,
    obo_client_id: str | None = None, obo_client_secret: str | None = None,
) -> dict:
    """Exchange a user token for a downstream token via OBO, then call downstream API."""
    steps = []

    # ── Step 1: Show the input user token ──
    input_decoded = decode_jwt(user_access_token) if user_access_token else {}
    steps.append(_build_step(
        label="User Token (Input)",
        description="The user's access token from a prior Auth Code flow. "
                    "This token is scoped to API A. The OBO flow will exchange it "
                    "for a new token scoped to the downstream resource.",
        tokens={"access_token": {"raw": user_access_token, **input_decoded}},
        highlights=_base_highlights(),
    ))

    # ── Step 2: Call API A with the user token ──
    api_a_url = f"{settings.api_a_base_url}/me"
    api_a_headers = {"Authorization": f"Bearer {user_access_token}"}
    try:
        async with httpx.AsyncClient() as client:
            api_a_resp = await client.get(api_a_url, headers=api_a_headers)
        try:
            api_a_body = api_a_resp.json()
        except Exception:
            api_a_body = {"raw": api_a_resp.text}
        api_a_status = api_a_resp.status_code
    except Exception as e:
        api_a_body = {"error": f"Could not reach API A: {e}"}
        api_a_status = 0

    steps.append(_build_step(
        label="Call API A",
        description="Client presents the user's access token to API A's /me endpoint. "
                    "API A validates the token (checks audience, issuer, signature) "
                    "and returns the user's claims. This proves the token works for API A.",
        request={
            "method": "GET",
            "url": api_a_url,
            "headers": {"Authorization": "Bearer <user_access_token>"},
            "body": {},
        },
        response={
            "status": api_a_status,
            "headers": {},
            "body": api_a_body,
        },
        highlights=_base_highlights(),
    ))

    # ── Step 3: OBO token exchange ──
    params = {
        "client_id": obo_client_id or settings.api_a_app_id,
        "client_secret": obo_client_secret or settings.api_a_client_secret,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": user_access_token,
        "requested_token_use": "on_behalf_of",
        "scope": scope,
    }
    result = await _post_token_endpoint(settings.token_endpoint, params)

    exchange_step = _result_to_step(
        result,
        label="OBO Token Exchange",
        description="API A exchanges the user's token for a downstream token. "
                    "It authenticates as itself (client_id + client_secret) and "
                    "presents the user's token as an assertion. Entra issues a new "
                    "token where the audience switches to the downstream API, but "
                    "the user's identity (sub/upn) is preserved.",
    )
    steps.append(exchange_step)

    # ── Step 4: Call API B with the exchanged token ──
    obo_access_token = result.get("response", {}).get("body", {}).get("access_token")
    if obo_access_token:
        obo_decoded = decode_jwt(obo_access_token)
        steps.append(_build_step(
            label="Exchanged Token",
            description="The new token issued by Entra. Compare the audience (aud) "
                        "with the input token — it has switched from API A to the "
                        "downstream resource. The sub/oid still represent the original "
                        "user, proving the identity carried through the exchange.",
            tokens={"access_token": {"raw": obo_access_token, **obo_decoded}},
            highlights=_base_highlights(),
        ))

        # Actually call API B
        api_b_url = f"{settings.api_b_base_url}/data"
        api_b_headers = {"Authorization": f"Bearer {obo_access_token}"}
        try:
            async with httpx.AsyncClient() as client:
                api_b_resp = await client.get(api_b_url, headers=api_b_headers)
            try:
                api_b_body = api_b_resp.json()
            except Exception:
                api_b_body = {"raw": api_b_resp.text}
            api_b_status = api_b_resp.status_code
        except Exception as e:
            api_b_body = {"error": f"Could not reach API B: {e}"}
            api_b_status = 0

        steps.append(_build_step(
            label="Call API B",
            description="API A calls the downstream API B with the exchanged token. "
                        "API B validates the token (checks its own audience, issuer, "
                        "signature) and returns data. The full OBO chain is complete: "
                        "User → Client → API A → Entra (OBO) → API B.",
            request={
                "method": "GET",
                "url": api_b_url,
                "headers": {"Authorization": "Bearer <obo_access_token>"},
                "body": {},
            },
            response={
                "status": api_b_status,
                "headers": {},
                "body": api_b_body,
            },
            highlights=_base_highlights(),
        ))
    else:
        steps.append(_build_step(
            label="Call API B (Skipped)",
            description="OBO exchange did not return an access token, "
                        "so the downstream call cannot be made.",
            highlights=_base_highlights(),
        ))

    result["steps"] = steps
    return result


# ---------------------------------------------------------------------------
# 5. Device Code
# ---------------------------------------------------------------------------

async def start_device_code_flow(*, scope: str) -> dict:
    """Initiate a device code flow — returns user_code and device_code."""
    params = {
        "client_id": settings.client_id,
        "scope": scope,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    body = _build_form_body(params)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            settings.device_code_endpoint, content=body, headers=headers,
        )

    try:
        resp_json = resp.json()
    except Exception:
        resp_json = {"raw": resp.text}

    result = format_token_response(
        request_method="POST",
        request_url=settings.device_code_endpoint,
        request_headers=headers,
        request_body=params,
        response_status=resp.status_code,
        response_headers=resp.headers,
        response_body=resp_json,
    )
    result["steps"] = [
        _result_to_step(
            result,
            label="Request Device Code",
            description="Client requests a device code from the /devicecode endpoint. "
                        "Entra returns a user_code and verification_uri. The user must "
                        "open that URL on another device and enter the code.",
        ),
    ]
    return result


async def poll_device_code(*, device_code: str) -> dict:
    """Poll the token endpoint for a device code flow completion."""
    params = {
        "client_id": settings.client_id,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
    }
    result = await _post_token_endpoint(settings.token_endpoint, params)
    resp_body = result.get("response", {}).get("body", {})
    if resp_body.get("error") == "authorization_pending":
        desc = "Polling the token endpoint. User hasn't completed authentication yet."
    elif "access_token" in resp_body:
        desc = "User authenticated successfully! Token endpoint returns access token."
    else:
        desc = "Polling the token endpoint for device code completion."
    result["steps"] = [
        _result_to_step(
            result,
            label="Poll for Token",
            description=desc,
        ),
    ]
    return result


# ---------------------------------------------------------------------------
# 6. Refresh Token
# ---------------------------------------------------------------------------

async def execute_refresh(*, refresh_token: str, scope: str) -> dict:
    """Exchange a refresh token for new tokens."""
    params = {
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": scope,
    }
    result = await _post_token_endpoint(settings.token_endpoint, params)
    result["steps"] = [
        _result_to_step(
            result,
            label="Refresh Token Exchange",
            description="Client exchanges an opaque refresh token for a fresh set "
                        "of tokens. The new access token has an updated expiry. "
                        "A new refresh token may also be issued (token rotation).",
        ),
    ]
    return result


# ---------------------------------------------------------------------------
# 7. Agent ID — Autonomous (app-only)
# ---------------------------------------------------------------------------

async def execute_agent_id_autonomous(*, scope: str) -> dict:
    """Two-step Agent ID flow: parent token → autonomous exchange.

    Step 1: client_credentials + fmi_path → parent token
    Step 2: client_credentials with parent as client_assertion → final token
    """
    # Step 1: Get parent token
    step1_params = {
        "client_id": settings.agent_blueprint_app_id,
        "client_secret": settings.agent_blueprint_secret,
        "grant_type": "client_credentials",
        "scope": "api://AzureADTokenExchange/.default",
        "fmi_path": settings.agent_identity_id,
    }
    step1_result = await _post_token_endpoint(
        settings.agent_token_endpoint, step1_params,
    )

    parent_step = _result_to_step(
        step1_result,
        label="Parent Token (Blueprint)",
        description="Blueprint app authenticates with client_credentials + fmi_path "
                    "to get a parent token. The fmi_path tells Entra which Agent "
                    "Identity to scope to. The audience is api://AzureADTokenExchange.",
    )

    parent_token = step1_result["response"]["body"].get("access_token")
    if not parent_token:
        return {
            "step1": step1_result,
            "step2": {"error": "Step 1 failed — no parent token acquired"},
            "steps": [
                parent_step,
                _build_step(
                    label="Token Exchange (Failed)",
                    description="Step 1 failed — no parent token acquired.",
                    highlights=_base_highlights(),
                ),
            ],
        }

    # Step 2: Exchange parent token for downstream token
    step2_params = {
        "client_id": settings.agent_identity_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": parent_token,
        "grant_type": "client_credentials",
        "scope": _coerce_default_scope(scope),
    }
    step2_result = await _post_token_endpoint(
        settings.agent_token_endpoint, step2_params,
    )

    exchange_step = _result_to_step(
        step2_result,
        label="Token Exchange (Agent)",
        description="Agent Identity exchanges the parent token (as client_assertion) "
                    "for a downstream access token. The client_id is now the Agent "
                    "Identity — the identity has \"switched\" from Blueprint to Agent. "
                    "The resulting token's sub claim is the Agent Identity.",
    )

    return {
        "step1": step1_result,
        "step2": step2_result,
        "steps": [parent_step, exchange_step],
    }


# ---------------------------------------------------------------------------
# 8. Agent ID — OBO (delegated)
# ---------------------------------------------------------------------------

async def execute_agent_id_obo(*, user_token: str, scope: str) -> dict:
    """Two-step Agent ID OBO flow: parent token → OBO exchange.

    Step 1: client_credentials + fmi_path → parent token
    Step 2: jwt-bearer with parent as client_assertion + user token as assertion
    """
    # Decode input user token for display
    input_decoded = decode_jwt(user_token) if user_token else {}
    input_step = _build_step(
        label="User Token (Input)",
        description="The user's access token from a prior Auth Code flow, "
                    "scoped to the Agent Blueprint API. This will be used as "
                    "the OBO assertion in Step 2.",
        tokens={"access_token": {"raw": user_token, **input_decoded}},
        highlights=_base_highlights(),
    )

    # Step 1: Get parent token (same as autonomous)
    step1_params = {
        "client_id": settings.agent_blueprint_app_id,
        "client_secret": settings.agent_blueprint_secret,
        "grant_type": "client_credentials",
        "scope": "api://AzureADTokenExchange/.default",
        "fmi_path": settings.agent_identity_id,
    }
    step1_result = await _post_token_endpoint(
        settings.agent_token_endpoint, step1_params,
    )

    parent_step = _result_to_step(
        step1_result,
        label="Parent Token (Blueprint)",
        description="Blueprint app authenticates with client_credentials + fmi_path. "
                    "The parent token establishes the agent identity context.",
    )

    parent_token = step1_result["response"]["body"].get("access_token")
    if not parent_token:
        return {
            "step1": step1_result,
            "step2": {"error": "Step 1 failed — no parent token acquired"},
            "steps": [
                input_step,
                parent_step,
                _build_step(
                    label="OBO Exchange (Failed)",
                    description="Step 1 failed — no parent token acquired.",
                    highlights=_base_highlights(),
                ),
            ],
        }

    # Step 2: OBO exchange
    step2_params = {
        "client_id": settings.agent_identity_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": parent_token,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": user_token,
        "requested_token_use": "on_behalf_of",
        "scope": scope,
    }
    step2_result = await _post_token_endpoint(
        settings.agent_token_endpoint, step2_params,
    )

    exchange_step = _result_to_step(
        step2_result,
        label="OBO Exchange (Agent)",
        description="Agent Identity exchanges the parent token + user token via OBO. "
                    "The client_assertion is the parent token (proving agent identity), "
                    "the assertion is the user token (proving user context). "
                    "The result carries BOTH the agent identity AND the user's "
                    "delegated permissions.",
    )

    return {
        "step1": step1_result,
        "step2": step2_result,
        "steps": [input_step, parent_step, exchange_step],
    }
