"""Raw REST implementations of all OAuth 2.0 / Entra ID token flows."""

import time as _time
import logging
import urllib.parse

import httpx

from app.config import settings
from app.auth.token_utils import format_token_response, decode_jwt
from app.auth.types import StepDict, TokenResponse

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cached Graph client-credentials token (for sign-in log queries)
# ---------------------------------------------------------------------------
_graph_cc_cache: dict = {"access_token": "", "expires_at": 0.0}


# ---------------------------------------------------------------------------
# OIDC Discovery — fetch real endpoint URLs from the discovery document
# ---------------------------------------------------------------------------
_oidc_cache: dict = {}


async def _ensure_oidc_discovery() -> tuple[dict, bool]:
    """Fetch and cache the OIDC discovery document.

    Returns (doc, fetched) where fetched=True when a real HTTP call was made.
    """
    if _oidc_cache:
        return _oidc_cache, False
    discovery_url = f"{settings.authority}/v2.0/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(discovery_url)
        doc = resp.json()
        _oidc_cache.update(doc)
    except Exception as e:
        _logger.warning("OIDC discovery failed: %s — falling back to hardcoded endpoints", e)
        _oidc_cache.update({
            "authorization_endpoint": settings.authority + "/oauth2/v2.0/authorize",
            "token_endpoint": settings.authority + "/oauth2/v2.0/token",
            "_fallback": True,
        })
    return _oidc_cache, True


def _oidc_discovery_step() -> dict:
    """Build a step showing the OIDC discovery fetch (call after _ensure_oidc_discovery)."""
    doc = _oidc_cache
    discovery_url = f"{settings.authority}/v2.0/.well-known/openid-configuration"
    is_fallback = doc.get("_fallback", False)
    # Show a curated subset of the document
    display_body = {
        k: doc.get(k, "")
        for k in [
            "authorization_endpoint", "token_endpoint", "issuer",
            "jwks_uri", "userinfo_endpoint",
            "response_types_supported", "scopes_supported",
        ]
        if doc.get(k)
    }
    return _build_step(
        label="OIDC Discovery",
        description="Before making any OAuth requests, the client fetches the "
                    "OpenID Connect discovery document to learn the authorization "
                    "and token endpoint URLs, the JWKS signing keys URI, supported "
                    "scopes, and other metadata. This is the standard way to "
                    "bootstrap an OAuth/OIDC flow — the client only needs to know "
                    "the tenant's authority URL."
                    + (" (Discovery failed — using hardcoded fallback endpoints.)" if is_fallback else ""),
        request={
            "method": "GET",
            "url": discovery_url,
            "headers": {},
            "body": {},
        },
        response={
            "status": 200 if not is_fallback else 0,
            "headers": {},
            "body": display_body,
        },
        highlights=_base_highlights(),
    )


def _token_endpoint() -> str:
    """Return the token endpoint from OIDC discovery cache (or fallback)."""
    return _oidc_cache.get("token_endpoint", settings.authority + "/oauth2/v2.0/token")


def _authorize_endpoint() -> str:
    """Return the authorization endpoint from OIDC discovery cache (or fallback)."""
    return _oidc_cache.get("authorization_endpoint", settings.authority + "/oauth2/v2.0/authorize")


# ---------------------------------------------------------------------------
# Step builder — unified step format for the step-through visualizer
# ---------------------------------------------------------------------------

def _build_step(
    *, label: str, description: str,
    request: dict | None = None, response: dict | None = None,
    tokens: dict | None = None,
    highlights: dict | None = None,
    authorize_url: str | None = None,
) -> StepDict:
    """Build a single step dict for the step-through visualizer."""
    step = {
        "label": label,
        "description": description,
        "request": request,
        "response": response,
        "tokens": tokens or {},
        "highlights": highlights or {},
    }
    if authorize_url:
        step["authorize_url"] = authorize_url
    return step


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

async def call_resource(*, access_token: str, scope: str) -> dict:
    """Public wrapper — call the resource API matching the scope."""
    return await _call_resource(access_token=access_token, scope=scope)


async def _call_resource(*, access_token: str, scope: str) -> dict:
    """Call the resource API matching *scope* and return a step dict.

    Maps the token audience to the right local API endpoint:
      - API A scope → localhost:8001/me
      - API B scope → localhost:8002/data
      - Graph .default → graph.microsoft.com/v1.0/organization (app-only)
      - Graph User.Read or delegated → graph.microsoft.com/v1.0/me
    """
    if settings.api_a_app_id and settings.api_a_app_id in scope:
        url = f"{settings.api_a_base_url}/me"
        label = "Call API A"
        desc = ("Present the access token to API A's /me endpoint. "
                "API A validates the token: (1) fetches JWKS signing keys from the "
                "jwks_uri in the cached OIDC discovery document, "
                "(2) matches the 'kid' header to find the signing key, "
                "(3) verifies the RS256 signature, (4) checks aud = API A's app ID, "
                "(5) checks iss matches the cached issuer, "
                "(6) checks exp > now. If all pass, returns the token claims.")
    elif settings.api_b_app_id and settings.api_b_app_id in scope:
        url = f"{settings.api_b_base_url}/data"
        label = "Call API B"
        desc = ("Present the access token to API B's /data endpoint. "
                "API B validates the token: (1) fetches JWKS signing keys "
                "from the cached jwks_uri, (2) matches kid, (3) verifies RS256 signature, "
                "(4) checks aud = API B's app ID, (5) checks issuer, "
                "(6) checks expiry. Returns data if valid.")
    elif "graph.microsoft.com" in scope:
        # Delegated tokens have scp; app-only tokens have roles/no scp
        decoded = decode_jwt(access_token) if access_token else {}
        payload = decoded.get("payload", {})
        has_user = bool(payload.get("scp") or payload.get("upn") or payload.get("preferred_username"))
        if has_user:
            url = "https://graph.microsoft.com/v1.0/me"
            label = "Call Graph /me"
            desc = ("Call Microsoft Graph /me with the delegated token. "
                    "Returns the signed-in user's profile.")
        else:
            url = "https://graph.microsoft.com/v1.0/organization"
            label = "Call Graph /organization"
            desc = ("Call Microsoft Graph /organization with the app-only token. "
                    "Returns tenant organization details.")
    else:
        return _build_step(
            label="Call Resource (Skipped)",
            description="Could not determine the target resource from the scope.",
            highlights=_base_highlights(),
        )

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}
        status = resp.status_code
    except Exception as e:
        body = {"error": f"Could not reach {url}: {e}"}
        status = 0

    return _build_step(
        label=label,
        description=desc,
        request={
            "method": "GET",
            "url": url,
            "headers": {"Authorization": "Bearer <access_token>"},
            "body": {},
        },
        response={
            "status": status,
            "headers": {},
            "body": body,
        },
        tokens={"access_token": {
            "raw": access_token,
            **decode_jwt(access_token),
        }} if access_token else {},
        highlights=_base_highlights(),
    )


async def _obo_token_exchange(*, assertion: str, scope: str,
                               obo_client_id: str | None = None,
                               obo_client_secret: str | None = None) -> dict:
    """Standard OBO token exchange — present an assertion to get a downstream token.

    Both SP OBO and Agent ID OBO use the same exchange: API A authenticates
    with its own credentials and presents the caller's token as an assertion.
    """
    params = {
        "client_id": obo_client_id or settings.api_a_app_id,
        "client_secret": obo_client_secret or settings.api_a_client_secret,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": assertion,
        "requested_token_use": "on_behalf_of",
        "scope": scope,
    }
    return await _post_token_endpoint(_token_endpoint(), params)


async def _call_resource_or_skip(result: dict, scope: str) -> dict:
    """Extract access_token from a token response and call the resource, or return a skip step."""
    access_token = result.get("response", {}).get("body", {}).get("access_token")
    if access_token:
        return await _call_resource(access_token=access_token, scope=scope)
    return _build_step(
        label="Call Resource (Skipped)",
        description="Token exchange did not return an access token — cannot call the resource.",
        highlights=_base_highlights(),
    )


async def _call_api_a_chain_step(
    access_token: str, downstream_scope: str, downstream_url: str,
    *, description: str,
) -> dict:
    """Call API A /chain and build the step — shared by CC chain and Agent ID chain."""
    api_a_status, api_a_body = await _call_api_a_chain(access_token, downstream_scope, downstream_url)
    return _build_step(
        label="Call API A",
        description=description,
        request={
            "method": "POST",
            "url": f"{settings.api_a_base_url}/chain",
            "headers": {"Authorization": "Bearer <app_only_token>"},
            "body": {"target_scope": downstream_scope, "target_url": downstream_url},
        },
        response={
            "status": api_a_status,
            "headers": {},
            "body": api_a_body,
        },
        tokens={"access_token": {
            "raw": access_token,
            **decode_jwt(access_token),
        }} if access_token else {},
        highlights=_base_highlights(),
    ), api_a_body


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


def _humanize_scope(scope: str) -> str:
    """Replace known app IDs in a scope string with human-readable names."""
    result = scope
    for app_id, name in [
        (settings.api_a_app_id, "API A"),
        (settings.api_b_app_id, "API B"),
        (settings.agent_blueprint_app_id, "Agent Blueprint"),
        (settings.client_id, "Client App"),
    ]:
        if app_id and app_id in result:
            result = result.replace(app_id, f"{name} ({app_id})")
    return result


def _scope_coercion_note(original: str) -> str:
    """Return a description note if the scope was coerced, or empty string."""
    coerced = _coerce_default_scope(original)
    if coerced != original:
        # Resolve app IDs to human-readable names in scope strings
        display_original = _humanize_scope(original)
        display_coerced = _humanize_scope(coerced)
        return (f" Note: the requested scope was coerced from '{display_original}' to "
                f"'{display_coerced}' because client_credentials flows require the "
                f"/.default suffix — they cannot request individual delegated "
                f"permissions, only the full set of application permissions "
                f"granted to the app.")
    return ""


def _offline_access_note(scope: str) -> str:
    """Return a note about offline_access if present in the scope."""
    if "offline_access" in scope:
        return (" The 'offline_access' scope requests a refresh token, which "
                "allows the client to silently acquire new access tokens for "
                "different APIs without requiring the user to sign in again.")
    return ""


def _user_read_note(token_body: dict) -> str:
    """Return a note about User.Read if it appears in the token's scp claim."""
    scp = token_body.get("scp", "") if isinstance(token_body, dict) else ""
    if "User.Read" in scp:
        return (" Note: the scp claim includes 'User.Read' even though it was not "
                "requested in this flow. Entra adds User.Read as a default delegated "
                "permission on all new app registrations. The scp claim always includes "
                "all consented delegated permissions for the resource — not just "
                "the scopes requested in the current token request.")
    return ""


# ---------------------------------------------------------------------------
# Shared Agent ID helpers (used by autonomous, autonomous chain, and OBO)
# ---------------------------------------------------------------------------

async def _acquire_parent_token() -> tuple[dict, dict]:
    """Acquire a parent token from the Blueprint via client_credentials + fmi_path.

    Returns (result_dict, step_dict).
    """
    params = {
        "client_id": settings.agent_blueprint_app_id,
        "client_secret": settings.agent_blueprint_secret,
        "grant_type": "client_credentials",
        "scope": "api://AzureADTokenExchange/.default",
        "fmi_path": settings.agent_identity_id,
    }
    result = await _post_token_endpoint(settings.agent_token_endpoint, params)
    step = _result_to_step(
        result,
        label="Parent Token (Blueprint)",
        description="Blueprint app authenticates with client_credentials + fmi_path "
                    "to get a parent token. The fmi_path tells Entra which Agent "
                    "Identity to scope to. The audience is api://AzureADTokenExchange.",
    )
    return result, step


async def _fmi_exchange(parent_token: str, scope: str, *, label: str = "FMI Exchange (Agent)") -> tuple[dict, dict]:
    """Exchange a parent token for a downstream token via client_assertion.

    Returns (result_dict, step_dict).
    """
    params = {
        "client_id": settings.agent_identity_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": parent_token,
        "grant_type": "client_credentials",
        "scope": _coerce_default_scope(scope),
    }
    coercion_note = _scope_coercion_note(scope)
    result = await _post_token_endpoint(settings.agent_token_endpoint, params)
    step = _result_to_step(
        result,
        label=label,
        description="Agent Identity exchanges the parent token (as client_assertion) "
                    "for a downstream access token. The client_id is now the Agent "
                    "Identity — the identity has \"switched\" from Blueprint to Agent. "
                    "The resulting token's sub claim is the Agent Identity."
                    + coercion_note,
    )
    # Include decoded parent token so the summary can show what was asserted
    decoded_parent = decode_jwt(parent_token)
    if decoded_parent.get("payload"):
        step["tokens"]["assertion_token"] = {
            "raw": parent_token,
            **decoded_parent,
        }
    return result, step


def _parse_chain_response(api_a_body: dict, downstream_label: str, downstream_url: str) -> list[dict]:
    """Parse API A's /chain endpoint response into CC grant + downstream call steps.

    Returns a list of 0–2 step dicts.
    """
    steps = []
    cc_request = api_a_body.get("cc_request", {})
    # Success path uses "cc_token_response", error path uses "cc_response"
    cc_response = api_a_body.get("cc_token_response") or api_a_body.get("cc_response") or {}
    downstream_access_token = cc_response.get("access_token", "")
    cc_tokens = {}
    if downstream_access_token:
        cc_tokens = {"access_token": {
            "raw": downstream_access_token,
            **decode_jwt(downstream_access_token),
        }}
    if cc_request:
        steps.append(_build_step(
            label=f"API A → Client Credentials for {downstream_label}",
            description=f"API A performs its own client_credentials grant to get a token "
                        f"for {downstream_label}. This is NOT OBO — there is no user identity. "
                        f"{downstream_label} will see API A as the caller (via appid/azp claim).",
            request={
                "method": "POST",
                "url": _token_endpoint(),
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": cc_request,
            },
            response={
                "status": 200 if not api_a_body.get("error") else 400,
                "headers": {},
                "body": cc_response or {"note": "Token acquired (details omitted)"},
            },
            tokens=cc_tokens,
            highlights=_base_highlights(),
        ))

    downstream_response = api_a_body.get("downstream_response") or api_a_body.get("api_b_response")
    actual_downstream_url = api_a_body.get("downstream_url", downstream_url)
    if downstream_response:
        steps.append(_build_step(
            label=f"API A → Call {downstream_label}",
            description=f"API A calls {downstream_label} with its own app-only token. "
                        f"{downstream_label} sees API A's identity (not the original caller). "
                        f"The chain is complete.",
            request={
                "method": "GET",
                "url": actual_downstream_url,
                "headers": {"Authorization": "Bearer <api_a_app_only_token>"},
                "body": {},
            },
            response={
                "status": 200,
                "headers": {},
                "body": downstream_response,
            },
            tokens=cc_tokens,
            highlights=_base_highlights(),
        ))

    return steps


async def _call_api_a_chain(
    access_token: str, downstream_scope: str, downstream_url: str,
) -> tuple[int, dict]:
    """Call API A /chain endpoint and return (status_code, response_body)."""
    api_a_url = (f"{settings.api_a_base_url}/chain"
                 f"?target_scope={downstream_scope}&target_url={downstream_url}")
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(api_a_url, headers=headers)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}
        return resp.status_code, body
    except Exception as e:
        return 0, {"error": f"Could not reach API A: {e}"}


# ---------------------------------------------------------------------------
# 1. Authorization Code — build the /authorize URL
# ---------------------------------------------------------------------------

async def build_auth_code_url(
    *, scope: str, state: str,
    prompt: str | None = None,
) -> dict:
    """Return the authorize URL and the parameters used (for display)."""
    _, fetched = await _ensure_oidc_discovery()
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

    url = f"{_authorize_endpoint()}?{urllib.parse.urlencode(params)}"

    display_params = dict(params)
    authorize_step = _build_step(
        label="Authorize Redirect",
        description=f"Browser redirects to Entra ID /authorize endpoint. "
                    f"User authenticates and consents to the requested scopes. "
                    f"If the app is pre-authorized on the target API, Entra skips "
                    f"the consent prompt — the user only authenticates. Without "
                    f"pre-authorization, the user would see a dialog listing the "
                    f"requested permissions."
                    + (_offline_access_note(scope)),
        request={
            "method": "GET",
            "url": _authorize_endpoint(),
            "headers": {},
            "body": display_params,
        },
        response={
            "status": 302,
            "headers": {"Location": f"{settings.redirect_uri}?code=<authorization_code>"},
            "body": {"note": "Entra ID redirects browser back with authorization code in query string"},
        },
        highlights=_base_highlights(),
        authorize_url=url,
    )

    return {
        "authorize_url": url,
        "request": {
            "method": "GET",
            "url": _authorize_endpoint(),
            "headers": {},
            "body": params,
        },
        "authorize_step": authorize_step,
        "discovery_step": _oidc_discovery_step() if fetched else None,
    }


# ---------------------------------------------------------------------------
# 2. Authorization Code — exchange code for tokens
# ---------------------------------------------------------------------------

async def exchange_auth_code(
    *, code: str, scope: str,
) -> dict:
    """Exchange an authorization code for tokens."""
    await _ensure_oidc_discovery()
    params = {
        "client_id": settings.client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri,
        "scope": scope,
        "client_secret": settings.client_secret,
    }

    result = await _post_token_endpoint(_token_endpoint(), params)

    resp_body = result.get("response", {}).get("body", {})
    at = resp_body.get("access_token", "")
    at_payload = decode_jwt(at).get("payload", {}) if at else {}
    exchange_step = _result_to_step(
        result,
        label="Token Exchange",
        description="Client exchanges the authorization code for tokens by "
                    "POSTing to the /token endpoint with client credentials. "
                    "The /token endpoint URL comes from the cached OIDC "
                    "discovery document."
                    + _user_read_note(at_payload),
    )
    result["exchange_step"] = exchange_step
    return result


# ---------------------------------------------------------------------------
# 3. Client Credentials
# ---------------------------------------------------------------------------

async def execute_client_credentials(*, scope: str) -> dict:
    """Acquire an app-only token via client credentials, then call the resource."""
    _, fetched = await _ensure_oidc_discovery()
    coercion_note = _scope_coercion_note(scope)
    params = {
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "grant_type": "client_credentials",
        "scope": _coerce_default_scope(scope),
    }
    result = await _post_token_endpoint(_token_endpoint(), params)
    steps = ([_oidc_discovery_step()] if fetched else []) + [
        _result_to_step(
            result,
            label="Client Credentials",
            description="App authenticates directly with client_id + client_secret. "
                        "No user involvement. Returns an app-only access token."
                        + coercion_note,
        ),
    ]

    steps.append(await _call_resource_or_skip(result, scope))

    result["steps"] = steps
    return result


async def execute_client_credentials_chain(*, scope: str) -> dict:
    """Client Credentials chain: Client → API A → API A does its own CC for downstream → downstream.

    Step 1: Client acquires app-only token for API A
    Step 2: Client calls API A /chain
    Step 3: API A acquires its own app-only token for downstream (shown from response)
    Step 4: API A calls downstream with its own token (shown from response)
    """
    _, fetched = await _ensure_oidc_discovery()
    # Strip 'chain:' prefix added by the frontend for routing
    actual_scope = scope.removeprefix("chain:")
    is_graph = "graph.microsoft.com" in actual_scope
    downstream_label = "Graph" if is_graph else "API B"
    downstream_scope = actual_scope
    downstream_url = "https://graph.microsoft.com/v1.0/organization" if is_graph else f"{settings.api_b_base_url}/data"

    # Step 1: Client gets token for API A
    cc_coercion_note = _scope_coercion_note(f"api://{settings.api_a_app_id}/.default")
    params = {
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "grant_type": "client_credentials",
        "scope": _coerce_default_scope(f"api://{settings.api_a_app_id}/.default"),
    }
    result = await _post_token_endpoint(_token_endpoint(), params)
    steps = ([_oidc_discovery_step()] if fetched else []) + [
        _result_to_step(
            result,
            label="Client Credentials for API A",
            description="Client app authenticates with client_id + client_secret to get "
                        "an app-only token for API A. No user involvement."
                        + cc_coercion_note,
        ),
    ]

    access_token = result.get("response", {}).get("body", {}).get("access_token")
    if not access_token:
        steps.append(_build_step(
            label="Call API A (Skipped)",
            description="No access token was acquired — cannot call API A.",
            highlights=_base_highlights(),
        ))
        result["steps"] = steps
        return result

    # Step 2: Call API A /chain
    chain_step, api_a_body = await _call_api_a_chain_step(
        access_token, downstream_scope, downstream_url,
        description="Client presents the app-only token to API A's /chain endpoint. "
                    "API A validates the token: fetches JWKS keys from the cached "
                    "jwks_uri, matches kid, verifies RS256 signature, checks aud = "
                    "API A's app ID, checks issuer + expiry.",
    )
    steps.append(chain_step)

    # Steps 3–4: Parse chain response
    steps.extend(_parse_chain_response(api_a_body, downstream_label, downstream_url))

    result["steps"] = steps
    return result


# ---------------------------------------------------------------------------
# 4. On-Behalf-Of (OBO)
# ---------------------------------------------------------------------------

async def execute_obo(
    *, user_access_token: str, scope: str,
    obo_client_id: str | None = None, obo_client_secret: str | None = None,
) -> dict:
    """Exchange a user token for a downstream token via OBO, then call downstream API."""
    _, fetched = await _ensure_oidc_discovery()
    steps = [_oidc_discovery_step()] if fetched else []

    # ── Step 1: Call API A with the user token ──
    api_a_scope = settings.api_a_scope or f"api://{settings.api_a_app_id}/access_as_user"
    steps.append(await _call_resource(access_token=user_access_token, scope=api_a_scope))

    # ── Step 2: OBO token exchange ──
    result = await _obo_token_exchange(
        assertion=user_access_token, scope=scope,
        obo_client_id=obo_client_id, obo_client_secret=obo_client_secret,
    )

    obo_body = result.get("response", {}).get("body", {})
    obo_at = obo_body.get("access_token", "")
    obo_payload = decode_jwt(obo_at).get("payload", {}) if obo_at else {}
    exchange_step = _result_to_step(
        result,
        label="OBO Token Exchange",
        description="API A exchanges the user's token for a downstream token. "
                    "It authenticates as itself (client_id + client_secret) and "
                    "presents the user's token as an assertion. Entra issues a new "
                    "token where the audience switches to the downstream API, but "
                    "the user's identity (sub/upn) is preserved. This only succeeds "
                    "if both the user and API A have been granted permissions to the "
                    "downstream API."
                    + _user_read_note(obo_payload),
    )
    steps.append(exchange_step)

    # ── Step 3: Call downstream resource with the exchanged token ──
    steps.append(await _call_resource_or_skip(result, scope))

    result["steps"] = steps
    return result


async def silent_acquire(*, refresh_token: str, scope: str) -> dict:
    """Silently acquire a token for a different resource using a refresh token.

    This mimics what MSAL's acquireTokenSilent does: exchange the refresh token
    for an access token scoped to a new resource, without user interaction.
    """
    await _ensure_oidc_discovery()
    params = {
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": scope,
    }
    result = await _post_token_endpoint(_token_endpoint(), params)
    silent_body = result.get("response", {}).get("body", {})
    silent_at = silent_body.get("access_token", "")
    silent_payload = decode_jwt(silent_at).get("payload", {}) if silent_at else {}
    result["step"] = _result_to_step(
        result,
        label="Silent Token Acquisition",
        description=f"The client uses the stored refresh token to silently acquire "
                    f"a new access token scoped to: {_humanize_scope(scope)}. Refresh tokens "
                    f"are audience-agnostic — they're tied to the client registration "
                    f"+ user session, so they can be redeemed for tokens targeting "
                    f"any API the client has permission to access. No new sign-in "
                    f"or /authorize redirect is needed."
                    + _user_read_note(silent_payload),
    )
    return result


# ---------------------------------------------------------------------------
# 7. Agent ID — Autonomous (app-only)
# ---------------------------------------------------------------------------

async def execute_agent_id_autonomous(*, scope: str) -> dict:
    """Two-step Agent ID flow: parent token → autonomous exchange.

    Step 1: client_credentials + fmi_path → parent token
    Step 2: client_credentials with parent as client_assertion → final token
    """
    _, fetched = await _ensure_oidc_discovery()
    step1_result, parent_step = await _acquire_parent_token()
    parent_token = step1_result["response"]["body"].get("access_token")
    if not parent_token:
        return {
            "step1": step1_result,
            "step2": {"error": "Step 1 failed — no parent token acquired"},
            "steps": ([_oidc_discovery_step()] if fetched else []) + [
                parent_step,
                _build_step(
                    label="FMI Exchange (Failed)",
                    description="Step 1 failed — no parent token acquired.",
                    highlights=_base_highlights(),
                ),
            ],
        }

    step2_result, exchange_step = await _fmi_exchange(parent_token, scope)
    steps = ([_oidc_discovery_step()] if fetched else []) + [parent_step, exchange_step]

    steps.append(await _call_resource_or_skip(step2_result, scope))

    return {
        "step1": step1_result,
        "step2": step2_result,
        "steps": steps,
    }


# ---------------------------------------------------------------------------
# 7b. Agent ID — Autonomous Chain (app-only → API A → downstream)
# ---------------------------------------------------------------------------

async def execute_agent_id_autonomous_chain(*, scope: str) -> dict:
    """Agent ID chain: Agent gets API A token via 2-step exchange, then API A
    does its own client_credentials for the downstream resource.

    Step 1: Parent token from Blueprint
    Step 2: FMI exchange for API A token (as Agent Identity)
    Step 3: Call API A /chain endpoint
    Step 4: API A's own CC grant to downstream (from response)
    Step 5: API A calls downstream (from response)
    """
    _, fetched = await _ensure_oidc_discovery()
    # Strip 'chain:' prefix added by the frontend for routing
    actual_scope = scope.removeprefix("chain:")
    is_graph = "graph.microsoft.com" in actual_scope
    downstream_label = "Graph" if is_graph else "API B"
    downstream_scope = actual_scope
    downstream_url = ("https://graph.microsoft.com/v1.0/organization" if is_graph
                      else f"{settings.api_b_base_url}/data")

    # Step 1: Parent token
    step1_result, parent_step = await _acquire_parent_token()
    steps = ([_oidc_discovery_step()] if fetched else []) + [parent_step]

    parent_token = step1_result["response"]["body"].get("access_token")
    if not parent_token:
        steps.append(_build_step(
            label="FMI Exchange (Failed)",
            description="Step 1 failed — no parent token acquired.",
            highlights=_base_highlights(),
        ))
        return {"steps": steps}

    # Step 2: Exchange parent token for API A token
    api_a_scope = _coerce_default_scope(f"api://{settings.api_a_app_id}/.default")
    step2_result, exchange_step = await _fmi_exchange(
        parent_token, api_a_scope, label="FMI Exchange (Agent → API A)",
    )
    steps.append(exchange_step)

    access_token = step2_result["response"]["body"].get("access_token")
    if not access_token:
        steps.append(_build_step(
            label="Call API A (Skipped)",
            description="FMI exchange did not return an access token.",
            highlights=_base_highlights(),
        ))
        return {"steps": steps}

    # Step 3: Call API A /chain
    chain_step, api_a_body = await _call_api_a_chain_step(
        access_token, downstream_scope, downstream_url,
        description="Agent presents the app-only token to API A's /chain endpoint. "
                    "API A validates the token: fetches JWKS keys from the cached "
                    "jwks_uri, matches kid, verifies RS256 signature, checks aud + "
                    "issuer + expiry. The sub claim identifies the Agent Identity "
                    "as the caller.",
    )
    steps.append(chain_step)

    # Steps 4–5: Parse chain response
    steps.extend(_parse_chain_response(api_a_body, downstream_label, downstream_url))

    return {"steps": steps}


# ---------------------------------------------------------------------------
# 8. Agent ID — OBO (delegated)
# ---------------------------------------------------------------------------

async def execute_agent_id_obo(*, user_token: str, scope: str) -> dict:
    """Agent ID OBO flow — direct or chained depending on target scope.

    Direct (target is NOT API A):
      Step 1: client_credentials + fmi_path → parent token (Blueprint)
      Step 2: jwt-bearer OBO exchange → agent token scoped to target resource
      Step 3: Call target resource

    Chained (target is API A, or explicit chain through API A → downstream):
      Step 1: client_credentials + fmi_path → parent token (Blueprint)
      Step 2: jwt-bearer OBO exchange → agent token scoped to API A
      Step 3: Call API A with agent token
      Step 4: API A OBO exchange → token scoped to downstream (API B / Graph)
      Step 5: Call downstream resource
    """
    # Ensure OIDC discovery is cached for endpoint resolution
    _, fetched = await _ensure_oidc_discovery()
    steps_prefix = [_oidc_discovery_step()] if fetched else []

    # Step 1: Get parent token
    step1_result, parent_step = await _acquire_parent_token()
    parent_token = step1_result["response"]["body"].get("access_token")
    if not parent_token:
        return {
            "step1": step1_result,
            "steps": steps_prefix + [
                parent_step,
                _build_step(
                    label="OBO Exchange (Failed)",
                    description="Step 1 failed — no parent token acquired.",
                    highlights=_base_highlights(),
                ),
            ],
        }

    # Determine whether the target scope involves API A (chained) or goes direct
    api_a_scope_id = settings.api_a_app_id or ""
    targets_api_a = api_a_scope_id and api_a_scope_id in scope

    if targets_api_a:
        # ── Chained path: Agent → API A (→ optionally downstream) ──
        return await _agent_id_obo_chain(
            user_token=user_token, scope=scope,
            parent_token=parent_token, parent_step=parent_step,
            step1_result=step1_result, steps_prefix=steps_prefix,
        )

    # ── Direct path: Agent → target resource (API B, Graph, etc.) ──
    obo_scope = scope
    step2_params = {
        "client_id": settings.agent_identity_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": parent_token,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": user_token,
        "requested_token_use": "on_behalf_of",
        "scope": obo_scope,
    }
    step2_result = await _post_token_endpoint(
        settings.agent_token_endpoint, step2_params,
    )

    exchange_step = _result_to_step(
        step2_result,
        label="OBO Exchange (Agent → Target)",
        description="Agent Identity exchanges the parent token + user token via OBO "
                    "to get a token scoped directly to the target resource. The "
                    "client_assertion is the parent token (proving agent identity), "
                    "the assertion is the user token (proving user context). No "
                    "intermediate API hop is needed.",
    )
    # Include decoded parent token (client_assertion) and user token (assertion)
    decoded_parent = decode_jwt(parent_token)
    if decoded_parent.get("payload"):
        exchange_step["tokens"]["assertion_token"] = {
            "raw": parent_token,
            **decoded_parent,
        }
    decoded_user = decode_jwt(user_token)
    if decoded_user.get("payload"):
        exchange_step["tokens"]["user_assertion_token"] = {
            "raw": user_token,
            **decoded_user,
        }

    steps = steps_prefix + [parent_step, exchange_step]
    steps.append(await _call_resource_or_skip(step2_result, scope))

    return {
        "step1": step1_result,
        "step2": step2_result,
        "steps": steps,
    }


async def _agent_id_obo_chain(
    *, user_token: str, scope: str,
    parent_token: str, parent_step: dict,
    step1_result: dict, steps_prefix: list[dict],
) -> dict:
    """Chained Agent ID OBO: Agent → API A → downstream."""
    api_a_scope = settings.api_a_scope or f"api://{settings.api_a_app_id}/access_as_user"
    step2_params = {
        "client_id": settings.agent_identity_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": parent_token,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": user_token,
        "requested_token_use": "on_behalf_of",
        "scope": api_a_scope,
    }
    step2_result = await _post_token_endpoint(
        settings.agent_token_endpoint, step2_params,
    )

    exchange_step = _result_to_step(
        step2_result,
        label="OBO Exchange (Agent → API A)",
        description="Agent Identity exchanges the parent token + user token via OBO "
                    "to get a token scoped to API A. The client_assertion is the parent "
                    "token (proving agent identity), the assertion is the user token "
                    "(proving user context).",
    )
    # Include decoded parent token (client_assertion) and user token (assertion)
    decoded_parent = decode_jwt(parent_token)
    if decoded_parent.get("payload"):
        exchange_step["tokens"]["assertion_token"] = {
            "raw": parent_token,
            **decoded_parent,
        }
    decoded_user = decode_jwt(user_token)
    if decoded_user.get("payload"):
        exchange_step["tokens"]["user_assertion_token"] = {
            "raw": user_token,
            **decoded_user,
        }

    steps = steps_prefix + [parent_step, exchange_step]

    api_a_token = step2_result["response"]["body"].get("access_token")
    if not api_a_token:
        steps.append(_build_step(
            label="Call API A (Skipped)",
            description="OBO exchange did not return an access token — cannot call API A.",
            highlights=_base_highlights(),
        ))
        return {"step1": step1_result, "step2": step2_result, "steps": steps}

    # Call API A with the agent token
    steps.append(await _call_resource(access_token=api_a_token, scope=api_a_scope))

    # OBO exchange — API A exchanges agent's token for downstream (API B)
    # If the target scope is API A itself, there's no downstream — just stop here.
    api_a_scope_id = settings.api_a_app_id or ""
    if api_a_scope_id and api_a_scope_id in scope and "/" not in scope.split(api_a_scope_id)[-1].lstrip("/"):
        pass  # API A is the final target — scope points at API A, no downstream
    else:
        obo_result = await _obo_token_exchange(assertion=api_a_token, scope=scope)

        agent_obo_body = obo_result.get("response", {}).get("body", {})
        agent_obo_at = agent_obo_body.get("access_token", "")
        agent_obo_payload = decode_jwt(agent_obo_at).get("payload", {}) if agent_obo_at else {}
        obo_step = _result_to_step(
            obo_result,
            label="OBO Token Exchange",
            description="API A exchanges the agent's token for a downstream token. "
                        "It authenticates as itself (client_id + client_secret) and "
                        "presents the agent's API A token as an assertion. Entra issues "
                        "a new token where the audience switches to the downstream API, "
                        "but the user's identity is preserved."
                        + _user_read_note(agent_obo_payload),
        )
        steps.append(obo_step)

        # Call downstream resource (API B / Graph)
        steps.append(await _call_resource_or_skip(obo_result, scope))

    return {
        "step1": step1_result,
        "step2": step2_result,
        "steps": steps,
    }


# ---------------------------------------------------------------------------
# Sign-in log queries (Microsoft Graph /auditLogs/signIns)
# ---------------------------------------------------------------------------

async def _get_graph_cc_token() -> str:
    """Get a cached Graph client-credentials token."""
    if _graph_cc_cache["access_token"] and _time.time() < _graph_cc_cache["expires_at"] - 60:
        return _graph_cc_cache["access_token"]

    # Use _token_endpoint() directly — it falls back to the well-known URL
    # if OIDC discovery hasn't been fetched yet. Don't call _ensure_oidc_discovery()
    # here to avoid consuming the first-fetch flag before a user-facing flow runs.
    result = await _post_token_endpoint(_token_endpoint(), {
        "client_id": settings.client_id,
        "client_secret": settings.client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    })
    data = result.get("response", {}).get("body", {})
    token = data.get("access_token", "")
    if token:
        _graph_cc_cache["access_token"] = token
        _graph_cc_cache["expires_at"] = _time.time() + data.get("expires_in", 3600)
    return token


async def fetch_signin_logs(after: str = "") -> list[dict]:
    """Fetch sign-in logs for our app from Microsoft Graph.

    Queries both interactive user sign-ins and service principal sign-ins,
    de-duplicates, and returns up to 20 entries sorted newest-first.
    Requires the client app to have AuditLog.Read.All (application) granted.
    """
    token = await _get_graph_cc_token()
    if not token:
        return []

    graph_headers = {"Authorization": f"Bearer {token}"}

    # Build appId filter covering all project app registrations
    app_ids = [settings.client_id]
    if settings.api_a_app_id:
        app_ids.append(settings.api_a_app_id)
    if settings.api_b_app_id:
        app_ids.append(settings.api_b_app_id)
    if settings.agent_blueprint_app_id:
        app_ids.append(settings.agent_blueprint_app_id)
    app_clause = " or ".join(f"appId eq '{aid}'" for aid in app_ids)
    base_filter = f"({app_clause})" if len(app_ids) > 1 else f"appId eq '{app_ids[0]}'"
    if after:
        base_filter += f" and createdDateTime ge {after}"

    entries: list[dict] = []
    _logger.warning("fetch_signin_logs: after=%s", after or "(none)")

    async with httpx.AsyncClient() as client:
        # Interactive + non-interactive user sign-ins (v1.0)
        resp1 = await client.get(
            "https://graph.microsoft.com/v1.0/auditLogs/signIns",
            params={
                "$filter": base_filter,
                "$orderby": "createdDateTime desc",
                "$top": "20",
            },
            headers=graph_headers,
        )
        if resp1.status_code == 200:
            vals = resp1.json().get("value", [])
            _logger.warning("fetch_signin_logs: user sign-ins: %d entries", len(vals))
            entries.extend(vals)
        elif resp1.status_code in (401, 403):
            error = resp1.json().get("error", {})
            msg = error.get("message", "Insufficient privileges")
            return [{"_error": f"AuditLog.Read.All permission required: {msg}"}]
        else:
            _logger.warning("fetch_signin_logs: user query failed %d: %s",
                            resp1.status_code, resp1.text[:500])

        # Service principal sign-ins (beta — signInEventTypes not available in v1.0)
        sp_filter = f"signInEventTypes/any(t:t eq 'servicePrincipal') and {base_filter}"
        resp2 = await client.get(
            "https://graph.microsoft.com/beta/auditLogs/signIns",
            params={
                "$filter": sp_filter,
                "$orderby": "createdDateTime desc",
                "$top": "20",
            },
            headers=graph_headers,
        )
        if resp2.status_code == 200:
            vals2 = resp2.json().get("value", [])
            _logger.warning("fetch_signin_logs: SP sign-ins: %d entries", len(vals2))
            entries.extend(vals2)
        else:
            _logger.warning("fetch_signin_logs: SP query failed %d: %s",
                            resp2.status_code, resp2.text[:500])

    # De-duplicate by id, sort newest-first
    seen: set[str] = set()
    unique: list[dict] = []
    for e in entries:
        eid = e.get("id", "")
        if eid and eid not in seen:
            seen.add(eid)
            unique.append(e)
    unique.sort(key=lambda e: e.get("createdDateTime", ""), reverse=True)

    return unique[:20]
