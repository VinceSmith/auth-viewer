"""Static fixture-backed OAuth flow simulation."""

from __future__ import annotations

import base64
import json
from copy import deepcopy

from app.config import settings
from app.auth.token_utils import decode_jwt

FAKE_TENANT_ID = "00000000-0000-0000-0000-000000000001"
FAKE_CLIENT_ID = "00000000-0000-0000-0000-000000000002"
FAKE_API_A_ID = "00000000-0000-0000-0000-000000000003"
FAKE_API_B_ID = "00000000-0000-0000-0000-000000000004"
FAKE_BLUEPRINT_ID = "00000000-0000-0000-0000-000000000005"
FAKE_AGENT_ID = "00000000-0000-0000-0000-000000000006"
FAKE_USER_OID = "00000000-0000-0000-0000-000000000007"
FAKE_USER_SUB = "sim-user-subject"
FAKE_NOW = 1_800_000_000
FAKE_EXP = 1_803_600_000
FAKE_REFRESH_TOKEN = "refresh-token"


def _b64url(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_fake_jwt(*, aud: str, delegated: bool = True, scopes: str = "access_as_user", roles: list[str] | None = None, subject: str = FAKE_USER_SUB) -> str:
    """Build a stable fake JWT that existing decode-only UI can inspect."""
    header = {"typ": "JWT", "alg": "RS256", "kid": "token-signing-key"}
    payload = {
        "iss": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/v2.0",
        "tid": FAKE_TENANT_ID,
        "aud": aud,
        "sub": subject,
        "iat": FAKE_NOW,
        "nbf": FAKE_NOW,
        "exp": FAKE_EXP,
    }
    if delegated:
        payload.update({
            "oid": FAKE_USER_OID,
            "name": "Adele Vance",
            "preferred_username": "adele.vance@example.test",
            "upn": "adele.vance@example.test",
            "scp": scopes,
        })
    else:
        payload.update({
            "azp": FAKE_CLIENT_ID,
            "appid": FAKE_CLIENT_ID,
            "idtyp": "app",
            "roles": roles or [".default"],
        })
    return f"{_b64url(header)}.{_b64url(payload)}.signature"


def _token(raw: str) -> dict:
    return {"raw": raw, **decode_jwt(raw)}


def _highlights() -> dict:
    return {
        FAKE_TENANT_ID: {"label": "Tenant", "role": "tenant"},
        FAKE_CLIENT_ID: {"label": "Client App", "role": "client"},
        FAKE_API_A_ID: {"label": "API A", "role": "resource_a"},
        FAKE_API_B_ID: {"label": "API B", "role": "resource_b"},
        FAKE_BLUEPRINT_ID: {"label": "Agent Blueprint", "role": "blueprint"},
        FAKE_AGENT_ID: {"label": "Agent Identity", "role": "agent"},
        "fb60f99c-7a34-4190-8149-302f77469936": {"label": "AzureADTokenExchange", "role": "token_exchange"},
    }


def highlights() -> dict:
    return deepcopy(_highlights())


def _step(*, label: str, description: str, diagram_index: int, request: dict | None = None, response: dict | None = None, tokens: dict | None = None) -> dict:
    return {
        "label": label,
        "description": description,
        "diagram_index": diagram_index,
        "request": request,
        "response": response,
        "tokens": tokens or {},
        "highlights": highlights(),
    }


def _resource_for_scope(scope: str) -> tuple[str, str, str]:
    configured_api_a_id = getattr(settings, "api_a_app_id", "") or ""
    configured_api_a_scope = getattr(settings, "api_a_scope", "") or ""
    configured_api_b_id = getattr(settings, "api_b_app_id", "") or ""
    configured_api_b_scope = getattr(settings, "api_b_scope", "") or ""
    if "graph.microsoft.com" in scope:
        return "https://graph.microsoft.com", "Microsoft Graph", "https://graph.microsoft.com/v1.0/me"
    if FAKE_API_B_ID in scope or "api-b" in scope or (configured_api_b_id and configured_api_b_id in scope) or (configured_api_b_scope and configured_api_b_scope in scope):
        return configured_api_b_id or FAKE_API_B_ID, "API B", "http://localhost:8002/data"
    if FAKE_API_A_ID in scope or "api-a" in scope or (configured_api_a_id and configured_api_a_id in scope) or (configured_api_a_scope and configured_api_a_scope in scope):
        return configured_api_a_id or FAKE_API_A_ID, "API A", "http://localhost:8001/me"
    raise ValueError(f"Unknown target resource for scope: {scope or '<empty>'}")


def _oidc_step() -> dict:
    return _step(
        label="OIDC Discovery",
        description="Before making any OAuth requests, the client fetches the OpenID Connect discovery document to learn the authorization and token endpoint URLs, the JWKS signing keys URI, supported scopes, and other metadata. This is the standard way to bootstrap an OAuth/OIDC flow — the client only needs to know the tenant's authority URL.",
        diagram_index=-1,
        request={"method": "GET", "url": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/v2.0/.well-known/openid-configuration", "headers": {}, "body": {}},
        response={"status": 200, "headers": {"x-ms-request-id": "req-discovery"}, "body": {"authorization_endpoint": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/v2.0/authorize", "token_endpoint": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/v2.0/token", "issuer": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/v2.0"}},
    )


def _user_read_note_for_token(raw: str) -> str:
    payload = decode_jwt(raw).get("payload", {}) if raw else {}
    scp = payload.get("scp", "") if isinstance(payload, dict) else ""
    if "User.Read" in scp:
        return (" Note: the scp claim includes 'User.Read' even though it was not "
                "requested in this flow. Entra adds User.Read as a default delegated "
                "permission on all new app registrations. The scp claim always includes "
                "all consented delegated permissions for the resource — not just "
                "the scopes requested in the current token request.")
    return ""


def _resource_call_description(label: str) -> str:
    if label == "API A":
        return ("Present the access token to API A's /me endpoint. "
                "API A validates the token: (1) fetches JWKS signing keys from the "
                "jwks_uri in the cached OIDC discovery document, "
                "(2) matches the 'kid' header to find the signing key, "
                "(3) verifies the RS256 signature, (4) checks aud = API A's app ID, "
                "(5) checks iss matches the cached issuer, "
                "(6) checks exp > now. If all pass, returns the token claims.")
    if label == "API B":
        return ("Present the access token to API B's /data endpoint. "
                "API B validates the token: (1) fetches JWKS signing keys "
                "from the cached jwks_uri, (2) matches kid, (3) verifies RS256 signature, "
                "(4) checks aud = API B's app ID, (5) checks issuer, "
                "(6) checks expiry. Returns data if valid.")
    if label == "Microsoft Graph":
        return "Call Microsoft Graph /me with the delegated token. Returns the signed-in user's profile."
    return f"Present the access token to {label}; the resource validates issuer, audience, and expiry before returning data."


def _token_exchange_step(*, label: str, grant_type: str, body: dict, access_token: str, id_token: str | None = None, diagram_index: int = 1, description: str | None = None) -> dict:
    grant_name = grant_type.replace("_", " ")
    response_body = {"token_type": "Bearer", "expires_in": 3600, "access_token": access_token}
    tokens = {"access_token": _token(access_token)}
    if id_token:
        response_body["id_token"] = id_token
        response_body["refresh_token"] = FAKE_REFRESH_TOKEN
        tokens["id_token"] = _token(id_token)
        tokens["refresh_token"] = {"raw": FAKE_REFRESH_TOKEN, "note": "Refresh tokens are opaque to clients"}
    return _step(
        label=label,
        description=description or f"The client sends a {grant_name} token request and receives a token response from Entra ID.",
        diagram_index=diagram_index,
        request={"method": "POST", "url": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/v2.0/token", "headers": {"content-type": "application/x-www-form-urlencoded"}, "body": body},
        response={"status": 200, "headers": {"x-ms-request-id": f"req-{grant_type}"}, "body": response_body},
        tokens=tokens,
    )


def _resource_call_step(*, access_token: str, scope: str, diagram_index: int = 2) -> dict:
    _aud, label, url = _resource_for_scope(scope)
    return _step(
        label=f"Call {label}",
        description=_resource_call_description(label),
        diagram_index=diagram_index,
        request={"method": "GET", "url": url, "headers": {"authorization": "Bearer eyJ...access-token"}, "body": {}},
        response={"status": 200, "headers": {"x-ms-request-id": f"req-call-{label.lower().replace(' ', '-')}"}, "body": {"resource": label, "message": "Token accepted"}},
        tokens={"access_token": _token(access_token)},
    )


def _api_a_downstream_call_step(*, access_token: str, scope: str, diagram_index: int) -> dict:
    step = _resource_call_step(access_token=access_token, scope=scope, diagram_index=diagram_index)
    step["label"] = f"API A {step['label']}"
    _aud, label, _url = _resource_for_scope(scope)
    step["description"] = (f"API A calls {label} with its own app-only token. "
                           f"{label} sees API A's identity (not the original caller). "
                           f"The chain is complete.")
    return step


def _api_a_chain_call_step(*, access_token: str, downstream_scope: str, downstream_url: str, actor: str, diagram_index: int) -> dict:
    subject = "Agent" if actor == "agent" else "Client"
    description = (
        f"{subject} presents the app-only token to API A's /chain endpoint. "
        "API A validates the token: fetches JWKS keys from the cached "
        "jwks_uri, matches kid, verifies RS256 signature, checks aud"
    )
    if actor == "agent":
        description += " + issuer + expiry. The sub claim identifies the Agent Identity as the caller."
    else:
        description += " = API A's app ID, checks issuer + expiry."
    return _step(
        label="Call API A",
        description=description,
        diagram_index=diagram_index,
        request={"method": "POST", "url": "http://localhost:8001/chain", "headers": {"authorization": "Bearer eyJ...access-token"}, "body": {"target_scope": downstream_scope, "target_url": downstream_url}},
        response={"status": 200, "headers": {"x-ms-request-id": "req-call-api-a-chain"}, "body": {"message": "Token accepted", "target_scope": downstream_scope}},
        tokens={"access_token": _token(access_token)},
    )


def _simulated_user_login_step(*, scope: str, diagram_index: int = 0) -> dict:
    authorize_url = f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/v2.0/authorize?client_id={FAKE_CLIENT_ID}&response_type=code&scope={scope}&state=state-value"
    return _step(
        label="User Login",
        description="Browser redirects to Entra ID /authorize endpoint. User authenticates and consents to the requested scopes. If the app is pre-authorized on the target API, Entra skips the consent prompt — the user only authenticates. Without pre-authorization, the user would see a dialog listing the requested permissions.",
        diagram_index=diagram_index,
        request={"method": "GET", "url": authorize_url, "headers": {}, "body": {"client_id": FAKE_CLIENT_ID, "response_type": "code", "scope": scope, "state": "state-value"}},
        response={"status": 302, "headers": {"location": "http://localhost:8000/auth/callback?code=authorization-code&state=state-value"}, "body": {"code": "authorization-code", "state": "state-value"}},
    )


def _auth_code_exchange_step(*, scope: str, access_token: str, diagram_index: int = 1) -> dict:
    id_token = make_fake_jwt(aud=FAKE_CLIENT_ID, delegated=True, scopes="openid profile")
    return _token_exchange_step(
        label="Auth Code Token Exchange",
        grant_type="authorization_code",
        body={"grant_type": "authorization_code", "code": "authorization-code", "client_id": FAKE_CLIENT_ID, "scope": scope},
        access_token=access_token,
        id_token=id_token,
        diagram_index=diagram_index,
        description="Client exchanges the authorization code for tokens by POSTing to the /token endpoint with client credentials. The /token endpoint URL comes from the cached OIDC discovery document." + _user_read_note_for_token(access_token),
    )


def _user_auth_prefix(*, scope: str, access_token: str) -> list[dict]:
    return [
        _simulated_user_login_step(scope=scope, diagram_index=0),
        _auth_code_exchange_step(scope=scope, access_token=access_token, diagram_index=1),
    ]


def _auth_code(scope: str) -> dict:
    aud, _label, _url = _resource_for_scope(scope)
    access_token = make_fake_jwt(aud=aud, delegated=True, scopes="access_as_user User.Read")
    return {
        "context": "Authorization Code flow: user sign-in returns a code; the client exchanges the code for tokens and calls the resource.",
        "steps": [
            *_user_auth_prefix(scope=scope, access_token=access_token),
            _resource_call_step(access_token=access_token, scope=scope, diagram_index=2),
        ],
    }


def _client_credentials(scope: str) -> dict:
    aud, _label, _url = _resource_for_scope(scope)
    token = make_fake_jwt(aud=aud, delegated=False, roles=["access_as_app"])
    return {
        "steps": [
            _oidc_step(),
            _token_exchange_step(
                label="Client Credentials Token",
                grant_type="client_credentials",
                body={"grant_type": "client_credentials", "client_id": FAKE_CLIENT_ID, "scope": scope, "client_assertion": "client-assertion"},
                access_token=token,
                diagram_index=0,
                description="App authenticates directly with client_id + client_secret. No user involvement. Returns an app-only access token.",
            ),
            _resource_call_step(access_token=token, scope=scope, diagram_index=1),
        ],
    }


def _client_credentials_chain(scope: str) -> dict:
    target_scope = scope[6:] if scope.startswith("chain:") else scope
    _target_aud, target_label, target_url = _resource_for_scope(target_scope)
    api_a_token = make_fake_jwt(aud=FAKE_API_A_ID, delegated=False, roles=["access_as_app"])
    downstream_token = make_fake_jwt(aud=_target_aud, delegated=False, roles=["access_as_app"])
    return {
        "steps": [
            _token_exchange_step(label="Client Credentials for API A", grant_type="client_credentials", body={"grant_type": "client_credentials", "scope": f"api://{FAKE_API_A_ID}/.default"}, access_token=api_a_token, diagram_index=0, description="Client app authenticates with client_id + client_secret to get an app-only token for API A. No user involvement."),
            _api_a_chain_call_step(access_token=api_a_token, downstream_scope=target_scope, downstream_url=target_url, actor="client", diagram_index=1),
            _step(label=f"API A Client Credentials for {target_label}", description=f"API A performs its own client_credentials grant to get a token for {target_label}. This is NOT OBO — there is no user identity. {target_label} will see API A as the caller (via appid/azp claim).", diagram_index=2, request={"method": "POST", "url": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/v2.0/token", "headers": {}, "body": {"grant_type": "client_credentials", "scope": target_scope}}, response={"status": 200, "headers": {}, "body": {"access_token": downstream_token}}, tokens={"access_token": _token(downstream_token)}),
            _api_a_downstream_call_step(access_token=downstream_token, scope=target_scope, diagram_index=3),
        ],
    }


def _obo(scope: str) -> dict:
    api_a_scope = f"api://{FAKE_API_A_ID}/access_as_user"
    user_token = make_fake_jwt(aud=FAKE_API_A_ID, delegated=True, scopes="access_as_user")
    downstream_token = make_fake_jwt(aud=_resource_for_scope(scope)[0], delegated=True, scopes="read User.Read")
    return {
        "steps": [
            *_user_auth_prefix(scope=f"openid profile {api_a_scope}", access_token=user_token),
            _resource_call_step(access_token=user_token, scope=api_a_scope, diagram_index=2),
            _step(label="OBO Token Exchange", description="API A exchanges the user's token for a downstream token. It authenticates as itself (client_id + client_secret) and presents the user's token as an assertion. Entra issues a new token where the audience switches to the downstream API, but the user's identity (sub/upn) is preserved. This only succeeds if both the user and API A have been granted permissions to the downstream API." + _user_read_note_for_token(downstream_token), diagram_index=3, request={"method": "POST", "url": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/v2.0/token", "headers": {}, "body": {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "requested_token_use": "on_behalf_of", "assertion": "eyJ...user-token", "scope": scope}}, response={"status": 200, "headers": {"x-ms-request-id": "req-obo"}, "body": {"access_token": downstream_token}}, tokens={"access_token": _token(downstream_token)}),
            _resource_call_step(access_token=downstream_token, scope=scope, diagram_index=4),
        ],
    }


def _agent_autonomous_chain(scope: str) -> dict:
    target_scope = scope[6:] if scope.startswith("chain:") else scope
    _target_aud, target_label, target_url = _resource_for_scope(target_scope)
    parent = make_fake_jwt(aud="api://AzureADTokenExchange", delegated=False, roles=["agent.parent"])
    api_a_token = make_fake_jwt(aud=FAKE_API_A_ID, delegated=False, roles=["agent.execute"], subject=FAKE_AGENT_ID)
    downstream_token = make_fake_jwt(aud=_target_aud, delegated=False, roles=["access_as_app"], subject=FAKE_AGENT_ID)
    return {
        "steps": [
            _token_exchange_step(label="Blueprint Parent Token", grant_type="client_credentials", body={"grant_type": "client_credentials", "client_id": FAKE_BLUEPRINT_ID, "scope": "api://AzureADTokenExchange/.default", "fmi_path": FAKE_AGENT_ID}, access_token=parent, diagram_index=0, description="Blueprint app authenticates with client_credentials + fmi_path to get a parent token. The fmi_path tells Entra which Agent Identity to scope to. The audience is api://AzureADTokenExchange."),
            _step(label="FMI Exchange for API A", description="Agent Identity exchanges the parent token (as client_assertion) for a downstream access token. The client_id is now the Agent Identity — the identity has \"switched\" from Blueprint to Agent. The resulting token's sub claim is the Agent Identity.", diagram_index=1, request={"method": "POST", "url": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/v2.0/token", "headers": {}, "body": {"grant_type": "client_credentials", "client_id": FAKE_AGENT_ID, "scope": f"api://{FAKE_API_A_ID}/.default"}}, response={"status": 200, "headers": {"x-ms-request-id": "req-agent-api-a"}, "body": {"access_token": api_a_token}}, tokens={"access_token": _token(api_a_token)}),
            _api_a_chain_call_step(access_token=api_a_token, downstream_scope=target_scope, downstream_url=target_url, actor="agent", diagram_index=2),
            _step(label=f"API A Client Credentials for {target_label}", description=f"API A performs its own client_credentials grant to get a token for {target_label}. This is NOT OBO — there is no user identity. {target_label} will see API A as the caller (via appid/azp claim).", diagram_index=3, request={"method": "POST", "url": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/v2.0/token", "headers": {}, "body": {"grant_type": "client_credentials", "scope": target_scope}}, response={"status": 200, "headers": {}, "body": {"access_token": downstream_token}}, tokens={"access_token": _token(downstream_token)}),
            _api_a_downstream_call_step(access_token=downstream_token, scope=target_scope, diagram_index=4),
        ],
    }


def _agent_autonomous(scope: str) -> dict:
    parent = make_fake_jwt(aud="api://AzureADTokenExchange", delegated=False, roles=["agent.parent"])
    agent = make_fake_jwt(aud=_resource_for_scope(scope)[0], delegated=False, roles=["agent.execute"], subject=FAKE_AGENT_ID)
    return {
        "steps": [
            _token_exchange_step(label="Blueprint Parent Token", grant_type="client_credentials", body={"grant_type": "client_credentials", "client_id": FAKE_BLUEPRINT_ID, "scope": "api://AzureADTokenExchange/.default", "fmi_path": FAKE_AGENT_ID}, access_token=parent, diagram_index=0, description="Blueprint app authenticates with client_credentials + fmi_path to get a parent token. The fmi_path tells Entra which Agent Identity to scope to. The audience is api://AzureADTokenExchange."),
            _step(label="Agent Identity Token Exchange", description="Agent Identity exchanges the parent token (as client_assertion) for a downstream access token. The client_id is now the Agent Identity — the identity has \"switched\" from Blueprint to Agent. The resulting token's sub claim is the Agent Identity.", diagram_index=1, request={"method": "POST", "url": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/v2.0/token", "headers": {}, "body": {"grant_type": "client_credentials", "client_id": FAKE_AGENT_ID, "scope": scope}}, response={"status": 200, "headers": {"x-ms-request-id": "req-agent"}, "body": {"access_token": agent}}, tokens={"access_token": _token(agent)}),
            _resource_call_step(access_token=agent, scope=scope, diagram_index=2),
        ],
    }


def _agent_obo(scope: str, chain_target: str = "") -> dict:
    if chain_target and chain_target != "api_a":
        raise ValueError(f"Unknown chain target: {chain_target}")
    target_scope = scope[10:] if scope.startswith("via_api_a:") else scope
    blueprint_scope = f"api://{FAKE_BLUEPRINT_ID}/access_as_user"
    blueprint_user = make_fake_jwt(aud=FAKE_BLUEPRINT_ID, delegated=True, scopes="access_as_user")
    parent = make_fake_jwt(aud="api://AzureADTokenExchange", delegated=False, roles=["agent.parent"])
    target_aud = _resource_for_scope(target_scope)[0]
    agent_token = make_fake_jwt(aud=target_aud, delegated=True, scopes="read User.Read", subject=FAKE_USER_SUB)
    is_chained = chain_target == "api_a" or scope.startswith("via_api_a:")
    agent_obo_description = (
        "Agent Identity exchanges the parent token + user token via OBO to get a token scoped to API A. "
        "The client_assertion is the parent token (proving agent identity), the assertion is the user token "
        "(proving user context)."
        if is_chained
        else "Agent Identity exchanges the parent token + user token via OBO to get a token scoped directly to the target resource. The client_assertion is the parent token (proving agent identity), the assertion is the user token (proving user context). No intermediate API hop is needed."
    )
    steps = [
        *_user_auth_prefix(scope=f"openid profile {blueprint_scope}", access_token=blueprint_user),
        _token_exchange_step(label="Blueprint Parent Token", grant_type="client_credentials", body={"grant_type": "client_credentials", "client_id": FAKE_BLUEPRINT_ID, "scope": "api://AzureADTokenExchange/.default", "fmi_path": FAKE_AGENT_ID}, access_token=parent, diagram_index=2, description="Blueprint app authenticates with client_credentials + fmi_path to get a parent token. The fmi_path tells Entra which Agent Identity to scope to. The audience is api://AzureADTokenExchange."),
        _step(label="Agent OBO Exchange", description=agent_obo_description, diagram_index=3, request={"method": "POST", "url": "http://localhost:8003/agent/exchange", "headers": {"authorization": "Bearer eyJ...blueprint-user"}, "body": {"scope": target_scope, "chain_target": chain_target}}, response={"status": 200, "headers": {"x-ms-request-id": "req-agent-obo"}, "body": {"access_token": agent_token}}, tokens={"access_token": _token(agent_token)}),
    ]
    if is_chained:
        api_a_token = make_fake_jwt(aud=FAKE_API_A_ID, delegated=True, scopes="access_as_user")
        downstream_token = make_fake_jwt(aud=target_aud, delegated=True, scopes="read User.Read", subject=FAKE_USER_SUB)
        steps[-1]["response"]["body"]["access_token"] = api_a_token
        steps[-1]["tokens"] = {"access_token": _token(api_a_token)}
        steps.append(_resource_call_step(access_token=api_a_token, scope=f"api://{FAKE_API_A_ID}/access_as_user", diagram_index=4))
        steps.append(_step(label="API A OBO to Downstream", description="API A exchanges the agent's token for a downstream token. It authenticates as itself (client_id + client_secret) and presents the agent's API A token as an assertion. Entra issues a new token where the audience switches to the downstream API, but the user's identity is preserved." + _user_read_note_for_token(downstream_token), diagram_index=5, request={"method": "POST", "url": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/v2.0/token", "headers": {}, "body": {"requested_token_use": "on_behalf_of", "scope": target_scope}}, response={"status": 200, "headers": {}, "body": {"access_token": downstream_token}}, tokens={"access_token": _token(downstream_token)}))
        steps.append(_resource_call_step(access_token=downstream_token, scope=target_scope, diagram_index=6))
    else:
        steps.append(_resource_call_step(access_token=agent_token, scope=target_scope, diagram_index=4))
    return {"steps": steps}


def execute(*, flow_type: str, scope: str = "", chain_target: str = "") -> dict:
    if flow_type == "auth_code":
        return deepcopy(_auth_code(scope))
    if flow_type == "client_credentials":
        return deepcopy(_client_credentials(scope))
    if flow_type == "client_credentials_chain":
        return deepcopy(_client_credentials_chain(scope))
    if flow_type == "obo":
        return deepcopy(_obo(scope))
    if flow_type == "agent_id_autonomous":
        return deepcopy(_agent_autonomous(scope))
    if flow_type == "agent_id_autonomous_chain":
        return deepcopy(_agent_autonomous_chain(scope))
    if flow_type == "agent_id_obo":
        return deepcopy(_agent_obo(scope, chain_target))
    raise ValueError(f"Unknown flow type: {flow_type}")


def session_status() -> dict:
    return {
        "has_access_token": True,
        "has_id_token": True,
        "has_refresh_token": True,
        "token_expired": False,
        "last_flow": "simulation",
        "simulation_mode": True,
    }


def me() -> dict:
    raw_id = make_fake_jwt(aud=FAKE_CLIENT_ID, delegated=True, scopes="openid profile")
    return {
        "signed_in": True,
        "profile": {
            "name": "Adele Vance",
            "preferred_username": "adele.vance@example.test",
            "oid": FAKE_USER_OID,
        },
        "id_token": decode_jwt(raw_id),
        "id_token_raw": raw_id,
    }


def silent_acquire(*, scope: str = "", flow_type: str = "auth_code") -> dict:
    aud, _label, _url = _resource_for_scope(scope)
    raw = make_fake_jwt(aud=aud, delegated=flow_type != "client_credentials", scopes="access_as_user User.Read")
    result = {
        "request": {"method": "POST", "url": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/v2.0/token", "headers": {}, "body": {"grant_type": "refresh_token", "scope": scope}},
        "response": {"status": 200, "headers": {"x-ms-request-id": "sim-silent"}, "body": {"access_token": raw, "refresh_token": FAKE_REFRESH_TOKEN}},
        "tokens": {"access_token": _token(raw), "refresh_token": {"raw": FAKE_REFRESH_TOKEN, "note": "Refresh tokens are opaque to clients"}},
    }
    return {"result": result, "access_token": raw}


def signin_logs(after: str = "") -> list[dict]:
    return [
        {
            "id": "signin-1",
            "simulated": True,
            "createdDateTime": "2026-05-09T00:00:00Z",
            "userDisplayName": "Adele Vance",
            "userPrincipalName": "adele.vance@example.test",
            "userId": FAKE_USER_OID,
            "appDisplayName": "Client App",
            "appId": FAKE_CLIENT_ID,
            "resourceDisplayName": "API A",
            "resourceId": FAKE_API_A_ID,
            "tenantId": FAKE_TENANT_ID,
            "scopes": "access_as_user",
            "status": {"errorCode": 0, "failureReason": "", "additionalDetails": "Success"},
            "conditionalAccessStatus": "notApplied",
            "ipAddress": "203.0.113.10",
            "clientAppUsed": "Browser",
        }
    ]
