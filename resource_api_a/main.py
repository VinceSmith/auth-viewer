"""Resource API A — middle-tier API for OBO chain."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

import httpx
from fastapi import FastAPI, Header, HTTPException
from jose import jwt, JWTError

app = FastAPI(title="Auth Viewer — API A")

API_A_APP_ID = os.getenv("API_A_APP_ID", "")
API_A_CLIENT_SECRET = os.getenv("API_A_CLIENT_SECRET", "")
API_B_SCOPE = os.getenv("API_B_SCOPE", "")
API_B_BASE_URL = os.getenv("API_B_BASE_URL", "http://localhost:8002")
TENANT_ID = os.getenv("TENANT_ID", "")
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

# Cache JWKS keys
_jwks_client = None


async def get_jwks():
    global _jwks_client
    if _jwks_client is None:
        async with httpx.AsyncClient() as client:
            resp = await client.get(JWKS_URL)
            _jwks_client = resp.json()
    return _jwks_client


async def validate_token(token: str) -> dict:
    """Validate a bearer token and return claims."""
    try:
        jwks = await get_jwks()
        # Decode header to find the signing key
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        rsa_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = key
                break

        if not rsa_key:
            raise HTTPException(status_code=401, detail="Signing key not found")

        claims = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=API_A_APP_ID,
            issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
            options={"verify_exp": True},
        )
        return claims
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {e}")


def extract_bearer(authorization: str) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    return authorization[7:]


@app.get("/me")
async def get_me(authorization: str = Header("")):
    """Return the token claims — demonstrates a simple protected endpoint."""
    token = extract_bearer(authorization)
    claims = await validate_token(token)
    return {"message": "Hello from API A", "claims": claims}


@app.post("/obo")
async def obo_chain(authorization: str = Header("")):
    """Perform OBO exchange and call API B on behalf of the user."""
    token = extract_bearer(authorization)
    claims = await validate_token(token)

    # OBO exchange: user's token for API A → token for API B
    token_endpoint = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    obo_params = {
        "client_id": API_A_APP_ID,
        "client_secret": API_A_CLIENT_SECRET,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": token,
        "requested_token_use": "on_behalf_of",
        "scope": API_B_SCOPE,
    }

    async with httpx.AsyncClient() as client:
        obo_resp = await client.post(
            token_endpoint,
            data=obo_params,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        obo_result = obo_resp.json()

    if "access_token" not in obo_result:
        return {
            "error": "OBO exchange failed",
            "obo_request": {k: v for k, v in obo_params.items() if k != "client_secret"},
            "obo_response": obo_result,
        }

    # Call API B with the OBO token
    api_b_token = obo_result["access_token"]
    async with httpx.AsyncClient() as client:
        api_b_resp = await client.get(
            f"{API_B_BASE_URL}/data",
            headers={"Authorization": f"Bearer {api_b_token}"},
        )
        api_b_result = api_b_resp.json()

    return {
        "message": "OBO chain complete",
        "original_claims": claims,
        "obo_request": {k: v for k, v in obo_params.items() if k != "client_secret"},
        "obo_token_response": {k: v for k, v in obo_result.items() if k != "access_token"},
        "api_b_response": api_b_result,
    }


@app.post("/chain")
async def cc_chain(authorization: str = Header(""), target_scope: str = "", target_url: str = ""):
    """Receive an app-only token, then do own client_credentials grant for a downstream resource."""
    token = extract_bearer(authorization)
    claims = await validate_token(token)

    # Determine downstream scope and URL (default to API B)
    downstream_scope = target_scope or (API_B_SCOPE.rsplit("/", 1)[0] + "/.default" if "/" in API_B_SCOPE else API_B_SCOPE)
    downstream_url = target_url or f"{API_B_BASE_URL}/data"

    # API A does its own client_credentials grant for the downstream resource
    token_endpoint = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    cc_params = {
        "client_id": API_A_APP_ID,
        "client_secret": API_A_CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": downstream_scope,
    }

    async with httpx.AsyncClient() as client:
        cc_resp = await client.post(
            token_endpoint,
            data=cc_params,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        cc_result = cc_resp.json()

    if "access_token" not in cc_result:
        return {
            "error": "Client credentials grant for downstream failed",
            "cc_request": {k: v for k, v in cc_params.items() if k != "client_secret"},
            "cc_response": cc_result,
        }

    # Call downstream with API A's own app-only token
    downstream_token = cc_result["access_token"]
    async with httpx.AsyncClient() as client:
        downstream_resp = await client.get(
            downstream_url,
            headers={"Authorization": f"Bearer {downstream_token}"},
        )
        try:
            downstream_result = downstream_resp.json()
        except Exception:
            downstream_result = {"raw": downstream_resp.text}

    return {
        "message": "Hello from API A",
        "original_claims": claims,
        "cc_request": {k: v for k, v in cc_params.items() if k != "client_secret"},
        "cc_token_response": {k: v for k, v in cc_result.items() if k != "access_token"},
        "downstream_url": downstream_url,
        "downstream_response": downstream_result,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "api-a"}
