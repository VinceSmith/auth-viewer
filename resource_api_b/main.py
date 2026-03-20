"""Resource API B — downstream API in the OBO chain."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

import httpx
from fastapi import FastAPI, Header, HTTPException
from jose import jwt, JWTError

app = FastAPI(title="Auth Viewer — API B")

API_B_APP_ID = os.getenv("API_B_APP_ID", "")
TENANT_ID = os.getenv("TENANT_ID", "")
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

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
            audience=API_B_APP_ID,
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


@app.get("/data")
async def get_data(authorization: str = Header("")):
    """Return sample data — the downstream resource in the OBO chain."""
    token = extract_bearer(authorization)
    claims = await validate_token(token)
    return {
        "message": "Hello from API B (downstream)",
        "data": {
            "items": [
                {"id": 1, "name": "Sample item 1"},
                {"id": 2, "name": "Sample item 2"},
                {"id": 3, "name": "Sample item 3"},
            ],
        },
        "claims": claims,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "api-b"}
