"""Resource API B — downstream API in the OBO chain."""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# Allow importing from the project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Header

from resource_apis.auth_utils import validate_token, extract_bearer

app = FastAPI(title="Auth Viewer — API B")

API_B_APP_ID = os.getenv("API_B_APP_ID", "")
TENANT_ID = os.getenv("TENANT_ID", "")
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
VALID_AUDIENCES = {API_B_APP_ID, f"api://{API_B_APP_ID}"}


async def _validate(token: str) -> dict:
    return await validate_token(
        token,
        jwks_url=JWKS_URL,
        valid_audiences=VALID_AUDIENCES,
        issuer=ISSUER,
    )


@app.get("/data")
async def get_data(authorization: str = Header("")):
    """Return sample data — the downstream resource in the OBO chain."""
    token = extract_bearer(authorization)
    claims = await _validate(token)
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

