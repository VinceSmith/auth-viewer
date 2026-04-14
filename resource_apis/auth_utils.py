"""Shared auth helpers for Resource API A and Resource API B.

Extracted to eliminate the copy-paste between both API services.
"""

import os
import time
import logging

import httpx
from fastapi import HTTPException
from jose import jwt, JWTError

_logger = logging.getLogger(__name__)

# JWKS cache entry: {"keys": [...], "fetched_at": float}
_jwks_cache: dict = {}
_JWKS_TTL_SECONDS = 3600  # 1 hour


async def get_jwks(jwks_url: str, *, force_refresh: bool = False) -> dict:
    """Fetch and cache JWKS keys with a 1-hour TTL.

    Args:
        jwks_url: The full JWKS endpoint URL.
        force_refresh: Skip cache and re-fetch unconditionally.
    """
    now = time.monotonic()
    cached = _jwks_cache.get(jwks_url)
    if not force_refresh and cached:
        if now - cached["fetched_at"] < _JWKS_TTL_SECONDS:
            return cached["keys"]

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(jwks_url, timeout=10)
        keys = resp.json()
        _jwks_cache[jwks_url] = {"keys": keys, "fetched_at": now}
        return keys
    except Exception as e:
        _logger.warning("JWKS fetch failed (%s): %s", jwks_url, e)
        # Return stale cache if available, otherwise raise
        if cached:
            _logger.warning("Returning stale JWKS cache due to fetch failure")
            return cached["keys"]
        raise HTTPException(status_code=503, detail=f"Could not fetch JWKS: {e}")


def _find_key(jwks: dict, kid: str | None) -> dict | None:
    """Find a JWK entry by kid."""
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    return None


async def validate_token(
    token: str,
    *,
    jwks_url: str,
    valid_audiences: set[str],
    issuer: str,
) -> dict:
    """Validate a Bearer JWT and return its claims.

    Performs:
    - kid lookup in JWKS (refreshes cache once on miss before returning 401)
    - RS256 signature verification
    - Expiry check
    - Audience validation (accepts any of valid_audiences)
    - Issuer validation

    Raises:
        HTTPException(401) on any validation failure.
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token header: {e}")

    kid = unverified_header.get("kid")

    jwks = await get_jwks(jwks_url)
    rsa_key = _find_key(jwks, kid)

    # Key miss: Entra may have rotated keys — refresh cache once and retry
    if rsa_key is None:
        _logger.info("kid %r not found in JWKS cache — refreshing", kid)
        jwks = await get_jwks(jwks_url, force_refresh=True)
        rsa_key = _find_key(jwks, kid)

    if rsa_key is None:
        raise HTTPException(status_code=401, detail=f"Signing key not found: kid={kid!r}")

    try:
        # python-jose doesn't support a set for audience, so skip audience
        # check here and validate manually below.
        claims = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=None,
            issuer=issuer,
            options={"verify_exp": True, "verify_aud": False},
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {e}")

    token_aud = claims.get("aud", "")
    if token_aud not in valid_audiences:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid audience: got {token_aud!r}, expected one of {sorted(valid_audiences)!r}",
        )

    return claims


def extract_bearer(authorization: str) -> str:
    """Extract the Bearer token from an Authorization header value.

    Raises:
        HTTPException(401) if the header is missing or malformed.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    return authorization[7:]
