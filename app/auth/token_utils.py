import base64
import json
from datetime import datetime, timezone


def decode_jwt(token: str) -> dict:
    """Decode a JWT token into header and payload (no signature verification)."""
    parts = token.split(".")
    if len(parts) < 2:
        return {"error": "Not a valid JWT (expected at least 2 dot-separated parts)"}

    header = _decode_part(parts[0])
    payload = _decode_part(parts[1])

    # Add human-readable timestamps for common time claims
    for claim in ("exp", "iat", "nbf"):
        if claim in payload and isinstance(payload[claim], (int, float)):
            payload[f"_{claim}_utc"] = datetime.fromtimestamp(
                payload[claim], tz=timezone.utc
            ).isoformat()

    return {"header": header, "payload": payload}


def _decode_part(part: str) -> dict:
    """Base64url-decode a JWT part and parse as JSON."""
    # Add padding
    padding = 4 - len(part) % 4
    if padding != 4:
        part += "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)
    except Exception as e:
        return {"decode_error": str(e)}


# Keys to strip from request/response bodies in the step summary.
_HIDDEN_KEYS: set[str] = set()

# Long-lived secrets to mask (replaced with placeholder like "[client_secret]")
_MASKED_KEYS = {"client_secret"}


def format_token_response(
    *, request_method: str, request_url: str, request_headers: dict,
    request_body: dict | str, response_status: int, response_headers: dict,
    response_body: dict,
) -> dict:
    """Package a token exchange request/response for the UI."""
    if isinstance(request_body, dict):
        display_body = {}
        for k, v in request_body.items():
            if k in _HIDDEN_KEYS:
                continue
            if k in _MASKED_KEYS:
                display_body[k] = f"[{k}]"
            else:
                display_body[k] = v
    else:
        display_body = request_body
    result = {
        "request": {
            "method": request_method,
            "url": request_url,
            "headers": _sanitize_headers(request_headers),
            "body": display_body,
        },
        "response": {
            "status": response_status,
            "headers": dict(response_headers),
            "body": response_body,
        },
        "tokens": {},
    }

    # Decode any tokens in the response
    for token_key in ("access_token", "id_token", "refresh_token"):
        if token_key in response_body:
            raw = response_body[token_key]
            if token_key == "refresh_token":
                # Refresh tokens are opaque — just note their presence
                result["tokens"][token_key] = {
                    "raw": raw[:20] + "..." if len(raw) > 20 else raw,
                    "note": "Refresh tokens are opaque to clients",
                }
            else:
                decoded = decode_jwt(raw)
                result["tokens"][token_key] = {
                    "raw": raw,
                    **decoded,
                }

    return result


def _sanitize_headers(headers: dict) -> dict:
    """Remove or mask sensitive headers for display."""
    sanitized = {}
    for k, v in headers.items():
        if k.lower() in ("authorization",):
            sanitized[k] = v[:20] + "..." if len(v) > 20 else v
        else:
            sanitized[k] = v
    return sanitized
