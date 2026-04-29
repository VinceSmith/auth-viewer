"""Credential helper — produces client assertions via DefaultAzureCredential.

In Azure (Container Apps): uses ManagedIdentityCredential automatically.
In local dev: uses AzureCLICredential (from `az login`).

The returned JWT is used as `client_assertion` in OAuth token requests,
replacing `client_secret` entirely.
"""

from azure.identity.aio import DefaultAzureCredential

_credential: DefaultAzureCredential | None = None

_FIC_AUDIENCE = "api://AzureADTokenExchange/.default"


def _ensure_credential() -> DefaultAzureCredential:
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential


async def get_client_assertion() -> str:
    """Get a client assertion JWT for use in token requests.

    The FIC on the target app registration must trust the current identity.
    """
    credential = _ensure_credential()
    token = await credential.get_token(_FIC_AUDIENCE)
    return token.token


async def close_credential() -> None:
    """Close the underlying credential (call on app shutdown)."""
    global _credential
    if _credential is not None:
        await _credential.close()
        _credential = None
