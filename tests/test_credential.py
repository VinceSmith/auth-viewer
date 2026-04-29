"""Tests for the credential helper module."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock


@pytest.mark.asyncio
async def test_get_client_assertion_returns_token():
    """get_client_assertion should return a token string from DefaultAzureCredential."""
    import app.auth.credential as cred_mod

    mock_credential = AsyncMock()
    mock_credential.get_token.return_value = MagicMock(token="fake-assertion-jwt")

    with patch.object(cred_mod, "_credential", mock_credential):
        result = await cred_mod.get_client_assertion()

    assert result == "fake-assertion-jwt"
    mock_credential.get_token.assert_awaited_once_with("api://AzureADTokenExchange/.default")


@pytest.mark.asyncio
async def test_get_client_assertion_reuses_credential():
    """Multiple calls should reuse the same DefaultAzureCredential instance."""
    import app.auth.credential as cred_mod

    mock_credential = AsyncMock()
    mock_credential.get_token.return_value = MagicMock(token="fake-assertion-jwt")

    with patch.object(cred_mod, "_credential", mock_credential):
        await cred_mod.get_client_assertion()
        await cred_mod.get_client_assertion()

    assert mock_credential.get_token.await_count == 2


@pytest.mark.asyncio
async def test_close_credential():
    """close_credential should close the underlying credential and reset state."""
    import app.auth.credential as cred_mod

    mock_credential = AsyncMock()
    cred_mod._credential = mock_credential

    await cred_mod.close_credential()

    mock_credential.close.assert_awaited_once()
    assert cred_mod._credential is None


@pytest.mark.asyncio
async def test_close_credential_when_none():
    """close_credential should be a no-op if no credential exists."""
    import app.auth.credential as cred_mod
    cred_mod._credential = None

    await cred_mod.close_credential()  # Should not raise
    assert cred_mod._credential is None
