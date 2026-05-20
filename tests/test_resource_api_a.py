from unittest.mock import AsyncMock

import pytest

from tests.conftest import make_mock_response


@pytest.mark.asyncio
async def test_cc_chain_prefers_api_a_client_secret(monkeypatch):
    from resource_api_a import main as api_a

    monkeypatch.setattr(api_a, "API_A_APP_ID", "api-a-client-id")
    monkeypatch.setattr(api_a, "API_A_CLIENT_SECRET", "api-a-secret", raising=False)
    monkeypatch.setattr(api_a, "TENANT_ID", "tenant-id")
    monkeypatch.setattr(api_a, "_validate", AsyncMock(return_value={"aud": "api-a-client-id"}))
    get_assertion = AsyncMock(side_effect=AssertionError("should not request a federated assertion"))
    monkeypatch.setattr(api_a, "get_client_assertion", get_assertion)

    token_response = make_mock_response(200, {"access_token": "api-b-token"})
    downstream_response = make_mock_response(200, {"message": "ok"})
    mock_client = AsyncMock()
    mock_client.post.return_value = token_response
    mock_client.get.return_value = downstream_response
    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_client
    monkeypatch.setattr(api_a.httpx, "AsyncClient", lambda: mock_context)

    result = await api_a.cc_chain(
        authorization="Bearer api-a-token",
        target_scope="api://api-b/.default",
        target_url="http://api-b/data",
    )

    assert result["cc_request"]["client_secret"] == "[client_secret]"
    assert "client_assertion" not in result["cc_request"]
    post_body = mock_client.post.call_args.kwargs["data"]
    assert post_body["client_secret"] == "api-a-secret"
    assert "client_assertion" not in post_body
    get_assertion.assert_not_called()


@pytest.mark.asyncio
async def test_obo_chain_prefers_api_a_client_secret(monkeypatch):
    from resource_api_a import main as api_a

    monkeypatch.setattr(api_a, "API_A_APP_ID", "api-a-client-id")
    monkeypatch.setattr(api_a, "API_A_CLIENT_SECRET", "api-a-secret", raising=False)
    monkeypatch.setattr(api_a, "API_B_SCOPE", "api://api-b/read")
    monkeypatch.setattr(api_a, "TENANT_ID", "tenant-id")
    monkeypatch.setattr(api_a, "_validate", AsyncMock(return_value={"sub": "user-id"}))
    get_assertion = AsyncMock(side_effect=AssertionError("should not request a federated assertion"))
    monkeypatch.setattr(api_a, "get_client_assertion", get_assertion)

    token_response = make_mock_response(200, {"access_token": "api-b-token"})
    downstream_response = make_mock_response(200, {"message": "ok"})
    mock_client = AsyncMock()
    mock_client.post.return_value = token_response
    mock_client.get.return_value = downstream_response
    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_client
    monkeypatch.setattr(api_a.httpx, "AsyncClient", lambda: mock_context)

    result = await api_a.obo_chain(authorization="Bearer user-token")

    assert result["obo_request"]["client_secret"] == "[client_secret]"
    assert "client_assertion" not in result["obo_request"]
    post_body = mock_client.post.call_args.kwargs["data"]
    assert post_body["client_secret"] == "api-a-secret"
    assert "client_assertion" not in post_body
    get_assertion.assert_not_called()