<# 
    register_apps.ps1 — Register all Entra app registrations for auth-viewer
    
    Prerequisites:
    - Azure CLI installed and logged in (az login)
    - Permissions to create app registrations in your tenant
    
    Usage:
    .\scripts\register_apps.ps1
    
    This script will:
    1. Register auth-viewer-client (confidential client)
    2. Register auth-viewer-api-a (middle tier, exposes scope)
    3. Register auth-viewer-api-b (downstream, exposes scope)
    4. Configure permissions and pre-authorizations
    5. Generate .env file with all required values
#>

param(
    [string]$TenantId = "",
    [string]$OutputEnvFile = ".env"
)

$ErrorActionPreference = "Stop"

# Get tenant ID if not provided
if (-not $TenantId) {
    $TenantId = (az account show --query tenantId -o tsv)
    Write-Host "Using tenant: $TenantId" -ForegroundColor Cyan
}

Write-Host "`n=== Registering auth-viewer-api-b (downstream API) ===" -ForegroundColor Yellow

# API B — downstream resource
$apiBName = "auth-viewer-api-b"
$apiBResult = az ad app create `
    --display-name $apiBName `
    --sign-in-audience AzureADMyOrg `
    --query "{appId: appId, id: id}" `
    -o json | ConvertFrom-Json

$apiBAppId = $apiBResult.appId
$apiBObjectId = $apiBResult.id
Write-Host "API B App ID: $apiBAppId"

# Set identifier URI
az ad app update --id $apiBObjectId --identifier-uris "api://$apiBAppId"

# Expose a scope on API B (use Graph REST API — az ad app update --set api= has schema bugs)
$apiBScopeId = [guid]::NewGuid().ToString()
$bodyFile = "$env:TEMP\auth-viewer-api-b.json"
@"
{
  "api": {
    "requestedAccessTokenVersion": 2,
    "oauth2PermissionScopes": [
      {
        "id": "$apiBScopeId",
        "adminConsentDescription": "Allow reading data from API B",
        "adminConsentDisplayName": "Read API B data",
        "isEnabled": true,
        "type": "Admin",
        "value": "read"
      }
    ]
  }
}
"@ | Set-Content $bodyFile -Encoding UTF8
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$apiBObjectId" --headers "Content-Type=application/json" --body "@$bodyFile"

# Create service principal for API B
az ad sp create --id $apiBAppId 2>$null
Write-Host "API B scope: api://$apiBAppId/read" -ForegroundColor Green


Write-Host "`n=== Registering auth-viewer-api-a (middle tier API) ===" -ForegroundColor Yellow

# API A — middle tier
$apiAName = "auth-viewer-api-a"
$apiAResult = az ad app create `
    --display-name $apiAName `
    --sign-in-audience AzureADMyOrg `
    --query "{appId: appId, id: id}" `
    -o json | ConvertFrom-Json

$apiAAppId = $apiAResult.appId
$apiAObjectId = $apiAResult.id
Write-Host "API A App ID: $apiAAppId"

# Set identifier URI
az ad app update --id $apiAObjectId --identifier-uris "api://$apiAAppId"

# Expose a scope on API A (use Graph REST API)
$apiAScopeId = [guid]::NewGuid().ToString()
$bodyFile = "$env:TEMP\auth-viewer-api-a.json"
@"
{
  "api": {
    "requestedAccessTokenVersion": 2,
    "oauth2PermissionScopes": [
      {
        "id": "$apiAScopeId",
        "adminConsentDescription": "Access API A as a user",
        "adminConsentDisplayName": "Access as user",
        "isEnabled": true,
        "type": "Admin",
        "value": "access_as_user"
      }
    ]
  }
}
"@ | Set-Content $bodyFile -Encoding UTF8
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$apiAObjectId" --headers "Content-Type=application/json" --body "@$bodyFile"

# Create service principal for API A
az ad sp create --id $apiAAppId 2>$null

# Create client secret for API A (needed for OBO)
$apiASecret = (az ad app credential reset --id $apiAObjectId --display-name "auth-viewer-obo" --query password -o tsv)
Write-Host "API A scope: api://$apiAAppId/access_as_user" -ForegroundColor Green

# Set API B delegated permission on API A idempotently (for OBO chain)
$bodyFile = "$env:TEMP\auth-viewer-apia-perms.json"
@"
{
  "requiredResourceAccess": [
    {
      "resourceAppId": "$apiBAppId",
      "resourceAccess": [{"id": "$apiBScopeId", "type": "Scope"}]
    },
    {
      "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceAccess": [{"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"}]
    }
  ]
}
"@ | Set-Content $bodyFile -Encoding UTF8
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$apiAObjectId" --headers "Content-Type=application/json" --body "@$bodyFile"
Write-Host "Set API B + Graph User.Read delegated permissions on API A (idempotent)" -ForegroundColor Green


Write-Host "`n=== Registering auth-viewer-client (confidential client) ===" -ForegroundColor Yellow

# Client app
$clientName = "auth-viewer-client"
$redirectUri = "http://localhost:8000/auth/callback"

$clientResult = az ad app create `
    --display-name $clientName `
    --sign-in-audience AzureADMyOrg `
    --web-redirect-uris $redirectUri `
    --query "{appId: appId, id: id}" `
    -o json | ConvertFrom-Json

$clientAppId = $clientResult.appId
$clientObjectId = $clientResult.id
Write-Host "Client App ID: $clientAppId"

# Create client secret
$clientSecret = (az ad app credential reset --id $clientObjectId --display-name "auth-viewer-secret" --query password -o tsv)

# Create service principal for client
az ad sp create --id $clientAppId 2>$null

# Enable public client flows (for PKCE without client_secret)
$bodyFile = "$env:TEMP\auth-viewer-client-public.json"
@"
{"isFallbackPublicClient": true}
"@ | Set-Content $bodyFile -Encoding UTF8
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$clientObjectId" --headers "Content-Type=application/json" --body "@$bodyFile"
Write-Host "Enabled isFallbackPublicClient for PKCE" -ForegroundColor Green

# Set permissions idempotently via Graph API PATCH (avoids orphaned scope IDs on re-run)
$bodyFile = "$env:TEMP\auth-viewer-client-perms.json"
@"
{
  "requiredResourceAccess": [
    {
      "resourceAppId": "$apiAAppId",
      "resourceAccess": [{"id": "$apiAScopeId", "type": "Scope"}]
    },
    {
      "resourceAppId": "$apiBAppId",
      "resourceAccess": [{"id": "$apiBScopeId", "type": "Scope"}]
    },
    {
      "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceAccess": [
        {"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"},
        {"id": "b0afded3-3588-46d8-8b3d-9842eff778da", "type": "Role"}
      ]
    }
  ]
}
"@ | Set-Content $bodyFile -Encoding UTF8
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$clientObjectId" --headers "Content-Type=application/json" --body "@$bodyFile"
Write-Host "Set API A + API B + Graph User.Read + AuditLog.Read.All permissions on client (idempotent)" -ForegroundColor Green


Write-Host "`n=== Configuring pre-authorizations ===" -ForegroundColor Yellow

# Pre-authorize client on API A (use Graph REST API)
$bodyFile = "$env:TEMP\auth-viewer-preauth-a.json"
@"
{
  "api": {
    "requestedAccessTokenVersion": 2,
    "oauth2PermissionScopes": [
      {
        "id": "$apiAScopeId",
        "adminConsentDescription": "Access API A as a user",
        "adminConsentDisplayName": "Access as user",
        "isEnabled": true,
        "type": "Admin",
        "value": "access_as_user"
      }
    ],
    "preAuthorizedApplications": [
      {
        "appId": "$clientAppId",
        "delegatedPermissionIds": ["$apiAScopeId"]
      }
    ]
  }
}
"@ | Set-Content $bodyFile -Encoding UTF8
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$apiAObjectId" --headers "Content-Type=application/json" --body "@$bodyFile"
Write-Host "Pre-authorized client on API A" -ForegroundColor Green

# Pre-authorize API A on API B (use Graph REST API)
$bodyFile = "$env:TEMP\auth-viewer-preauth-b.json"
@"
{
  "api": {
    "requestedAccessTokenVersion": 2,
    "oauth2PermissionScopes": [
      {
        "id": "$apiBScopeId",
        "adminConsentDescription": "Allow reading data from API B",
        "adminConsentDisplayName": "Read API B data",
        "isEnabled": true,
        "type": "Admin",
        "value": "read"
      }
    ],
    "preAuthorizedApplications": [
      {
        "appId": "$apiAAppId",
        "delegatedPermissionIds": ["$apiBScopeId"]
      }
    ]
  }
}
"@ | Set-Content $bodyFile -Encoding UTF8
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$apiBObjectId" --headers "Content-Type=application/json" --body "@$bodyFile"
Write-Host "Pre-authorized API A on API B" -ForegroundColor Green


Write-Host "`n=== Granting admin consent ===" -ForegroundColor Yellow

# Grant delegated permission consent (oauth2PermissionGrants)
az ad app permission grant --id $clientAppId --api $apiAAppId --scope "access_as_user" 2>$null
az ad app permission grant --id $apiAAppId --api $apiBAppId --scope "read" 2>$null
az ad app permission grant --id $apiAAppId --api 00000003-0000-0000-c000-000000000000 --scope "User.Read openid profile" 2>$null
az ad app permission admin-consent --id $clientObjectId 2>$null
az ad app permission admin-consent --id $apiAObjectId 2>$null
Write-Host "Admin consent granted" -ForegroundColor Green


Write-Host "`n=== Generating $OutputEnvFile ===" -ForegroundColor Yellow

$envContent = @"
# Generated by register_apps.ps1 on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

# Entra ID
TENANT_ID=$TenantId
REDIRECT_URI=$redirectUri

# Client App (auth-viewer-client)
CLIENT_ID=$clientAppId
CLIENT_SECRET=$clientSecret

# Resource API A (auth-viewer-api-a)
API_A_APP_ID=$apiAAppId
API_A_CLIENT_SECRET=$apiASecret
API_A_SCOPE=api://$apiAAppId/access_as_user
API_A_BASE_URL=http://localhost:8001

# Resource API B (auth-viewer-api-b)
API_B_APP_ID=$apiBAppId
API_B_SCOPE=api://$apiBAppId/read
API_B_BASE_URL=http://localhost:8002

# Agent ID (Blueprint + Agent Identity) — fill in manually
AGENT_BLUEPRINT_APP_ID=
AGENT_BLUEPRINT_SECRET=
AGENT_IDENTITY_ID=
AGENT_IDENTITY_TENANT_ID=

# Session
SESSION_SECRET=$(([guid]::NewGuid().ToString()) + ([guid]::NewGuid().ToString()))
"@

Set-Content -Path $OutputEnvFile -Value $envContent
Write-Host "`n✅ Done! App registrations created and .env generated." -ForegroundColor Green
Write-Host "`nApp IDs:" -ForegroundColor Cyan
Write-Host "  Client:  $clientAppId"
Write-Host "  API A:   $apiAAppId"
Write-Host "  API B:   $apiBAppId"
Write-Host "`n⚠️  Fill in AGENT_* values in .env manually for Agent ID flows." -ForegroundColor Yellow
