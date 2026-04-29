<# 
    setup-agent-id.ps1 — Register Agent Identity Blueprint + Agent Identity for auth-viewer

    Prerequisites:
    - Azure CLI installed and logged in (az login)
    - register_apps.ps1 already ran (the .env file must exist with CLIENT_ID populated)
    - Permission to create app registrations and service principals

    Usage:
    .\scripts\setup-agent-id.ps1

    This script will:
    1. Register auth-viewer-blueprint (Agent Identity Blueprint app)
    2. Expose access_as_user scope on the Blueprint
    3. Pre-authorize the client app on the Blueprint
    4. Register auth-viewer-agent-identity (the Agent Identity — workload identity)
    5. Configure federated credential (WIF) linking agent to blueprint
    6. Grant delegated permission for the agent to call Graph
    7. Update .env with all AGENT_* values

    Docs: https://learn.microsoft.com/entra/identity/workload-identities/agent-identity-overview
#>

param(
    [string]$TenantId = "",
    [string]$EnvFile = ".env"
)

$ErrorActionPreference = "Stop"

# ── Load existing .env to get CLIENT_ID ──────────────────────────
if (-not (Test-Path $EnvFile)) {
    Write-Error ".env file not found. Run .\scripts\register_apps.ps1 first."
    exit 1
}

$envVars = @{}
Get-Content $EnvFile | ForEach-Object {
    if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
        $envVars[$Matches[1].Trim()] = $Matches[2].Trim()
    }
}

$ClientId = $envVars["CLIENT_ID"]
if (-not $ClientId) {
    Write-Error "CLIENT_ID not found in .env. Run .\scripts\register_apps.ps1 first."
    exit 1
}

if (-not $TenantId) {
    $TenantId = $envVars["TENANT_ID"]
    if (-not $TenantId) {
        $TenantId = (az account show --query tenantId -o tsv)
    }
}
Write-Host "Using tenant: $TenantId" -ForegroundColor Cyan
Write-Host "Using client: $ClientId" -ForegroundColor Cyan


# ══════════════════════════════════════════════════════════════════
# 1. Register Blueprint app
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Registering auth-viewer-blueprint ===" -ForegroundColor Yellow

$bpName = "auth-viewer-blueprint"
$bpResult = az ad app create `
    --display-name $bpName `
    --sign-in-audience AzureADMyOrg `
    --query "{appId: appId, id: id}" `
    -o json | ConvertFrom-Json

$bpAppId = $bpResult.appId
$bpObjectId = $bpResult.id
Write-Host "Blueprint App ID: $bpAppId"

# Set identifier URI
az ad app update --id $bpObjectId --identifier-uris "api://$bpAppId"

# Expose access_as_user scope
$bpScopeId = [guid]::NewGuid().ToString()
$bodyFile = "$env:TEMP\auth-viewer-bp-scope.json"
@"
{
  "identifierUris": ["api://$bpAppId"],
  "api": {
    "requestedAccessTokenVersion": 2,
    "oauth2PermissionScopes": [{
      "id": "$bpScopeId",
      "adminConsentDescription": "Allow access to agent API on behalf of the user",
      "adminConsentDisplayName": "Access agent API",
      "userConsentDescription": "Allow access to agent API on your behalf",
      "userConsentDisplayName": "Access agent API",
      "value": "access_as_user",
      "type": "User",
      "isEnabled": true
    }],
    "preAuthorizedApplications": [{
      "appId": "$ClientId",
      "delegatedPermissionIds": ["$bpScopeId"]
    }]
  },
  "optionalClaims": {
    "accessToken": [
      {"name": "xms_tnt_fct", "essential": false},
      {"name": "xms_sub_fct", "essential": false},
      {"name": "xms_act_fct", "essential": false},
      {"name": "xms_par_app_azp", "essential": false}
    ]
  }
}
"@ | Set-Content $bodyFile -Encoding UTF8
az rest --method PATCH `
    --url "https://graph.microsoft.com/v1.0/applications/$bpObjectId" `
    --headers "Content-Type=application/json" `
    --body "@$bodyFile"
Write-Host "Blueprint scope: api://$bpAppId/access_as_user" -ForegroundColor Green

# Create service principal for Blueprint
az ad sp create --id $bpAppId 2>$null

# NOTE: No client secret — Blueprint uses Federated Identity Credentials (FIC).
# Run scripts/setup_fic.ps1 after deploying Container Apps to configure FICs.


# ══════════════════════════════════════════════════════════════════
# 2. Register Agent Identity app (workload identity)
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Registering auth-viewer-agent-identity ===" -ForegroundColor Yellow

$agentName = "auth-viewer-agent-identity"
$agentResult = az ad app create `
    --display-name $agentName `
    --sign-in-audience AzureADMyOrg `
    --query "{appId: appId, id: id}" `
    -o json | ConvertFrom-Json

$agentAppId = $agentResult.appId
$agentObjectId = $agentResult.id
Write-Host "Agent Identity App ID: $agentAppId"

# Create service principal for Agent Identity
$agentSpResult = az ad sp create --id $agentAppId --query "{id: id}" -o json 2>$null | ConvertFrom-Json
$agentSpObjectId = $agentSpResult.id
Write-Host "Agent Identity SP Object ID: $agentSpObjectId"


# ══════════════════════════════════════════════════════════════════
# 3. Configure Workload Identity Federation (WIF)
#    Links the agent identity to the blueprint via a federated credential
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Configuring federated credential (WIF) ===" -ForegroundColor Yellow

$fidcBody = @{
    name        = "auth-viewer-blueprint-fic"
    issuer      = "https://login.microsoftonline.com/$TenantId/v2.0"
    subject     = $bpAppId
    audiences   = @("api://AzureADTokenExchange")
    description = "Trust Blueprint to issue tokens for this agent identity"
} | ConvertTo-Json -Depth 3

$bodyFile = "$env:TEMP\auth-viewer-fidc.json"
$fidcBody | Set-Content $bodyFile -Encoding UTF8
az rest --method POST `
    --url "https://graph.microsoft.com/v1.0/applications/$agentObjectId/federatedIdentityCredentials" `
    --headers "Content-Type=application/json" `
    --body "@$bodyFile" 2>$null
Write-Host "Federated credential created" -ForegroundColor Green


# ══════════════════════════════════════════════════════════════════
# 4. Grant delegated permission for agent to access Graph
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Granting Graph User.Read to agent identity ===" -ForegroundColor Yellow

# Get Microsoft Graph service principal
$graphSpId = (az ad sp show --id "00000003-0000-0000-c000-000000000000" --query id -o tsv)

# Create oauth2PermissionGrant (delegated consent for the agent SP)
$grantBody = @{
    clientId    = $agentSpObjectId
    consentType = "AllPrincipals"
    resourceId  = $graphSpId
    scope       = "User.Read"
} | ConvertTo-Json -Depth 3

$bodyFile = "$env:TEMP\auth-viewer-agent-grant.json"
$grantBody | Set-Content $bodyFile -Encoding UTF8
az rest --method POST `
    --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" `
    --headers "Content-Type=application/json" `
    --body "@$bodyFile" 2>$null
Write-Host "Graph User.Read consent granted to agent" -ForegroundColor Green


# ══════════════════════════════════════════════════════════════════
# 5. Grant Blueprint delegated consent on client
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Granting Blueprint consent to client ===" -ForegroundColor Yellow
az ad app permission grant --id $ClientId --api $bpAppId --scope "access_as_user" 2>$null
Write-Host "Blueprint access_as_user consent granted to client" -ForegroundColor Green


# ══════════════════════════════════════════════════════════════════
# 5b. Grant agent identity delegated consent on API A and API B
#     Required for Agent ID OBO flows targeting these resource APIs
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Granting agent identity consent on API A and API B ===" -ForegroundColor Yellow

$ApiAAppId = $envVars["API_A_APP_ID"]
$ApiBAppId = $envVars["API_B_APP_ID"]

if ($ApiAAppId) {
    $apiASpId = (az ad sp show --id $ApiAAppId --query id -o tsv 2>$null)
    if ($apiASpId) {
        $grantA = @{
            clientId    = $agentSpObjectId
            consentType = "AllPrincipals"
            resourceId  = $apiASpId
            scope       = "access_as_user"
        } | ConvertTo-Json -Depth 3
        $bodyFile = "$env:TEMP\auth-viewer-agent-grant-a.json"
        $grantA | Set-Content $bodyFile -Encoding UTF8
        az rest --method POST `
            --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" `
            --headers "Content-Type=application/json" `
            --body "@$bodyFile" 2>$null
        Write-Host "API A access_as_user consent granted to agent" -ForegroundColor Green
    }
}

if ($ApiBAppId) {
    $apiBSpId = (az ad sp show --id $ApiBAppId --query id -o tsv 2>$null)
    if ($apiBSpId) {
        $grantB = @{
            clientId    = $agentSpObjectId
            consentType = "AllPrincipals"
            resourceId  = $apiBSpId
            scope       = "read"
        } | ConvertTo-Json -Depth 3
        $bodyFile = "$env:TEMP\auth-viewer-agent-grant-b.json"
        $grantB | Set-Content $bodyFile -Encoding UTF8
        az rest --method POST `
            --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" `
            --headers "Content-Type=application/json" `
            --body "@$bodyFile" 2>$null
        Write-Host "API B read consent granted to agent" -ForegroundColor Green
    }
}


# ══════════════════════════════════════════════════════════════════
# 6. Update .env with Agent ID values
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Updating $EnvFile ===" -ForegroundColor Yellow

# Read existing .env, replace AGENT_* lines
$lines = Get-Content $EnvFile
$newLines = @()
foreach ($line in $lines) {
    if ($line -match '^AGENT_BLUEPRINT_APP_ID=') {
        $newLines += "AGENT_BLUEPRINT_APP_ID=$bpAppId"
    } elseif ($line -match '^AGENT_IDENTITY_ID=') {
        $newLines += "AGENT_IDENTITY_ID=$agentAppId"
    } elseif ($line -match '^AGENT_IDENTITY_TENANT_ID=') {
        $newLines += "AGENT_IDENTITY_TENANT_ID=$TenantId"
    } else {
        $newLines += $line
    }
}
Set-Content -Path $EnvFile -Value ($newLines -join "`n")

Write-Host "`n`u{2705} Agent ID setup complete!" -ForegroundColor Green
Write-Host "`nAgent ID values:" -ForegroundColor Cyan
Write-Host "  Blueprint:      $bpAppId"
Write-Host "  Blueprint Scope: api://$bpAppId/access_as_user"
Write-Host "  Agent Identity: $agentAppId"
Write-Host "  Tenant:         $TenantId"
