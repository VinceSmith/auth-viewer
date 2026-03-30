<#
    deploy_azure.ps1 — Deploy auth-viewer to Azure Container Apps with Easy Auth

    Cross-tenant setup:
    - App registrations live in the Entra test tenant (TENANT_ID from .env)
    - Azure resources are deployed to a separate subscription (SubscriptionId param)
    - Easy Auth is configured to validate tokens from the app registration tenant

    Prerequisites:
    - Azure CLI installed and logged in (with access to both tenants)
    - .env file populated (from register_apps.ps1)

    Usage:
    .\scripts\deploy_azure.ps1
    .\scripts\deploy_azure.ps1 -SubscriptionId "your-sub-id"

    This script will:
    1. Create a resource group, Container Apps environment, and ACR
    2. Build and push the Docker image
    3. Create 3 container apps (main, api-a, api-b) with secrets from .env
    4. Configure Easy Auth on the main app (requires Entra sign-in from app reg tenant)
    5. Update the Entra app registration with the new redirect URI
#>

param(
    [string]$SubscriptionId = "eed3fbe8-5fbd-4ce1-9d39-caceb296a288",
    [string]$ResourceGroup = "rg-auth-viewer",
    [string]$Location = "eastus2",
    [string]$EnvName = "auth-viewer-env",
    [string]$AcrName = "authvieweracr",
    [string]$EnvFile = ".env"
)

$ErrorActionPreference = "Stop"

# ── Load .env ────────────────────────────────────────────────────
if (-not (Test-Path $EnvFile)) {
    Write-Error ".env not found. Run .\scripts\register_apps.ps1 first."
    exit 1
}

$envVars = @{}
Get-Content $EnvFile | ForEach-Object {
    if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
        $envVars[$Matches[1].Trim()] = $Matches[2].Trim()
    }
}

$TenantId          = $envVars["TENANT_ID"]
$ClientId          = $envVars["CLIENT_ID"]
$ClientSecret      = $envVars["CLIENT_SECRET"]
$ApiAAppId         = $envVars["API_A_APP_ID"]
$ApiAClientSecret  = $envVars["API_A_CLIENT_SECRET"]
$ApiAScope         = $envVars["API_A_SCOPE"]
$ApiBAppId         = $envVars["API_B_APP_ID"]
$ApiBScope         = $envVars["API_B_SCOPE"]
$AgentBlueprintId  = $envVars["AGENT_BLUEPRINT_APP_ID"]
$AgentBlueprintSec = $envVars["AGENT_BLUEPRINT_SECRET"]
$AgentIdentityId   = $envVars["AGENT_IDENTITY_ID"]
$AgentIdentityTid  = $envVars["AGENT_IDENTITY_TENANT_ID"]
$SessionSecret     = $envVars["SESSION_SECRET"]

Write-Host "Deploying auth-viewer to Azure Container Apps" -ForegroundColor Cyan
Write-Host "  Subscription:   $SubscriptionId" -ForegroundColor Cyan
Write-Host "  Resource Group: $ResourceGroup" -ForegroundColor Cyan
Write-Host "  Location:       $Location" -ForegroundColor Cyan
Write-Host "  Entra Tenant:   $TenantId (app registrations)" -ForegroundColor Cyan

# Set the subscription for all Azure resource commands
az account set --subscription $SubscriptionId

# ══════════════════════════════════════════════════════════════════
# 1. Resource Group
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Creating resource group ===" -ForegroundColor Yellow
az group create --name $ResourceGroup --location $Location -o none

# ══════════════════════════════════════════════════════════════════
# 2. Container Registry
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Creating Azure Container Registry ===" -ForegroundColor Yellow
az acr create --resource-group $ResourceGroup --name $AcrName --sku Basic --admin-enabled true -o none
$AcrLoginServer = (az acr show --name $AcrName --query loginServer -o tsv)
Write-Host "ACR: $AcrLoginServer" -ForegroundColor Green

# ══════════════════════════════════════════════════════════════════
# 3. Build and push image
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Building Docker image in ACR ===" -ForegroundColor Yellow
az acr build --registry $AcrName --image auth-viewer:latest --file Dockerfile . 
$ImageName = "$AcrLoginServer/auth-viewer:latest"
Write-Host "Image: $ImageName" -ForegroundColor Green

# ══════════════════════════════════════════════════════════════════
# 4. Container Apps environment
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Creating Container Apps environment ===" -ForegroundColor Yellow
az containerapp env create `
    --name $EnvName `
    --resource-group $ResourceGroup `
    --location $Location `
    -o none

# ACR credentials for image pull
$AcrPassword = (az acr credential show --name $AcrName --query "passwords[0].value" -o tsv)

# ══════════════════════════════════════════════════════════════════
# 5. Deploy API B (internal only)
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Deploying API B (internal) ===" -ForegroundColor Yellow
az containerapp create `
    --name api-b `
    --resource-group $ResourceGroup `
    --environment $EnvName `
    --image $ImageName `
    --registry-server $AcrLoginServer `
    --registry-username $AcrName `
    --registry-password "$AcrPassword" `
    --target-port 8002 `
    --ingress internal `
    --min-replicas 1 --max-replicas 1 `
    --env-vars "TENANT_ID=$TenantId" "API_B_APP_ID=$ApiBAppId" `
    -o none

# Override the startup command (default CMD is for the main app)
az containerapp update `
    --name api-b `
    --resource-group $ResourceGroup `
    --container-name api-b `
    --args "resource_api_b.main:app" "--host" "0.0.0.0" "--port" "8002" `
    --command "uvicorn" `
    -o none

$ApiBInternalUrl = (az containerapp show --name api-b --resource-group $ResourceGroup --query "properties.configuration.ingress.fqdn" -o tsv)
$ApiBBaseUrl = "https://$ApiBInternalUrl"
Write-Host "API B internal URL: $ApiBBaseUrl" -ForegroundColor Green

# ══════════════════════════════════════════════════════════════════
# 6. Deploy API A (internal only)
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Deploying API A (internal) ===" -ForegroundColor Yellow
az containerapp create `
    --name api-a `
    --resource-group $ResourceGroup `
    --environment $EnvName `
    --image $ImageName `
    --registry-server $AcrLoginServer `
    --registry-username $AcrName `
    --registry-password "$AcrPassword" `
    --target-port 8001 `
    --ingress internal `
    --min-replicas 1 --max-replicas 1 `
    --secrets "api-a-secret=$ApiAClientSecret" `
    --env-vars "TENANT_ID=$TenantId" "API_A_APP_ID=$ApiAAppId" "API_A_CLIENT_SECRET=secretref:api-a-secret" "API_B_SCOPE=$ApiBScope" "API_B_BASE_URL=$ApiBBaseUrl" `
    -o none

# Override the startup command (default CMD is for the main app)
az containerapp update `
    --name api-a `
    --resource-group $ResourceGroup `
    --container-name api-a `
    --args "resource_api_a.main:app" "--host" "0.0.0.0" "--port" "8001" `
    --command "uvicorn" `
    -o none

$ApiAInternalUrl = (az containerapp show --name api-a --resource-group $ResourceGroup --query "properties.configuration.ingress.fqdn" -o tsv)
$ApiABaseUrl = "https://$ApiAInternalUrl"
Write-Host "API A internal URL: $ApiABaseUrl" -ForegroundColor Green

# ══════════════════════════════════════════════════════════════════
# 7. Deploy Main App (external + Easy Auth)
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Deploying Main App (external) ===" -ForegroundColor Yellow
az containerapp create `
    --name auth-viewer `
    --resource-group $ResourceGroup `
    --environment $EnvName `
    --image $ImageName `
    --registry-server $AcrLoginServer `
    --registry-username $AcrName `
    --registry-password "$AcrPassword" `
    --target-port 8000 `
    --ingress external `
    --min-replicas 1 --max-replicas 1 `
    --secrets "client-secret=$ClientSecret" "api-a-secret=$ApiAClientSecret" "bp-secret=$AgentBlueprintSec" "session-secret=$SessionSecret" `
    --env-vars "TENANT_ID=$TenantId" "CLIENT_ID=$ClientId" "CLIENT_SECRET=secretref:client-secret" "API_A_APP_ID=$ApiAAppId" "API_A_CLIENT_SECRET=secretref:api-a-secret" "API_A_SCOPE=$ApiAScope" "API_A_BASE_URL=$ApiABaseUrl" "API_B_APP_ID=$ApiBAppId" "API_B_SCOPE=$ApiBScope" "API_B_BASE_URL=$ApiBBaseUrl" "AGENT_BLUEPRINT_APP_ID=$AgentBlueprintId" "AGENT_BLUEPRINT_SECRET=secretref:bp-secret" "AGENT_IDENTITY_ID=$AgentIdentityId" "AGENT_IDENTITY_TENANT_ID=$AgentIdentityTid" "SESSION_SECRET=secretref:session-secret" `
    -o none

$AppFqdn = (az containerapp show --name auth-viewer --resource-group $ResourceGroup --query "properties.configuration.ingress.fqdn" -o tsv)
$AppUrl = "https://$AppFqdn"
Write-Host "Main App URL: $AppUrl" -ForegroundColor Green

# ══════════════════════════════════════════════════════════════════
# 8. Update REDIRECT_URI env var on the container
#    The app registration redirect URI must be updated separately
#    (requires az login to the app registration tenant)
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Updating REDIRECT_URI env var ===" -ForegroundColor Yellow
$RedirectUri = "$AppUrl/auth/callback"

az containerapp update `
    --name auth-viewer `
    --resource-group $ResourceGroup `
    --set-env-vars "REDIRECT_URI=$RedirectUri" `
    -o none

Write-Host "REDIRECT_URI set to: $RedirectUri" -ForegroundColor Green
Write-Host "`n>>> MANUAL STEP REQUIRED <<<" -ForegroundColor Red
Write-Host "Run these commands in a separate terminal to update the app registration:" -ForegroundColor Yellow
Write-Host "  az login --tenant $TenantId" -ForegroundColor White
Write-Host "  az ad app update --id $ClientId --web-redirect-uris http://localhost:8000/auth/callback $RedirectUri" -ForegroundColor White

# ══════════════════════════════════════════════════════════════════
# 9. Configure Easy Auth (Microsoft Entra, require authentication)
#    Issuer points to the APP REGISTRATION tenant, not the resource tenant.
#    This ensures only users from the test tenant (native + B2B guests) can sign in.
# ══════════════════════════════════════════════════════════════════
Write-Host "`n=== Configuring Easy Auth ===" -ForegroundColor Yellow

# Get the Container App resource ID
$AppResourceId = (az containerapp show --name auth-viewer --resource-group $ResourceGroup --query id -o tsv)

# Configure authentication — require login, validate against app reg tenant
$authConfig = @{
    properties = @{
        platform = @{
            enabled = $true
        }
        globalValidation = @{
            unauthenticatedClientAction = "RedirectToLoginPage"
            redirectToProvider = "azureactivedirectory"
        }
        identityProviders = @{
            azureActiveDirectory = @{
                enabled = $true
                registration = @{
                    openIdIssuer = "https://login.microsoftonline.com/$TenantId/v2.0"
                    clientId = $ClientId
                    clientSecretSettingName = "microsoft-provider-authentication-secret"
                }
                validation = @{
                    allowedAudiences = @($ClientId, "api://$ClientId")
                }
            }
        }
    }
} | ConvertTo-Json -Depth 10

$bodyFile = "$env:TEMP\auth-viewer-easyauth.json"
$authConfig | Set-Content $bodyFile -Encoding UTF8

# Set the client secret as an auth secret
az containerapp secret set `
    --name auth-viewer `
    --resource-group $ResourceGroup `
    --secrets "microsoft-provider-authentication-secret=$ClientSecret" `
    -o none

# Apply auth config via ARM
az rest --method PUT `
    --url "$AppResourceId/authConfigs/Current?api-version=2024-03-01" `
    --headers "Content-Type=application/json" `
    --body "@$bodyFile"

Write-Host "Easy Auth configured — sign-in required for all requests" -ForegroundColor Green

# ══════════════════════════════════════════════════════════════════
# Done
# ══════════════════════════════════════════════════════════════════
Write-Host "`n`u{2705} Deployment complete!" -ForegroundColor Green
Write-Host "`nApp URL: $AppUrl" -ForegroundColor Cyan
Write-Host "Callback: $RedirectUri" -ForegroundColor Cyan
Write-Host "`nResource group: $ResourceGroup" -ForegroundColor Cyan
Write-Host "ACR:            $AcrName" -ForegroundColor Cyan
Write-Host "`nEasy Auth requires Entra sign-in before accessing the app." -ForegroundColor Cyan
Write-Host "Only users in tenant $TenantId (native + B2B guests) can sign in." -ForegroundColor Cyan
