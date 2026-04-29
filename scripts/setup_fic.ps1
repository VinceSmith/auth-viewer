<#
    setup_fic.ps1 — Create Federated Identity Credentials on all app registrations
    
    Prerequisites:
    - Azure CLI installed and logged in (az login)
    - Container Apps already deployed with system-assigned MI enabled
    - .env file with app IDs populated
    
    This script will:
    1. Enable system-assigned MI on auth-viewer and api-a Container Apps
    2. Create FICs on auth-viewer-client, auth-viewer-api-a, auth-viewer-blueprint
    3. Create a developer FIC for local az login
    4. Create GitHub Actions OIDC FIC on auth-viewer-deploy SP
#>

param(
    [string]$ResourceGroup = "rg-auth-viewer",
    [string]$GitHubRepo = "VinceSmith/auth-viewer",
    [string]$GitHubBranch = "master"
)

$ErrorActionPreference = "Stop"

# Load app IDs from .env
$envFile = Join-Path $PSScriptRoot ".." ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
        }
    }
}

$clientAppId = $env:CLIENT_ID
$apiAAppId = $env:API_A_APP_ID
$blueprintAppId = $env:AGENT_BLUEPRINT_APP_ID
$deploySPAppId = "df57db7e-01c1-44cd-9fd4-3be2b9f842a6"
$tenantId = $env:TENANT_ID

Write-Host "=== Step 1: Enable system-assigned MI on Container Apps ===" -ForegroundColor Yellow

# Enable MI on auth-viewer
az containerapp identity assign --name auth-viewer --resource-group $ResourceGroup --system-assigned --output none
$authViewerMI = (az containerapp show --name auth-viewer --resource-group $ResourceGroup --query "identity.principalId" -o tsv)
Write-Host "auth-viewer MI principal: $authViewerMI" -ForegroundColor Green

# Enable MI on api-a
az containerapp identity assign --name api-a --resource-group $ResourceGroup --system-assigned --output none
$apiAMI = (az containerapp show --name api-a --resource-group $ResourceGroup --query "identity.principalId" -o tsv)
Write-Host "api-a MI principal: $apiAMI" -ForegroundColor Green

Write-Host "`n=== Step 2: Create FICs on app registrations ===" -ForegroundColor Yellow

# Helper function to create FIC
function Add-FIC {
    param(
        [string]$AppId,
        [string]$FICName,
        [string]$Subject,
        [string]$Issuer = "https://login.microsoftonline.com/$tenantId/v2.0",
        [string]$Description
    )
    
    $objectId = (az ad app show --id $AppId --query id -o tsv)
    
    # Check if FIC already exists
    $existing = az ad app federated-credential list --id $objectId --query "[?name=='$FICName'].name" -o tsv
    if ($existing) {
        Write-Host "  FIC '$FICName' already exists on $AppId — skipping" -ForegroundColor DarkGray
        return
    }
    
    $body = @{
        name = $FICName
        issuer = $Issuer
        subject = $Subject
        audiences = @("api://AzureADTokenExchange")
        description = $Description
    } | ConvertTo-Json -Compress
    
    $bodyFile = "$env:TEMP\fic-$FICName.json"
    $body | Set-Content $bodyFile -Encoding UTF8
    az ad app federated-credential create --id $objectId --parameters "@$bodyFile" --output none
    Write-Host "  Created FIC '$FICName' on $AppId" -ForegroundColor Green
}

# FICs for auth-viewer-client (trusted by auth-viewer container MI)
Add-FIC -AppId $clientAppId -FICName "auth-viewer-container-mi" `
    -Subject $authViewerMI `
    -Description "Trust auth-viewer Container App managed identity"

# FICs for auth-viewer-api-a (trusted by BOTH auth-viewer MI and api-a MI)
Add-FIC -AppId $apiAAppId -FICName "auth-viewer-container-mi" `
    -Subject $authViewerMI `
    -Description "Trust auth-viewer Container App MI (for flows.py OBO)"

Add-FIC -AppId $apiAAppId -FICName "api-a-container-mi" `
    -Subject $apiAMI `
    -Description "Trust api-a Container App MI (for resource_api_a OBO/CC)"

# FICs for auth-viewer-blueprint (trusted by auth-viewer container MI)
if ($blueprintAppId) {
    Add-FIC -AppId $blueprintAppId -FICName "auth-viewer-container-mi" `
        -Subject $authViewerMI `
        -Description "Trust auth-viewer Container App MI for Agent ID flows"
} else {
    Write-Host "  Skipping blueprint FIC — AGENT_BLUEPRINT_APP_ID not set" -ForegroundColor DarkYellow
}

Write-Host "`n=== Step 3: Create developer FIC for local az login ===" -ForegroundColor Yellow

$devObjectId = (az ad signed-in-user show --query id -o tsv)
Write-Host "Developer object ID: $devObjectId" -ForegroundColor Cyan

Add-FIC -AppId $clientAppId -FICName "developer-azlogin" `
    -Subject $devObjectId `
    -Description "Trust developer az login identity for local dev"

Add-FIC -AppId $apiAAppId -FICName "developer-azlogin" `
    -Subject $devObjectId `
    -Description "Trust developer az login identity for local dev"

if ($blueprintAppId) {
    Add-FIC -AppId $blueprintAppId -FICName "developer-azlogin" `
        -Subject $devObjectId `
        -Description "Trust developer az login identity for local dev"
}

Write-Host "`n=== Step 4: Create GitHub Actions OIDC FIC on deploy SP ===" -ForegroundColor Yellow

$deployObjectId = (az ad app show --id $deploySPAppId --query id -o tsv)
$ghSubject = "repo:${GitHubRepo}:ref:refs/heads/${GitHubBranch}"

$existing = az ad app federated-credential list --id $deployObjectId --query "[?name=='github-actions-oidc'].name" -o tsv
if ($existing) {
    Write-Host "  FIC 'github-actions-oidc' already exists — skipping" -ForegroundColor DarkGray
} else {
    $body = @{
        name = "github-actions-oidc"
        issuer = "https://token.actions.githubusercontent.com"
        subject = $ghSubject
        audiences = @("api://AzureADTokenExchange")
        description = "Trust GitHub Actions OIDC for CI/CD"
    } | ConvertTo-Json -Compress
    
    $bodyFile = "$env:TEMP\fic-github-oidc.json"
    $body | Set-Content $bodyFile -Encoding UTF8
    az ad app federated-credential create --id $deployObjectId --parameters "@$bodyFile" --output none
    Write-Host "  Created GitHub Actions OIDC FIC on deploy SP" -ForegroundColor Green
}

Write-Host "`n=== Done ===" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1. Set GitHub secrets: AZURE_CLIENT_ID=$deploySPAppId, AZURE_TENANT_ID=$tenantId, AZURE_SUBSCRIPTION_ID=<sub-id>"
Write-Host "  2. Delete GitHub secret: AZURE_CREDENTIALS"
Write-Host "  3. Delete old secrets: az ad app credential list --id <app-id>"
