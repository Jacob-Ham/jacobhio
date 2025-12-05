### Authenticate with Access Tokens
---

**Azure PowerShell (Az Module)**

```powershell
$accesstoken = "<YOUR-ACCESS-TOKEN>"
$accountid = "is required but not validated"
Connect-AzAccount -AccessToken $accesstoken -AccountId $accountid
```

Validate connection:
```powershell
Get-AzContext
Get-AzResource
```

**Azure CLI**

> [!NOTE] Note
> Azure CLI doesn't natively support direct access token authentication. Use REST API calls or convert to refresh token first.

With access token via REST API:
```bash
curl -H "Authorization: Bearer <ACCESS-TOKEN>" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

**Microsoft Graph PowerShell**

```powershell
$accesstoken = "<YOUR-GRAPH-TOKEN>"
Connect-MgGraph -AccessToken $accesstoken
```

Validate:
```powershell
Get-MgContext
```

**AADInternals**
https://github.com/Gerenios/AADInternals

```powershell
Import-Module AADInternals
$at = "<YOUR-ACCESS-TOKEN>"
Get-AADIntAccessTokenForAADGraph -AccessToken $at
```

**Direct API calls with cURL**

Azure Management API:
```bash
curl -H "Authorization: Bearer <ACCESS-TOKEN>" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

Microsoft Graph API:
```bash
curl -H "Authorization: Bearer <ACCESS-TOKEN>" \
  "https://graph.microsoft.com/v1.0/me"
```

Azure Key Vault:
```bash
curl -H "Authorization: Bearer <VAULT-TOKEN>" \
  "https://<vault-name>.vault.azure.net/secrets?api-version=7.1"
```

**PowerShell Invoke-RestMethod**

```powershell
$accessToken = "<YOUR-ACCESS-TOKEN>"
$headers = @{
    'Authorization' = "Bearer $accessToken"
    'Content-Type' = 'application/json'
}
$uri = "https://graph.microsoft.com/v1.0/me"
Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
```

### Authenticate with Refresh Tokens
---

**TokenTactics**
https://github.com/f-bader/TokenTacticsV2

Convert refresh token to access token:
```powershell
Import-Module ./TokenTactics.psm1

# Get ARM token
RefreshTo-AzureManagementToken -domain domain.com -RefreshToken '<REFRESH-TOKEN>'

# Get Graph token  
RefreshTo-MSGraphToken -domain domain.com -RefreshToken '<REFRESH-TOKEN>'

# Get MSTeams token
RefreshTo-MSTeamsToken -domain domain.com -RefreshToken '<REFRESH-TOKEN>'

# Get Substrate token
RefreshTo-SubstrateToken -domain domain.com -RefreshToken '<REFRESH-TOKEN>'

# Get Outlook token
RefreshTo-OutlookToken -domain domain.com -RefreshToken '<REFRESH-TOKEN>'
```

Access tokens:
```powershell
$MSGraphToken.access_token
$AzureManagementToken.access_token
```

> [!NOTE] Opsec
> TokenTactics uses specific user agents. Use `-Device` or `-Browser` flags to blend in better

**AADInternals**

```powershell
Import-Module AADInternals

$RefreshToken = "<REFRESH-TOKEN>"

# Get access token for specific resource
Get-AADIntAccessTokenForAADGraph -RefreshToken $RefreshToken
Get-AADIntAccessTokenForAzureCoreManagement -RefreshToken $RefreshToken  
Get-AADIntAccessTokenForMSGraph -RefreshToken $RefreshToken
```

**GraphRunner**
https://github.com/dafthack/GraphRunner

```powershell
Import-Module .\GraphRunner.ps1

# Use refresh token to get new tokens
Invoke-RefreshGraphTokens -RefreshToken '<REFRESH-TOKEN>'
```

**ROADTools**
https://github.com/dirkjanm/ROADtools

```bash
# Get tokens with credentials first
roadrecon auth -u "user@domain.com" -p 'Password123'

# Refresh token stored in .roadtools_auth for reuse
roadrecon auth --refresh-token <REFRESH-TOKEN>
```

### Using Both Access + Refresh Tokens
---

**Save Azure context for persistence**

```powershell
# Authenticate with access token
Connect-AzAccount -AccessToken $accesstoken -AccountId "user@domain.com"

# Save entire context (includes tokens)
Save-AzContext -Path ./azure_context.json

# Restore context later
Import-AzContext -Path ./azure_context.json
```

**TokenTactics token refresh workflow**

```powershell
# Initial auth with refresh token
RefreshTo-MSGraphToken -domain domain.com -RefreshToken '<REFRESH-TOKEN>'

# Use access token  
$headers = @{ 'Authorization' = "Bearer $($MSGraphToken.access_token)" }

# When access token expires, refresh again
Invoke-RefreshToMSGraphToken -domain domain.com -RefreshToken '<REFRESH-TOKEN>'
```

**AADInternals session management**

```powershell
# Get initial tokens
$tokens = Get-AADIntAccessTokenForAADGraph -RefreshToken $RefreshToken

# Parse tokens
$AccessToken = $tokens[0]
$RefreshToken = $tokens[1]

# Use access token for operations
Get-AADIntUsers -AccessToken $AccessToken

# Refresh when needed
$newTokens = Get-AADIntAccessTokenForAADGraph -RefreshToken $RefreshToken
```

### Token Audience Mapping
---

Make sure your access token's `aud` claim matches the resource:

| Resource | Audience (aud) | Use Case |
|----------|----------------|----------|
| Azure Management | `https://management.azure.com` | ARM API, subscriptions, resources |
| Microsoft Graph | `https://graph.microsoft.com` | Users, groups, mail, teams |
| Azure AD Graph | `https://graph.windows.net` | Legacy Azure AD (deprecated) |
| Key Vault | `https://vault.azure.net` | Secrets, keys, certificates |
| Storage | `https://storage.azure.com` | Blob, queue, table storage |
| Office 365 | `https://outlook.office365.com` | Exchange, mailboxes |

### FOCI Token Abuse
---

If you have a refresh token from a FOCI (Family of Client IDs) app, you can exchange it for access to ANY app in the family.

**TokenTactics FOCI support**

```powershell
# Refresh token from one FOCI app can access others
RefreshTo-MSGraphToken -domain domain.com -RefreshToken '<FOCI-REFRESH-TOKEN>'
RefreshTo-AzureManagementToken -domain domain.com -RefreshToken '<SAME-FOCI-TOKEN>'
RefreshTo-MSTeamsToken -domain domain.com -RefreshToken '<SAME-FOCI-TOKEN>'
```

Common FOCI apps:
- Microsoft Teams  
- Microsoft Office
- Azure PowerShell
- Azure CLI
- Microsoft Graph PowerShell

### Decode & Inspect Tokens
---

**PowerShell JWT decode**

```powershell
function Parse-JWTtoken {
    param([string]$token)
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { $tokenPayload += "=" }
    $bytes = [System.Convert]::FromBase64String($tokenPayload)
    $json = [System.Text.Encoding]::ASCII.GetString($bytes)
    $json | ConvertFrom-Json
}

Parse-JWTtoken -token "<YOUR-TOKEN>"
```

**Online decoder** (opsec warning)
- jwt.io (sends token to external site)

**Check token validity**

```bash
# Graph token
curl -H "Authorization: Bearer <TOKEN>" https://graph.microsoft.com/v1.0/me

# ARM token  
curl -H "Authorization: Bearer <TOKEN>" \
  https://management.azure.com/subscriptions?api-version=2020-01-01
```

### Extract Tokens from Azure CLI/PowerShell
---

See: [[get_tokens]] for full extraction methods

**Quick token extraction**

Azure CLI:
```bash
az account get-access-token --resource "https://management.azure.com" | jq -r '.accessToken'
az account get-access-token --resource "https://graph.microsoft.com" | jq -r '.accessToken'
```

PowerShell:
```powershell
(Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
(Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
```

**Token cache locations**

Linux/Mac:
```bash
~/.azure/msal_token_cache.json
~/.Azure/msal_token_cache.json
```

Windows:
```
C:\Users\<user>\.Azure\accessTokens.json
C:\Users\<user>\.azure\msal_token_cache.bin
```
