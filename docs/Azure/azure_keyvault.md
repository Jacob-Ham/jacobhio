
### Identify 


Login and validate:
```powershell
az login
az account show
```

Get graph session:
```powershell
Install-Module Microsoft.Graph
Import-Module Microsoft.Graph.Users
Connect-MgGraph
Install-Module Az
Import-Module Az
Connect-AzAccount
```

Validate graph
```powershell
Get-MgContext
```

Check user
```
az ad signed-in-user show
```

Check for group membership

```powershell
Get-MgUserMemberOf -userid "user@domain.com" | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}
```

Get subscription ID:
```powershell
Get-AzSubscription | Select-Object Name, Id
```

Check for other azure permissions

```powershell
# Given subscription ID
$CurrentSubscriptionID = "<sub id>"

# Set output format
$OutputFormat = "table"

# Set the given subscription as the active one
& az account set --subscription $CurrentSubscriptionID

# List resources in the current subscription
& az resource list -o $OutputFormat
```

Look for keyvault resource types and note resource name. 

Then, enumerate secrets stored in the vault

```powershell
# Set variables
$VaultName = "<vault name>"

# Set the current Azure subscription
$SubscriptionID = "<sub-id>"
az account set --subscription $SubscriptionID

# List and store the secrets
$secretsJson = az keyvault secret list --vault-name $VaultName -o json

$secrets = $secretsJson | ConvertFrom-Json

# List and store the keys
$keysJson = az keyvault key list --vault-name $VaultName -o json

$keys = $keysJson | ConvertFrom-Json

# Output the secrets
Write-Host "Secrets in vault $VaultName"
foreach ($secret in $secrets) {
    Write-Host $secret.id
}

# Output the keys
Write-Host "Keys in vault $VaultName"
foreach ($key in $keys) {
    Write-Host $key.id
}
```

or with powershell module
```powershell
Get-AzKeyVaultSecret -VaultName 'ext-contractors' | Select-Object Name
```


Read stored secrets:

script kinda sucks
```powershell
# Set variables
$VaultName = "<vaul-name>"
$SecretNames = @("<nameofsecret>", "ameofsecret2", "nameofsecret3")

# Set the current Azure subscription
$SubscriptionID = "<sub id>"
az account set --subscription $SubscriptionID

# Retrieve and output the secret values
Write-Host "Secret Values from vault $VaultName"
foreach ($SecretName in $SecretNames) {
    $secretValueJson = az keyvault secret show --name $SecretName --vault-name $VaultName -o json
    $secretValue = ($secretValueJson | ConvertFrom-Json).value
    Write-Host "$SecretName - $secretValue"
}
```

Better script?
```powershell
$VaultName = "secrets-vault"

Get-AzKeyVaultSecret -VaultName $VaultName | ForEach-Object { Get-AzKeyVaultSecret -VaultName $VaultName -Name $_.Name -asplaintext }
```

One at at a time:
```powershll
az keyvault secret show --name <name> --vault-name <vault> -o json
```


If these happen to be user credentials, we can validate the users still exist with:
show active users:

You might need to use just first name (case sensitive) for this
```powershell
az ad user list --query "[?givenName=='user1' || givenName=='user2' || givenName=='user3'].{Name:displayName, UPN:userPrincipalName, JobTitle:jobTitle}" -o table
```

This will return info on only existing users.
Assuming we have a user here, lets grab its objectID for further enumeration
```powershell
Get-MgUser -UserId user@domain.com
```
(note down object ID)

Further enumerate users groups with object ID:
```powershell
$UserId = 'OBJECT ID'
Get-MgUserMemberOf -userid $userid | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}
```

Any extra privs?

**With curl**
```powershell
$vaultName = "vualtname"
$apiVersion = "7.1"
$accessToken = 'token'
$headers = @{
'Authorization' = "Bearer $accessToken"
'Content-Type' = 'application/json'
}
$uri = "https://$vaultName.vault.azure.net/secrets?api-version=$apiVersion"
$response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
$response.value | ForEach-Object {
Write-Host "Secret Name: $($_.id)"
}
```
this will output secret name and endpoint.

Read the secret:
```powershell
$secretName = "<name returned from above>"
$apiVersion = "7.1"
$vaultName = "<vault>"
$accessToken = ''
$secretUri = "https://$vaultName.vault.azure.net/secrets/${secretName}?api-
version=$apiVersion"
$headers = @{
'Authorization' = "Bearer $accessToken"
'Content-Type' = 'application/json'
}
$secretResponse = Invoke-RestMethod -Uri $secretUri -Method Get -Headers $headers
Write-Host "Secret Value: $($secretResponse.value)"
```