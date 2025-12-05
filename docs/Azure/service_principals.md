
## Enumeration
___
### Azure CLI

**List all SPs**
```bash
az ad sp list --all
az ad sp list --all --query "[].[displayName,appId,servicePrincipalNames]" -o table
```

**Get SP info**
```bash
az ad sp show --id <sp-id>
```

**Search SP by name**
```bash
az ad sp list --all --query "[?contains(displayName,'Test')].displayName"
```

**Get owner of SP**
```bash
az ad sp owner list --id <sp-id> --query "[].[displayName]" -o table
```

**Get SPs owned by current user**
```
az ad sp list --show-mine
```

**Get SPs with generated secret or certificate**
```bash
az ad sp list --query '[?length(keyCredentials) > `0` || length(passwordCredentials) > `0`].[displayName, appId, keyCredentials, passwordCredentials]' -o json
```

