___
### Authenticated
---
List available resources for your user
```bash
az resource list
```

or with curl
```bash
SubscriptionId='<TENANTID>'
ResourceUrl="https://management.azure.com/subscriptions/$SubscriptionId/resources"
accesstoken='jwtaccesstoken'

curl -X GET "${ResourceUrl}?api-version=2020-06-01" \
-H "Authorization: Bearer $accesstoken" \
-H "Content-Type: application/json"
```

Check resources your user owns
```powershell
Get-MgUserOwnedObject -UserId "user.one@domain.com"
```

Check resources your user as "reader" or *greater* access to 
```powershell
Get-AzResource
```

Check specific permissions.
```powershell
Get-AzRoleAssignment -SignInName user.one@domain.com
```

