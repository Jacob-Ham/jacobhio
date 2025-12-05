
## Enumeration
---
### Azure CLI

**List all administrative units**
```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits"
```

**Get AU Info**
```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/<au-id>"
```

**Get members**
```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/<au-id>/members"
```

**Get principals with roles over the AU**
```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/<au-id>/scopedRoleMembers"
```