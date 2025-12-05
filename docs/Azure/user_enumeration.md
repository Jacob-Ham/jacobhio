
### Unauthenticated
---
Spray!

With **o365enum**
https://github.com/gremwell/o365enum
```
o365enum.py -u userslist.txt -n 1 -m office.com
```

OmniSpray
https://github.com/0xZDH/Omnispray
```bash
python3 omnispray.py --type enum -uf users.txt --module o365_enum_office
```

### Authenticated
---
#### AZ CLI

**Get all users**
```bash
az ad user list --query "[].userPrincipalName" --output tsv
```

```bash
az ad user list --output table
```

Az Powershell
get modules:
```powershell
Install-Module -Name Az -Repository PSGallery -Force
Import-Module -Name Az
Install-Module -Name Microsoft.Graph -Scope CurrentUser -AllowClobber -Force
Import-Module -Name Microsoft.Graph
```

Dump all users:
```bash
Get-AzADUser
```

**List admin users**
```bash
az ad user list --query "[?contains(displayName,'admin')].displayName"
```

**Search user attributes for strings**
```cmd
az ad user list | findstr /i "password" | findstr /v "null,"
```

```bash
az ad user list | grep -i "password" | grep -v "null,"
```

**Get users from Entra ID**
```bash
az ad user list --query "[].{osi:onPremisesSecurityIdentifier,upn:userPrincipalName}[?osi==null]"
```

**Get synced users from on-prem**
```bash
az ad user list --query "[].{osi:onPremisesSecurityIdentifier,upn:userPrincipalName}[?osi!=null]"
```

**Get groups where the user is a member**
```bash
az ad user get-member-groups --id <email>
```

**Get roles assigned to the user in Azure (NOT in Entra ID)**
```bash
az role assignment list --include-inherited --include-groups --include-classic-administrators true --assignee <email>
```

**Get ALL roles assigned in Azure in the current subscription (NOT in Entra ID)**
```bash
az role assignment list --include-groups --include-classic-administrators true --all
```

#### API

**Get bearer token**
```bash
export TOKEN=$(az account get-access-token --resource https://graph.microsoft.com/ --query accessToken -o tsv)
```

**Get users**
```bash
curl -X GET "https://graph.microsoft.com/v1.0/users" \ -H "Authorization: Bearer $TOKEN" \ -H "Content-Type: application/json" | jq
```

**Get EntraID roles assigned to user**
```bash
curl -X GET "https://graph.microsoft.com/beta/rolemanagement/directory/transitiveRoleAssignments?\$count=true&\$filter=principalId%20eq%20'86b10631-ff01-4e73-a031-29e505565caa'" \
-H "Authorization: Bearer $TOKEN" \
-H "ConsistencyLevel: eventual" \
-H "Content-Type: application/json" | jq
```

**Get role details**
```bash
curl -X GET "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/cf1c38e5-3621-4004-a7cb-879624dced7c" \
-H "Authorization: Bearer $TOKEN" \
-H "Content-Type: application/json" | jq
```


**User properties to gain context**
```powershell
Get-AzADUser -UserPrincipalName 'user.one@domain.com' | fl
```

**With GraphRunner.ps1**
```powershell
Get-AzureADUsers -Tokens $tokens -outfile users.txt
```

Validate enabled users
```bash
az ad user list --query "[?givenName=='user1' || givenName=='user2' || givenName=='user3'].{Name:displayName, UPN:userPrincipalName, JobTitle:jobTitle}" -o table
```

Get users object ID
```bash
Get-MgUser -UserId user1@domain.com
```

Find role assignment.

get tenantid
```bash
az account show --query tenantId --output tsv
```

```powershell
(Get-AzContext).Tenant.Id
```

```powershell
Get-AzRoleAssignment -Scope "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94" | Select-Object DisplayName, RoleDefinitionName
```