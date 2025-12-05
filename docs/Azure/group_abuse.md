
## Enumeration

#### Azure CLI
---
**List groups**
```bash
az ad group list
```

**Get group information**
```bash
az ad group show --group <name>
```

**Get groups from EntraID**
```bash
az ad group list --query "[].{osi:onPremisesSecurityIdentifier,displayName:displayName,description:description}[?osi==null]"
```

**Get synced users from on-prem**
```bash
az ad group list --query "[].{osi:onPremisesSecurityIdentifier,displayName:displayName,description:description}[?osi!=null]"
```

**Get group members**
```bash
az ad group member list --group <group-name> --query "[].userPrincipalName" -o table
```

**Get which groups a group is member of**
```bash
az ad group get-member-groups -g "<group-name>"
```

**Get roles assigned to the group in Azure (NOT in Entra ID)**
```bash
az role assignment list --include-groups --include-classic-administrators true --assignee <group-id>
```


List users group membership
```powershell
Get-MgUserMemberOf -userid "user@domain.com" | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}
```

Get objectID from group name
```bash
az ad group show --group "My Group Display Name" --query id --output tsv
```

```powershell
(Get-MgGroup -Filter "DisplayName eq 'My Group Display Name'").Id
```

get custom role defenitions (list all properties)
```bash
az role definition list --custom-role-only true --query "[?roleName=='Role Name']" -o json
```



#### GraphRunner.ps1

Enum Dynamic Groups

```powershell
Get-DynamicGroups -Tokens $tokens
```

Enum groupd ID 

```powershell
Get-SecurityGroups -Tokens $tokens
```

Enum UserID

```powershell
Get-UserObjectID -Tokens $tokens user.one@domain.com
```

Add user to group

```powershell
Invoke-AddGroupMember -groupId <groupid> -userId <userid>
```

#### BARK
https://github.com/BloodHoundAD/BARK

Enumerate Entra groups and info about them

```powershell
$Groups = Get-AllEntraGroups
$Group = $Groups | Where-Object { $_.DisplayName -eq "<interesting group>" }
$Group
```



### Interesting Groups
---
#### Directory Readers
- Allows Entra enumeration 

