---
tags:
  - AD
---

## Explainer
---
If you’re accessing a resource with network authentication, like winrm, your creds may not be cached in memory. Because of this, actions you take that you have permissions to take may be denied. The DC cannot recognize your access rights.
## Workarounds
---
### 1. Use Invoke-Command to pass a PSCredential object with every request
---
```Bash
$SecPassword = ConvertTo-SecureString 'password' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\user', $SecPassword)
```
```Bash
Import-Module powerview.ps1
get-domainuser -spn -credential $Cred | select samaccountname
```
### 2. **Register PSSession Configuration (from windows)**
---
```Bash
Register-PSSessionConfiguration -Name <namethesessionyhere> -RunAsCredential domain\user
```
```Bash
Restart-Service WinRM
```
```Bash
Enter-PSSession -ComputerName computer01 -Credential domain\user -ConfigurationName <whateveryouanemdthesession>
```

> [!important] Note: We cannot use Register-PSSessionConfiguration from an evil-winrm shell because we won't be able to get the credentials popup. Furthermore, if we try to run this by first setting up a PSCredential object and then attempting to run the command by passing credentials like -RunAsCredential $Cred, we will get an error because we can only use RunAs from an elevated PowerShell terminal.