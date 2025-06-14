---
tags:
  - AD
---

## **From Linux**
---
```Bash
nxc smb 172.16.5.5 -u <user> -p password> --pass-pol
```
```Bash
rpcclient -U "" -N <target-ip>
rpcclient -U "username" <target-ip>
rpcclient $> querydominfo
```
```Bash
enum4linux -P <target-ip>
```
```bash
ldeep ldap -u 'USER' -p "PASS' -d 'domain.local' -s $IP domain_policy
```
## From Windows
---
```batch
net accounts
```
**PowerView**
```powershell
Get-DomainPolicy
```
