---
tags:
  - AD
---

## Share Enumeration
---
```PowerShell
nxc smb <ip> -u '' -p '' --shares
```
```PowerShell
nxc smb <ip> -u '' -p '' -M spider_plus --share 'sharename'
```
```PowerShell
smbmap -u <user> -p <pass> -d <domain> -H <ip>
```
```PowerShell
smbmap -u <user> -p <pass> -d <domain> -H <ip> -R 'sharename' --dir-only
```

