---
tags:
  - AD
---


run powershell with admin rights
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
```
```
gpupdate /force
```
Reboot box