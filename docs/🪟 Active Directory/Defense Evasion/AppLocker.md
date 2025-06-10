---
tags:
  - AD
---
AppLocker is a built-in Windows feature that enables application whitelisting. It controls which applications and scripts can run on a computer by enforcing policies delivered via Group Policy. Rules are defined using file properties such as publisher, name, version, hash, or path and can be configured to either allow or block execution. These rules can be applied to specific users or groups.

**List AppLocker rules**
```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

