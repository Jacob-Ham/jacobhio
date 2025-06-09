---
tags:
  - Authenticated
  - OPSEC
  - AD
---
## Identify
---
## Windows Defender
---
```Python
Get-MpComputerStatus
```
If RealTimeProtection: True, we have defender enabled
## **AppLocker**
---
```PowerShell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

!!! alert "note"
	Organizations often block the `PowerShell.exe` executable, but forget about the other [PowerShell executable locations](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`
## **PowerShell Constrained Language Mode**
---
Will prevent tons of useful powershell features
```PowerShell
$ExecutionContext.SessionState.LanguageMode
```
## LAPS
---
[https://github.com/leoloobeek/LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)
Can help us find ADUsers that have permissions to read LAPS passwords
```PowerShell
Find-LAPSDelegatedGroups
```
The Find-AdmPwdExtendedRights checks the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights." Users with "All Extended Rights" can read LAPS passwords and may be less protected than users in delegated groups, so this is worth checking for.
```PowerShell
Find-AdmPwdExtendedRights
```
Find computers with laps enabled
```PowerShell
Get-LAPSComputers
```