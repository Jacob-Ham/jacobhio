---
tags:
  - "#type/technique"
  - "#tactic/TA0007"
  - "#technique/T1557001"
  - "#stage/reconnaissance"
  - "#stage/lateral-movement"
  - "#os/windows"
  - "#protocol/smb"
  - "#tool/nmap"
  - "#tool/netexec"
  - "#tool/bloodhound"
  - "#tool/powerview"
  - privileges/unauthenticated
aliases:
  - SMB Relay Attack
  - SMB Signature Verification
  - NTLM Relay to SMB
---
## Technique
___
SMB (Server Message Block) signing is a security feature that digitally signs SMB packets, allowing recipients to verify the sender's identity and message integrity. When SMB signing is not enforced, attackers can perform man-in-the-middle attacks by intercepting and modifying SMB traffic without detection.

Identifying systems with SMB signing disabled is a critical reconnaissance step before performing NTLM relay attacks. In these attacks, an attacker captures authentication traffic from one system and relays it to another system where SMB signing is not enforced, effectively impersonating the victim and potentially gaining unauthorized access with their privileges.

This technique is particularly dangerous in Active Directory environments where service accounts or administrative users might be coerced into authenticating to attacker-controlled systems, allowing for lateral movement and privilege escalation.

## Prerequisites
___

**Access Level:** 
- Unauthenticated network access for basic enumeration
- Domain user credentials for more comprehensive scanning (optional)

**System State:** 
- Target systems with SMB services accessible (TCP port 445)
- Network connectivity to potential target systems

**Tools Required:**
- Network scanning tools (Nmap, NetExec)
- Domain enumeration tools for authenticated scanning (PowerView)
- BloodHound for visualizing attack paths (optional)

## Considerations
___

**Impact**

Discovering systems with SMB signing disabled can lead to:
- Lateral movement across the network by relaying authentication
- Privilege escalation if high-privilege account credentials are relayed
- Domain compromise if Domain Admin credentials are captured and relayed
- Access to sensitive file shares and systems without direct authentication

**OPSEC**

- Scanning large IP ranges for SMB signing status may generate significant network traffic
- Multiple failed SMB connections might trigger security alerts
- Authenticated scans will create login events that could be monitored
- Using domain credentials creates trackable authentication events

## Execution
___

### Unauthenticated Enumeration

**Using Nmap:**
```bash
# Scan a single host
sudo nmap -p 445 --script=smb-security-mode.nse <target-ip>

# Scan an entire subnet
sudo nmap -p 445 --script=smb-security-mode.nse <target-ip/range>
```

**Using NetExec (formerly CrackMapExec):**
```bash
# Scan a subnet and generate a list of hosts with SMB signing disabled
nxc smb <subnet> --gen-relay-list nosigning.txt
```

**Using [auth.py](https://github.com/Jacob-Ham/auth) tool:**
```bash
# Quick check of SMB signing status
auth smb <subnet>
```

### Authenticated Enumeration

**Setup a domain context:**
```cmd
# Create a new command prompt with domain credentials
runas /netonly /user:domain\username cmd.exe

# Start PowerShell with script execution
powershell -ep bypass
```

**Using PowerView to identify targets:**
```powershell
# Import PowerView
. .\PowerView.ps1

# Export list of domain computers to a file
Get-DomainComputer -Properties dnshostname | Select-Object -ExpandProperty dnshostname | Out-File -FilePath computers.txt
```

**Scan the exported computers:**
```bash
# Use NetExec to check SMB signing status
nxc smb computers.txt --gen-relay-list vulnerable_hosts.txt
```

### Using BloodHound

**Query for vulnerable systems:**
```cypher
# Find computers with SMB signing disabled
MATCH (n:Computer)
WHERE n.smbsigning = False
RETURN n

# Find attack paths to high-value targets through computers with SMB signing disabled
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name: "DOMAIN ADMINS@DOMAIN.LOCAL"}))
MATCH (c:Computer {smbsigning: False})
RETURN p, c
```

### Cleanup Considerations

- Remove any generated files containing lists of vulnerable systems
- Clear command history that might contain scanning commands
- Log out of any authenticated sessions created for enumeration

## Detection & Mitigation
___

### Detection

- Monitor for port scans targeting TCP/445 across multiple systems
- Watch for unusual SMB traffic patterns and connection attempts
- Look for authentication attempts from unexpected source systems
- Monitor for Event ID 4624 (successful logon) from administrative accounts on unusual systems
- Set up honeypot systems with SMB signing disabled to detect scanning activity

### Mitigation

**Enable and Enforce SMB Signing:**
```powershell
# Server-side registry settings
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord

# Client-side registry settings
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
```

**Group Policy Settings:**
- Configure "Microsoft network server: Digitally sign communications (always)" to Enabled
- Configure "Microsoft network client: Digitally sign communications (always)" to Enabled

**Additional Mitigations:**
- Disable NTLM authentication where possible in favor of Kerberos
- Upgrade to SMB 3.0+ which has enhanced security features
- Disable SMBv1 which lacks modern security protections
- Implement network segmentation to limit the impact of relay attacks
- Use Extended Protection for Authentication (EPA) where available
