---
tags:
  - "#type/technique"
  - "#tactic/TA0007"
  - "#technique/T1021.002"
  - "#stage/reconnaissance"
  - "#protocol/smb"
  - "#os/windows"
  - "#tool/netexec"
  - "#tool/enum4linux"
  - privileges/unauthenticated
aliases:
  - Null Session
  - Anonymous SMB Access
  - Unauthenticated Enumeration
---

## Technique
___
Null session refers to an unauthenticated connection to a Windows machine or domain controller where no username or password is provided. This technique allows attackers to potentially enumerate sensitive information about the target network, including user accounts, shares, groups, and policies without authentication credentials.

Microsoft originally designed SMB and NetBIOS services to be open and accessible for ease of use in network environments, allowing unauthenticated users to query for certain information. While modern Windows systems have significantly restricted this access by default, misconfigured or legacy systems may still permit null sessions, creating a serious security risk.

Successful null session exploitation can provide valuable information for further attacks, including user enumeration for password spraying, service enumeration, and discovery of network resources. This represents a critical initial reconnaissance technique in the attack chain against Active Directory environments.

## Prerequisites
___

**Access Level:** No authentication required, only network connectivity to target systems.

**System State Requirements:**
- Target system with SMB services (TCP/445) or NetBIOS services (TCP/139) exposed
- Misconfigured Windows security policy that allows anonymous access
- Network connectivity to the target domain controllers or member servers

**Environment Setup:**
- Configure DNS to prioritize domain controllers

```
echo "nameserver <DC-IP>" > /etc/resolv.conf
```

- Same network segment as the target (or ability to route to SMB/LDAP services)
- Tools installed: `enum4linux-ng`, `smbclient`, `nxc` (NetExec), `ldapsearch`

**Identifying Domain Controllers:**
```bash
# Using DNS SRV records
nslookup -type=SRV _ldap._tcp.domain.local

# Using nltest (windows)
nltest /dclist:yourdomain.com

# Using nmap
nmap -p 53,88,389 --open <IP-RANGE> -oG - | grep -i open
```

## Execution
___

### Testing for Null Sessions

**SMB Enumeration:**

```bash
# Check for null session access on a single host
smbclient -N -L \\\\<DC-IP>

# Check multiple DCs from a list
for dc in $(cat dcs.txt); do echo $dc && smbclient -N -L \\\\$dc; done

# Using NetExec (formerly CrackMapExec)
nxc smb <DC-IP> -u '' -p ''

# Using auth.py tool
auth smb dcs.txt
```

**LDAP Enumeration:**

```bash
# Anonymous LDAP bind
ldapsearch -x -h <DC-IP> -b "DC=domain,DC=local" -s sub "(objectClass=*)" | grep -i "cn:"

# Check if anonymous LDAP bind is possible
nxc ldap <DC-IP> -u '' -p ''
```

### Exploiting Null Sessions

**User Enumeration:**

```bash
# Using enum4linux-ng
enum4linux-ng -U <DC-IP>

# Using rpcclient
rpcclient -U "" -N <DC-IP>
rpcclient $> enumdomusers
rpcclient $> queryuser 0x3e8
```

**Group Enumeration:**

```bash
# Using enum4linux-ng
enum4linux-ng -G <DC-IP>

# Using rpcclient
rpcclient -U "" -N <DC-IP>
rpcclient $> enumdomgroups
rpcclient $> querygroup 0x200
```

**Share Enumeration:**

```bash
# Using enum4linux-ng
enum4linux-ng -S <DC-IP>

# Using smbmap
smbmap -H <DC-IP> -u '' -p ''
```

**Domain Policy Enumeration:**

```bash
# Using enum4linux-ng
enum4linux-ng -P <DC-IP>

# Using rpcclient
rpcclient -U "" -N <DC-IP>
rpcclient $> getdompwinfo
```

> [!NOTE] Note
> Anonymous login doesn't always mean useful enumeration is possible. Always attempt to extract actionable information to demonstrate impact. The most valuable targets are user lists, password policies, and accessible shares.


## Detection & Mitigation
___

### Detection

- Monitor for anonymous/null session connections to domain controllers and member servers
- Look for Event IDs related to anonymous logons:
  - Windows Security Log Event ID 4624 (Type 3 logon) with blank username
  - Event ID 4625 failures when null sessions are blocked
- Track SMB traffic patterns showing enumeration attempts from untrusted sources
- Implement honeypot accounts and monitor for enumeration attempts

### Mitigation

**Windows Registry Settings:**
```powershell
# Disable null sessions on Windows Server
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RestrictAnonymous" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RestrictAnonymousSAM" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1
```

**Group Policy Settings:**
- Configure "Network access: Do not allow anonymous enumeration of SAM accounts" to Enabled
- Configure "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to Enabled
- Configure "Network access: Restrict anonymous access to Named Pipes and Shares" to Enabled
- Configure "Network access: Let Everyone permissions apply to anonymous users" to Disabled

**Network-Level Controls:**
- Implement proper network segmentation
- Use firewalls to restrict SMB/LDAP access to authenticated systems only
- Deploy SMB signing requirements across the domain
- Consider disabling SMBv1 which is more vulnerable to various attacks

**Monitoring:**
- Implement continuous monitoring for anonymous connection attempts
- Set up alerts for successful null session authentications
- Regularly audit domain controllers for proper security configurations
