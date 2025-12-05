---
tags:
  - type/technique
  - tactic/reconnaissance
  - technique/password-policy
  - service/active-directory
  - os/windows
  - os/linux
  - tool/nxc
  - tool/rpcclient
  - tool/enum4linux
  - tool/powerview
---

## Technique
___
Password Policy Enumeration is a reconnaissance technique used to discover the password requirements and account lockout settings enforced in an Active Directory domain. This information helps attackers craft more effective password attacks by understanding complexity requirements, lockout thresholds, and reset timers.

## Prerequisites
___
**From Windows:** Domain-joined machine or network access to domain controller.

**From Linux:** Network access to domain controller with valid credentials or null session capability.

## Execution
___

### From Windows

#### Command Line
```batch
# View domain password policy
net accounts /domain
```

#### PowerShell
```powershell
# Using native PowerShell
(Get-ADDefaultDomainPasswordPolicy).MinPasswordLength
(Get-ADDefaultDomainPasswordPolicy).LockoutThreshold
(Get-ADDefaultDomainPasswordPolicy) | Format-List
```

#### PowerView
```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Get domain password policy
Get-DomainPolicy

# View the details
(Get-DomainPolicy)."System Access"
```

### From Linux

#### NetExec (formerly CrackMapExec)
```bash
# With valid credentials
nxc smb 192.168.1.10 -u username -p password --pass-pol

# With null session (if allowed)
nxc smb 192.168.1.10 -u '' -p '' --pass-pol
```

#### RPCClient
```bash
# Connect with null session (if allowed)
rpcclient -U "" -N 192.168.1.10

# Connect with credentials
rpcclient -U "domain/username%password" 192.168.1.10

# Query domain information
rpcclient $> querydominfo

# Get password policy
rpcclient $> getdompwinfo
```

#### Enum4Linux
```bash
# Query password policy specifically
enum4linux -P 192.168.1.10

# Full enumeration including password policy
enum4linux -a 192.168.1.10
```

#### LDAP Tools
```bash
# Using ldeep
ldeep ldap -u 'username' -p 'password' -d 'domain.local' -s 192.168.1.10 domain_policy

# Using ldapsearch
ldapsearch -x -h 192.168.1.10 -D "domain\\username" -w "password" -b "DC=domain,DC=local" "(objectClass=domainDNS)" | grep -i pwdproperties
```

#### Impacket
```bash
# Using impacket-GetADPolicyInfo
impacket-GetADPolicyInfo -dc-ip 192.168.1.10 'domain/username:password'
```

## Considerations
___

**Important Policy Settings**
- Minimum password length
- Password complexity requirements
- Password history count
- Maximum password age
- Account lockout threshold
- Account lockout duration
- Account lockout observation window

**OPSEC**
- Most of these techniques generate minimal logs as they use standard protocols and queries
- RPCClient and LDAP queries appear as normal directory service activity
- Windows command line tools generate standard user activity logs

## Detection & Mitigation
___

**Detection**
- Monitor for multiple policy queries from the same source in a short time
- Watch for non-admin accounts querying domain policies
- Look for policy queries from non-domain-joined machines

**Mitigation**
- Restrict null sessions
- Implement proper access controls for domain policy information
- Use dedicated admin workstations for policy management
- Audit and monitor access to domain controllers