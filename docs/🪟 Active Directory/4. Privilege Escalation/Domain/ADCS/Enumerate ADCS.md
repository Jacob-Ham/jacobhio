---
tags:
  - Authenticated
  - Certificate-Service
  - Privilege-Escalation
  - AD
---
## Identify
---
### From Windows
**Check if “Cert Publishers” group exists (checks if ADCS is enabled)**
```C
net localgroup "Cert Publishers"
```
**Use cerify.exe**
```C
.\Certify.exe find /vulnerable
```
Powershell
```C
Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2) (pkiextendedkeyusage=1.3.6.1.5.2.3.4))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase 'CN=Configuration,DC=Domain,DC=local'
```
### From Linux
**NetExec**
```C
nxc ldap <IP> -u "user" -p "Password123!" -M adcs
```
**ldap**
```bash
ldapsearch -x -D "CN=svc-ldapuser,CN=Users,DC=certified,DC=htb" -w 'SuperSecretPass' -b "DC=certified,DC=htb" "(&(objectClass=pKIEnrollmentService))" -H ldap://10.129.229.25
```
**Certipy**
```C
certipy-ad find -u 'user@domain.local' -p 'Password123!' -dc-ip <IP> -vulnerable -stdout
```
## Exploit
---

- [ESC1](ESC1.md)


