---
tags:
  - AD
---

## Remote
---
Multi-Protocol
```bash
enum4linux -a <IP>
```
**SMB**
```bash
nxc smb <IP> -u '' -p '' --users
```
**RPC**
```bash
rpcclient -U "" -N <IP>
enumdomusers
```
```PowerShell
queryuser 0x457 <---user RID
```
ldap
```bash
ldapsearch -x -b "DC=HTB,DC=LOCAL" -s sub "(&(objectclass=user))" -H ldap://<IP> | grep -i samaccountname: | cut -f 2 -d " "
```
```bash
nxc ldap <IP> -u '' -p '' --users    
```
```PowerShell
python3 windapsearch.py --dc-ip <dcip> -u user@domain -p 'pass' --da
```
```PowerShell
python3 windapsearch.py --dc-ip <dcip> -u user@domain -p <pass> -PU
```
**Check logged in users**
```PowerShell
nxc smb <IP> -u '' -p '' --loggedon-users
```
## Brute force usernames
---
```Python
kerbrute userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.175
```
### Generate userlists
---
**Username Anarchy**
```Python
sudo apt install ruby -y
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
```
```Bash
./username-anarchy Jane Smith > jane_smith_usernames.txt
```
## Validate Known Usernames
---
```C
kerberute userenum -d <DOMAIN> users.txt
```

!!! alert "Add a known negative user to make sure the server is properly validating."