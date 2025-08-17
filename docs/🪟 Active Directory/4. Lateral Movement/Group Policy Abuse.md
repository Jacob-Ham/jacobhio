---
tags:
  - AD
---

## Identify
---
```Bash
Get-GPO -All | Select DisplayName
```
**Check if group has control**
```Bash
$sid=Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```
**Converting GPO GUID to Name**
```Bash
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```
**group3r**
[https://github.com/Group3r/Group3r](https://github.com/Group3r/Group3r)
```Bash
group3r.exe -f <filepath-name.log> 
```
### In BloodHound
---
Checking in BloodHound, we can see that the `Domain Users` group has several rights over the `Disconnect Idle RDP` GPO, which could be leveraged for full control of the object.

If we select the GPO in BloodHound and scroll down to `Affected Objects` on the `Node Info` tab, we can see that this GPO is applied to one OU, which contains four computer objects.


# Exploit
---
https://github.com/FSecureLABS/SharpGPOAbuse
We could use a tool such as SharpGPOAbuse to take advantage of this GPO misconfiguration by performing actions such as adding a user that we control to the local admins group on one of the affected hosts, creating an immediate scheduled task on one of the hosts to give us a reverse shell, or configure a malicious computer startup script to provide us with a reverse shell or similar.