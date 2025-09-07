___
Default is 10 for domain users, this makes RBCD and kerberos relay attacks significantly easier to exploit and is worth reporting.

### Identify

with nxc
```bash
nxc ldap <ip> -u user -p pass -M maq
```

with powerview
```powershell
Get-DomainPolcy -Policy DC -domain <domain> | Select-Object -ExpandProperty PrivilegeRights | select seMachineAccountPrivilege
ConverFrom-SID <SID>
```

with powershell
```powershell
Get-ADObject ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
```

ldapsearch

```bash
ldapsearch -x -H ldap://<dcip> -b "DC=example,DC=local" ms-DS-MachineAccountQuota
```

---
### **What now?**
- [Resource-Based Constrained Delegation](../4.%20Lateral%20Movement/Resource-Based%20Constrained%20Delegation.md)

