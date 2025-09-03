---
tags:
  - Authenticated
  - Lateral-Movement
  - Privilege-Escalation
  - AD
---
## Identify
---
- **Domain Admins**
    - Full control of the domain and can manage all resources in the domain.
- **Enterprise Admins**
    - This group exists in the root domain of a forest and has full rights to administer any domain within the forest.
- **Schema Admins**
    - Members can modify the AD schema, which affects the entire forest. This group should have no permanent members unless schema changes are being made.
- **Administrators** (Built-in)
    - By default, this group has wide-ranging administrative privileges on a domain controller.
- **Server Operators**
    - Members can log on to domain controllers, start/stop services, format hard drives, and perform other significant administrative tasks.
- **Backup Operators**
    - Members can bypass file permissions to back up and restore files across the domain controller. This often grants access to sensitive data.
- **Account Operators**
    - Members can create, modify, and delete most user and group accounts (except for certain high-privilege groups), making them powerful with regard to identity management.
- **DNS Admins**
    - Members manage DNS servers, which control name resolution. A compromise here can enable attacks like DNS poisoning or redirection.
- **Key Admins & Enterprise Key Admins**
    - Introduced in newer versions of Active Directory Certificate Services (AD CS); these groups can manage public key infrastructure (PKI) objects and certificate authorities.
- **Exchange Organization Management** (if Microsoft Exchange is installed)
    - Members can administer all Exchange resources and mailboxes, with significant access to messaging data.
  
## Exploit
---

## **Backup Operators**
**Remote**
```bash
nxc smb <target> -u '' -p '' -M backup_operator
```
Get machine account hash and dump ntds with that.
```bash
nxc smb 172.16.210.5 -u 'DC01$' -H <MachineAccHash> --ntds --user Administrator
```

## **Exchange Groups**

[https://github.com/gdedrouas/Exchange-AD-Privesc](https://github.com/gdedrouas/Exchange-AD-Privesc)

**Exchange Windows Permissions**

- members are granted the ability to write a DACL to the domain object. This can be leveraged to give a user DCSync privileges.

**Organization Management**

- access the mailboxes of all domain users. It is not uncommon for sysadmins to be members of this group. This group also has full control of the OU called Microsoft Exchange Security Groups, which contains the group Exchange Windows Permissions.