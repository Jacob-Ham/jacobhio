---
tags:
  - Authenticated
  - Bloodhound
  - DACL
  - PingCastle
  - Privilege-Escalation
  - AD
---
## Bloodhound
---
**Remote ingestion**
```C
nxc ldap <IP> -u <user> -p <pass> --bloodhound --collection All --dns-server <DC-IP>
```
```C
bloodhound-python -c All -u <user> -p <pass> -d domain.local -ns <dc-ip>
```
```PowerShell
sudo bloodhound-python -u 'user' -p 'pass' -ns <dc-ip> -d domain.local -c all 
```

**Local Ingestion**
```C
SharpHound.exe --CollectionMethods All
```
```C
Invoke-BloodHound -CollectionMethod All
```
cypher queries

```Plain
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

```Plain
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

## powerview.py (remote)
---
[https://github.com/aniqfakhrul/powerview.py](https://github.com/aniqfakhrul/powerview.py)

Run powerview functions remotely over a persistent ldap bind.

CLI:
```bash
powerview range.net/lowpriv:Password123@192.168.86.192 --dc-ip 192.168.86.192 
```
Web & Cli
```bash
powerview range.net/lowpriv:Password123@192.168.86.192 --web --web-host 0.0.0.0 --web-port 3000 --web-auth user:password1234
```

## **PowerView/Sharpview** (local)
---
[https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)


| **Command**                         | **Description**                                                                            |
| ----------------------------------- | ------------------------------------------------------------------------------------------ |
| `Export-PowerViewCSV`               | Append results to a CSV file                                                               |
| `ConvertTo-SID`                     | Convert a User or group name to its SID value                                              |
| `Get-DomainSPNTicket`               | Requests the Kerberos ticket for a specified Service Principal Name (SPN) account          |
| **Domain/LDAP Functions:**          |                                                                                            |
| `Get-Domain`                        | Will return the AD object for the current (or specified) domain                            |
| `Get-DomainController`              | Return a list of the Domain Controllers for the specified domain                           |
| `Get-DomainUser`                    | Will return all users or specific user objects in AD                                       |
| `Get-DomainComputer`                | Will return all computers or specific computer objects in AD                               |
| `Get-DomainGroup`                   | Will return all groups or specific group objects in AD                                     |
| `Get-DomainOU`                      | Search for all or specific OU objects in AD                                                |
| `Find-InterestingDomainAcl`         | Finds object ACLs in the domain with modification rights set to non-built in objects       |
| `Get-DomainGroupMember`             | Will return the members of a specific domain group                                         |
| `Get-DomainFileServer`              | Returns a list of servers likely functioning as file servers                               |
| `Get-DomainDFSShare`                | Returns a list of all distributed file systems for the current (or specified) domain       |
| **GPO Functions:**                  |                                                                                            |
| `Get-DomainGPO`                     | Will return all GPOs or specific GPO objects in AD                                         |
| `Get-DomainPolicy`                  | Returns the default domain policy or the domain controller policy for the current domain   |
| **Computer Enumeration Functions:** |                                                                                            |
| `Get-NetLocalGroup`                 | Enumerates local groups on the local or a remote machine                                   |
| `Get-NetLocalGroupMember`           | Enumerates members of a specific local group                                               |
| `Get-NetShare`                      | Returns open shares on the local (or a remote) machine                                     |
| `Get-NetSession`                    | Will return session information for the local (or a remote) machine                        |
| `Test-AdminAccess`                  | Tests if the current user has administrative access to the local (or a remote) machine     |
| **Threaded 'Meta'-Functions:**      |                                                                                            |
| `Find-DomainUserLocation`           | Finds machines where specific users are logged in                                          |
| `Find-DomainShare`                  | Finds reachable shares on domain machines                                                  |
| `Find-InterestingDomainShareFile`   | Searches for files matching specific criteria on readable shares in the domain             |
| `Find-LocalAdminAccess`             | Find machines on the local domain where the current user has local administrator access    |
| **Domain Trust Functions:**         |                                                                                            |
| `Get-DomainTrust`                   | Returns domain trusts for the current domain or a specified domain                         |
| `Get-ForestTrust`                   | Returns all forest trusts for the current forest or a specified forest                     |
| `Get-DomainForeignUser`             | Enumerates users who are in groups outside of the user's domain                            |
| `Get-DomainForeignGroupMember`      | Enumerates groups with users outside of the group's domain and returns each foreign member |
| `Get-DomainTrustMapping`            | Will enumerate all trusts for the current domain and any others seen.                      |



```PowerShell
Get-DomainUser -Identity <username> -Domain <domain.local> | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```
```PowerShell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```
```PowerShell
Get-DomainTrustMapping
```
```PowerShell
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```
```PowerShell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```
## Powershell
---
```PowerShell
Get-Module
```
```PowerShell
Import-Module ActiveDirectory
```
```PowerShell
Get-ADDomain
```
```PowerShell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
```PowerShell
Get-ADTrust -Filter *
```
```PowerShell
Get-ADGroup -Filter * | select name
Get-ADGroup -Identity "Backup Operators"
Get-ADGroupMember -Identity "Backup Operators"
```
  
## Raw LDAP
---
```Python
ldapsearch -x -b "DC=EGOTISTICAL-BANK,DC=LOCAL" -H ldap://10.10.10.175
```