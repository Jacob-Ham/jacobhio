___

## Domain Information

```powershell
# View information about the current domain
.\SharpView.exe Get-Domain

# View the domain password policy
Get-DomainPolicy

# View a list of domain trusts
Get-DomainTrust

# Enumerate trusts for our domain/reachable domains
Get-DomainTrustMapping
```

## User Enumeration

```powershell
# Count all domain users
(Get-DomainUser).count

# Find ASREPRoastable users
.\SharpView.exe Get-DomainUser -KerberosPreauthNotRequired

# Find users with SPNs set
.\SharpView.exe Get-DomainUser -SPN

# Find non-blank user description fields
Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}

# List all UAC values
Get-DomainUser harry.jones | ConvertFrom-UACValue -showall

# Find machines where domain users are logged in
Find-DomainUserLocation

# Find foreign domain users
Find-ForeignGroup
```

## SID/Username Conversion

```powershell
# Convert a username to a SID
.\SharpView.exe ConvertTo-SID -Name sally.jones

# Convert a SID to a username
.\SharpView.exe Convert-ADName -ObjectName S-1-5-21-2974783224-3764228556-2640795941-1724
```

## Group Enumeration

```powershell
# List domain groups
Get-DomainGroup -Properties Name

# Get members of a domain group
.\SharpView.exe Get-DomainGroupMember -Identity 'Help Desk'

# List protected groups
.\SharpView.exe Get-DomainGroup -AdminCount

# List managed security groups
.\SharpView.exe Find-ManagedSecurityGroups
```

## Computer Enumeration

```powershell
# Get a listing of domain computers
Get-DomainComputer

# Find computers that allow unconstrained delegation
.\SharpView.exe Get-DomainComputer -Unconstrained

# Find computers set with constrained delegation
Get-DomainComputer -TrustedToAuth
```

## Network & Shares

```powershell
# Enumerate open shares on a remote computer
.\SharpView.exe Get-NetShare -ComputerName SQL01

# Get local groups on a host
Get-NetLocalGroup -ComputerName WS01

# Get members of a local group
.\SharpView.exe Get-NetLocalGroupMember -ComputerName WS01
```

## Access Testing

```powershell
# Test local admin access on a remote host
Test-AdminAccess -ComputerName SQL01
```

## Organizational Units

```powershell
# List all OUs
.\SharpView.exe Get-DomainOU
```

## ACL Enumeration

```powershell
# Enumerate ACLs on a user
Get-DomainObjectAcl -Identity harry.jones

# Find objects in the domain with modification rights over non built-in objects
Find-InterestingDomainAcl

# Find the ACLs set on a directory
Get-PathAcl "\\SQL01\DB_backups"
```

## Group Policy Objects (GPO)

```powershell
# List all GPO names
.\SharpView.exe Get-DomainGPO | findstr displayname

# List GPOs on a specific host
Get-DomainGPO -ComputerIdentity WS01

# Get a report of all GPOs applied to a host
gpresult /r /S WS01

# Find GPO permissions
Get-DomainGPO | Get-ObjectAcl
```

## Help & Documentation

```powershell
# Get help about a SharpView function
.\SharpView.exe Get-DomainUser -Help
```