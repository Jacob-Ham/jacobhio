---
tags:
  - "#type/technique"
  - "#tactic/TA0007"
  - "#technique/T1059"
  - "#stage/reconnaissance"
  - "#stage/discovery"
  - "#os/windows"
  - "#os/linux"
  - "#tool/bloodhound"
  - "#tool/sharphound"
  - "#tool/bloodhound-python"
  - "#tool/nxc"
aliases:
  - AD Enumeration
  - Graph Analysis
  - Attack Path Mapping
---
## Technique
___
BloodHound is a powerful Active Directory reconnaissance tool that uses graph theory to reveal hidden and often unintended relationships within an Active Directory environment. It collects data about users, computers, groups, access control lists, sessions, and trusts through LDAP queries and other methods, then presents this information visually in a graph database.

The tool can discover non-obvious attack paths that might otherwise go unnoticed during manual enumeration. These paths often lead to privilege escalation opportunities, including paths to Domain Admin or other highly privileged groups. BloodHound allows attackers to quickly identify the most efficient path to their target, reducing the risk of detection by minimizing unnecessary actions.

## Prerequisites
___

**Access Level:** A valid Active Directory domain account, typically with standard user privileges. No special or elevated privileges are required for basic collection.

**System State:** 
- **Windows Collection**: Access to a domain-joined Windows machine for SharpHound collection
- **Linux Collection**: Network connectivity to Domain Controllers from a Linux machine

**Environment Requirements:**
- Neo4j database (for data storage and visualization)
- BloodHound GUI application (for data analysis)
- SharpHound or BloodHound Python (for data collection)

```bash
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz

tar -xvzf bloodhound-cli-linux-amd64.tar.gz

./bloodhound-cli install
```

## Considerations
___

**Impact**

BloodHound provides a comprehensive map of the Active Directory environment, revealing paths to privileged access that might otherwise remain hidden. This can significantly accelerate privilege escalation and lateral movement operations.

**OPSEC**

- **Collection Noise:** SharpHound performs numerous LDAP, SMB, and WMI queries which may trigger detection systems. These queries might appear suspicious, especially if many are made in a short period.

- **File Creation:** SharpHound creates multiple JSON files that could be detected by endpoint protection.

- **LDAP Traffic:** Remote collection using BloodHound Python generates significant LDAP traffic to domain controllers, which may appear in security logs.

- **Session Enumeration:** Collecting session data requires touching each computer in the domain, which can generate alerts.

## Execution
___
### Collection (from Linux)

#### **BloodHound Python**

Collect all data:
```bash
bloodhound-python -c All -u 'username' -p 'password' -d domain.local -ns 10.10.10.10
```

Collect specific data:
```bash
bloodhound-python -c Domain,LocalAdmin -u 'username' -p 'password' -d domain.local -ns 10.10.10.10
```

Use LDAPS:
```bash
bloodhound-python -c All -u 'username' -p 'password' -d domain.local -ns 10.10.10.10 --use-ldaps
```

#### **NetExec**

```bash
nxc ldap 10.10.10.10 -u 'username' -p 'password' --bloodhound --collection All --dns-server 10.10.10.10
```

### Collection (from Windows)

#### **SharpHound (C# Binary)**

Full collection:
```powershell
SharpHound.exe --CollectionMethods All
```

Stealth collection:
```powershell
SharpHound.exe --CollectionMethods DCOnly --Stealth
```

Specific collection with output:
```powershell
SharpHound.exe --CollectionMethods Session,Trusts --OutputDirectory C:\Temp
```

#### **PowerShell Module**

Import and run:
```powershell
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
```

Stealth collection:
```powershell
Invoke-BloodHound -CollectionMethod DCOnly -Stealth
```

### BloodHound Data Analysis

https://queries.specterops.io/

#### **Common Cypher Queries**

Find all Domain Admins:
```cypher
MATCH (n:Group) WHERE n.name =~ ".*DOMAIN ADMINS.*" RETURN n
```

Find paths to Domain Admins:
```cypher
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p
```

Find Kerberoastable users:
```cypher
MATCH (u:User {hasspn:true}) RETURN u
```

Find high-value targets:
```cypher
MATCH (u:User) WHERE u.highvalue=true RETURN u
```

Find computers where Domain Admins are logged in:
```cypher
MATCH p=(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}), (c:Computer)-[:HasSession]->(u) RETURN c.name, u.name
```

Find PS Remoting paths:
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) 
MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) 
RETURN p2
```

Find SQL Admin paths:
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) 
MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) 
RETURN p2
```

### Collection Methods Explained

- **Default**: Basic data collection (Container, Group, LocalGroup, GPOLocalGroup, Session, Trusts)
- **All**: All collection methods except RDP, DCOM, and LocalAdmin
- **DCOnly**: Collects data only from Domain Controllers (reduced footprint)
- **ObjectProps**: Object properties (description, email, title, etc.)
- **ACL**: Permission relationships between objects
- **Group**: Group membership information
- **LocalAdmin**: Finds local administrator information
- **Session**: User session information
- **Trusts**: Domain and forest trust relationships
- **Container**: Organizational Units and containers
- **GPOLocalGroup**: Local group memberships through GPOs
- **LoggedOn**: Currently logged-on users (requires admin)
- **ComputerOnly**: Just computer objects

### Cleanup Considerations

- Delete SharpHound JSON files after importing
- Clear SharpHound logs (located in the output directory)
- Remove any SharpHound binaries or PowerShell modules
- Avoid leaving the Neo4j database accessible to unauthorized users

### Detection & Mitigation

#### Detection

- Monitor for SharpHound-specific files (group_membership.json, local_admins.json, etc.)
- Watch for numerous LDAP queries in a short timeframe, especially those querying for all objects
- Look for automated collection of computer account information
- Monitor for suspicious binaries or PowerShell imports (SharpHound.ps1, SharpHound.exe)
- Event ID 4662 (operation performed on AD object) with unusual query patterns

#### Mitigation

- **Network Segmentation**: Implement proper tiered administration models
- **Just-In-Time Administration**: Use temporary privileges instead of permanent ones
- **Remove Excessive Privileges**: Regularly audit and remove unnecessary access rights
- **Protected Users Security Group**: Place sensitive accounts in this group to limit credential exposure
- **Regular BloodHound Audits**: Run BloodHound proactively to identify and mitigate attack paths
- **Monitor Service Accounts**: Ensure service accounts don't have excessive privileges
- **Implement PAWs**: Use Privileged Access Workstations for administrative tasks