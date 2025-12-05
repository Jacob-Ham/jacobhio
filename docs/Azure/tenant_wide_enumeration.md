
## azurehound
---
Bloodhound for azure, graph theory bla bla bla

Ingestor:
```bash
azurehound -r "<refreshtoken>" list --tenant "domain.com" -o out.json
```
or
```bash
azurehound -j "<accesstoken>" list --tenant "domain.com" -o out.json
```
or
```bash
azurehound -u "<username>" -p "<password>" list --tenant "domain.com" -o out.json
```

#### Cyphers

identify and return all relationships involving Azure Service Principals
```cypher
MATCH p = (g:AZServicePrincipal)-[r]->(n) RETURN p
```

display shortest path to managed identity
```cypher
MATCH (u:AZUser), (m:AZServicePrincipal {serviceprincipaltype: 'ManagedIdentity'}) MATCH p = shortestPath((u)-[*..]->(m)) RETURN p
```

> [!NOTE] BloodHound blind spots
> Azure role assignments that have been assigned at a subscription, management group, resource group, or individual resource level. Role memberships are not supported if scoped to an administrative unit. You CAN see these with the az cli, powershell Az, graph api
> https://github.com/SpecterOps/BloodHound-Legacy/issues/677

^^ or use [[#ROADRecon]] (still wont show admin roles scoped to admin unit)

**Work around this with shell:**

List administrative units
```powershell
Get-MgDirectoryAdministrativeUnit | f1
```

List scoped role members
```powershell
Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId <ObjectID> | Select-Object rolememberjInfo, roleId -ExpandProperty roleMemberInfo
```

Grab the object id and run
```powershell
Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId <ObjectID> | f1
```

Next? [[role_abuse]]

## ROADRecon
----
```bash
pipx install roadrecon
```

ROADRecon as a million auth methods:
```bash
roadrecon auth -h
```

> [!NOTE] OPSEC
> ROADRecon lets you specify a US with `--user-agent` to easily match a target environment

Gather info
```bash
roadrecon gather --user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.3'
```

Access UI
```bash
http://127.0.0.1:5000
```

