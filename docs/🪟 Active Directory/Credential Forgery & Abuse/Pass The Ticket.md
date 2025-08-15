---
tags:
  - Authenticated
  - Elevated
  - Kerberos
  - Lateral-Movement
  - AD
  - type/technique
  - tactic/TA0008
  - technique/T1550003
  - stage/lateral-movement
  - os/windows
  - tool/rubeus
  - tool/klist
aliases:
  - Pass the Ticket
  - PtT
  - Steal or Forge Kerberos Tickets
---
## Technique
___
Pass-the-Ticket (PtT) is a lateral movement technique that uses a stolen Kerberos ticket to authenticate to systems and access resources as the impersonated user. This attack bypasses the need to extract credentials from protected processes like LSASS, making it effective in hardened environments where credential dumping is monitored or prevented.

The attack leverages a stolen Ticket Granting Ticket (TGT) or a service ticket (TGS). An attacker can use this ticket from a different machine to request new service tickets from the Domain Controller and gain access to network resources, effectively impersonating the user without ever knowing their password.

## Prerequisites
___

**Access Level:** Administrative rights are required on the source machine to dump Kerberos tickets from memory, as they belong to other users' logon sessions.

**System State:** The attacker must have a foothold on a domain-joined machine where a target user is currently logged in or has an active Kerberos ticket cached.

**Information:** The attacker needs to identify a valid Kerberos ticket in memory to steal.

**Misc**: Your system time must be synced with the DC. If your time is too skewed, the ticket will be considered invalid.

## Considerations
___

**Impact**

Successful PtT allows an attacker to move laterally across the network and access any resources the impersonated user has permissions for. If the stolen ticket belongs to a Domain Administrator, the attacker gains full control over the domain.

!!! alert "DANGER"
	**Sacrificial Processes:** It is critical to inject stolen tickets into a "sacrificial process" rather than overwriting the ticket of an existing logon session. Overwriting a ticket for a critical process (like `SYSTEM$`) or a service can cause an outage, as the service may not be able to re-authenticate until it is restarted. Using a sacrificial process creates a new, isolated logon session for the ticket. While this is safer, creating a new logon session (`LOGON_TYPE = 9`) is an Indicator of Compromise (IOC) that can be detected.

**OPSEC**

- **Tooling Footprint:** Executing tools like `Rubeus.exe` from disk creates obvious IOCs (process name, file hash, arguments) for EDR. Prefer in-memory execution or integrated C2 capabilities to avoid detection.

- **Logon Artifacts:** Creating a sacrificial process generates a detectable **`LOGON_TYPE = 9`** event. This is a direct trade-off between preventing service outages and maintaining stealth.

- **Suspicious Service Requests:** After passing a ticket, the host's requests for new service tickets can appear abnormal.

## Execution
___

**Create a Sacrificial Process**

To avoid overwriting existing tickets and potentially causing service disruptions, create a new process with its own logon session. Rubeus can create this process, which will be used for ticket injection. The `/show` flag makes the new command window visible.

```powershell
.\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```
The output provides the Logon ID (LUID) of the new session. Save this for later.


**Identify TIckets** (In original session)

```powershell
.\Rubeus.exe triage
```

Once a target ticket is identified (e.g., a ticket for `admin@DOMAIN.LOCAL` with the service `krbtgt`), save its LUID.


**Dump the target ticket with its LUID** (In original session)

```powershell
.\Rubeus.exe dump /luid:0x89275d /service:krbtgt /nowrap
```

This command outputs the user's ticket in Base64 format.

**Pass the Ticket (PTT)** (In **Sacrificial Process**)

inject the stolen ticket into the current logon session. The `/ptt` flag passes the ticket directly into memory.

```cmd
Rubeus.exe renew /ticket:doIFVjCCBVKgAwIBBaEDA<SNIP> /ptt
```

Rerun `klist` to confirm that the ticket for the target user is now in our current session.

```cmd
klist
```

The output should now show the impersonated user's ticket. With this ticket in memory, any network action you perform will be on behalf of that user. For example, accessing a Domain Controller's C$ share.

```cmd
dir \\dc01\c$
```
Windows will automatically use the injected TGT to request a TGS for the `cifs/dc01` service and grant you access.

## Cleanup Considerations
___

Terminating the sacrificial process will destroy the associated logon session and the injected tickets.

## Detection & Mitigation
___

#### Detection

- Monitor for process creation events associated with `LOGON_TYPE = 9` (New Credentials), which tools like Rubeus use to create sacrificial processes.
    
- Audit for Kerberos service ticket requests (Event ID 4769) originating from unusual hosts or at anomalous times.
    
- Network traffic analysis can potentially identify a ticket being used from an IP address not associated with the legitimate user.

#### Mitigation

- **Limit Admin Privileges:** Restricting local administrator rights prevents attackers from being able to dump tickets from other users' sessions on a machine.
    
- **Protected Users Group:** Add high-privilege accounts to the "Protected Users" group in Active Directory. This enforces security controls that make it much harder to steal or use their tickets, such as disabling credential caching.
    
- **Microsoft Defender for Identity:** Can detect anomalous ticket usage across the network, which is a key indicator of a Pass-the-Ticket attack.