---
tags:
  - "#type/technique"
  - "#tactic/TA0008"
  - "#technique/T1134"
  - "#stage/lateral-movement"
  - "#os/windows"
  - "#tool/powerview"
  - "#tool/bloodhound"
aliases:
  - Domain ACLs
  - Access Control List Abuse
  - DACL Modification
  - Domain Permission Attacks
---

## Technique
___

 Attackers leverage misconfigured or overly permissive ACLs to escalate privileges, move laterally, and ultimately gain control over the domain. This is often done by identifying an ACL that grants a low-privilege user control over a high-value object (like a Domain Admin account or a sensitive group) and then using that control to compromise the target.

## Prerequisites
___

- **Initial Access:** The attacker needs to have a foothold in the network, typically as a standard, unprivileged domain user.
    
- **Active Directory Enumeration:** The attacker must use tools like **BloodHound** to enumerate the Active Directory topology, identify the relationships between users and groups, and pinpoint the specific dangerous ACLs that can be exploited. This involves collecting data on objects, their properties, and their ACLs.
    
- **Tooling:** The attacker requires tools to interact with Active Directory and modify ACLs. Common tools include **PowerShell (with the Active Directory module)**, **Python-based libraries (like `impacket`)**, and specialized tools like **BloodyAD**.

## Execution
___


## Detection & Mitigation
___