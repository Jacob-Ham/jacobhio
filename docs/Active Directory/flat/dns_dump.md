---
tags:
  - "#type/technique"
  - "#tactic/TA0007"
  - "#technique/T1590"
  - "#stage/reconnaissance"
  - "#protocol/dns"
  - "#os/windows"
  - "#tool/adidnsdump"
  - "#tool/dig"
aliases:
  - DNS Dump
  - Active Directory DNS Enumeration
  - Zone Transfer
  - DNS Records Extraction
---
## Technique
___

 https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/ 

Some records may be "hidden" due to default permissions (e.g., computer DNS records without "Everyone" read rights), visible only as names in LDAP queries but not their contents. These can be resolved via DNS queries. Inspired by prior work on ADIDNS, this uses tools like adidnsdump to automate enumeration over LDAP and DNS.

## Prerequisites
___

**Access Level:** Valid AD domain account (even low-privilege).
**System State:** Network access to a DC with AD-integrated DNS.
**Tools:** [adidnsdump](https://github.com/dirkjanm/adidnsdump) 

## Execution
___

Display available DNS zones

```bash
adidnsdump -u domain\\user --print-zones dc01.domain.local
```

This shows forest/domain zones (e.g., ignore stub/forward zones and query their actual zones).

Dump & list records in default zone (outputs to `records.csv`). Hidden records appear with "?" as type/IP is unknown:

```bash
adidnsdump -u domain\\user dc01.domain.local
```

Dump records in specific zone:

```bash
adidnsdump -u domain\\user --zone <zone> dc01.domain.local
```

Resolve hidden records by querying DNS for A/AAAA records (resolves "?" entries with actual IPs):

```bash
adidnsdump -u domain\\user dc01.domain.local -r
```

Prior tools like PowerShell scripts (e.g., from Mubix, 2013) or Python versions exist, but adidnsdump automates and enhances this.
## Detection & Mitigation
___
### Detection

- Monitor LDAP queries listing DNS zone children or high-volume DNS requests.
- Audit DNS zone accesses; alert on anomalies like bulk queries from single user.
- Enable logging for unusual DNS queries (e.g., many A/AAAA lookups in short time).
### Mitigation

- Do not rely on DNS secrecy for security (treat it as public).
- Remove "List contents" permission for "Everyone" and "Pre-Windows 2000 Compatible Access" on DNS zones (may break inheritance and cause issues; test thoroughly).
- Disable local user DNS record creation if not needed (though breaks AD functionality).
- Instead of blocking, monitor for high volumes of DNS/DNS-related LDAP queries and enable auditing on zone permissions.

