---
tags:
  - "#type/technique"
  - "#tactic/TA0001"
  - "#tactic/TA0004"
  - "#technique/T1558.001"
  - "#stage/initial-access"
  - "#stage/privilege-escalation"
  - "#os/windows"
  - "#protocol/netlogon"
  - "#tool/netexec"
  - "#cve/CVE-2020-1472"
aliases:
  - ZeroLogon
  - Netlogon Elevation of Privilege
  - CVE-2020-1472
---

## Technique
___

ZeroLogon (CVE-2020-1472) is a critical vulnerability in the Microsoft Windows Netlogon Remote Protocol (MS-NRPC) discovered in 2020. This vulnerability allows an unauthenticated attacker with network access to a domain controller to completely compromise the Active Directory domain.

The vulnerability stems from a cryptographic flaw in the Netlogon authentication process, where under certain circumstances, the initialization vector (IV) of AES-CFB8 mode becomes all zeros. This allows an attacker to:

1. Impersonate any computer account in the domain, including domain controllers
2. Set an empty password for the domain controller computer account
3. Use this compromised account to gain domain admin privileges

## Prerequisites
___

**Access Level:** Network access to a domain controller (no prior authentication required)

**System State:** Unpatched domain controller vulnerable to CVE-2020-1472 (pre-August 2020 or without security updates)

**Tools:** NetExec (formerly CrackMapExec) with zerologon module, or a specialized ZeroLogon exploit script

## Considerations
___

**Impact**

Successful exploitation provides complete domain compromise, allowing an attacker to:
- Reset any password in the domain
- Add new domain admin accounts
- Modify security configurations
- Access any resource in the domain

**OPSEC**

- **Extreme Risk of Detection:** ZeroLogon exploitation is highly detectable
- **Domain Stability Risk:** Improper exploitation can break domain functionality by corrupting the computer account password for the domain controller
- **Microsoft Monitoring:** Microsoft actively monitors for ZeroLogon exploitation attempts

> **WARNING**: This vulnerability is extremely dangerous and can easily cause domain-wide outages if exploited incorrectly. Do not attempt to exploit this vulnerability on production systems without explicit authorization and a recovery plan.

## Identification
___

Check if a domain controller is vulnerable using NetExec:

```bash
nxc smb <ip> -u '' -p '' -M zerologon
```

https://github.com/SecuraBV/CVE-2020-1472

```bash
python3 zerologon_tester.py domain.local <dc-ip>
```

## Exploitation
___

While exploitation details are deliberately not provided in full to prevent misuse, the general process involves:

1. Exploiting the cryptographic flaw to bypass authentication
2. Setting an empty password for the domain controller computer account
3. Using this account to gain domain admin privileges (typically via DCSync)
4. Restoring the original password to prevent domain disruption

## Recovery
___

If exploitation occurs without proper restoration of the domain controller's machine account password, the domain controller will be unable to authenticate to the domain, potentially causing widespread service disruption.

Recovery steps may include:
1. Restore from backups
2. Seize FSMO roles to another domain controller
3. Restore proper machine account passwords
4. In extreme cases, rebuild the domain from scratch

## Detection & Mitigation
___

### Detection

- Monitor for Event ID 5805 (Netlogon errors) on domain controllers
- Look for unauthorized password reset attempts for domain controller computer accounts
- Watch for failed Netlogon secure channel establishment
- Monitor for unusual RPC traffic to domain controllers on port 135/TCP

### Mitigation

1. **Apply Microsoft Security Updates**:
   - [August 2020 Security Update](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1472) (initial mitigation)
   - [February 2021 Security Update](https://support.microsoft.com/en-us/topic/february-9-2021-kb4601347-os-build-17763-1757-08afcb15-a2a2-54e9-281d-0673a3fe5f6a) (enforcement mode)

2. **Enable Netlogon secure channel enforcement mode**:
   ```powershell
   # Check current enforcement mode
   Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "FullSecureChannelProtection"
   
   # Enable enforcement mode
   New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "FullSecureChannelProtection" -Value 1 -PropertyType DWORD -Force
   ```

3. **Monitor for exploitation attempts**

4. **Implement network segmentation** to limit access to domain controllers

5. **Use a tiered administration model** to minimize exposure of privileged accounts