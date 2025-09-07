___

**Edit `/etc/resolv.conf` to prioritize the DC.**

Enum DCs:
```bash
nslookup -type=SVR _ldap._tcp.FQDN
```

Use smbclient to check against all DCs

```bash
for dc in $(cat dcs.txt); do echo $dc && smbclient -N -L \\\\$dc; done; 
```

or: [auth.py](https://github.com/Jacob-Ham/auth)

```
auth smb <dcs.txt> 
```

!!! alert "note"
	 anon login != unauth enum, you should try to pull info to show impact. 

**Try to pull users**:

```bash
enum4linux-ng -U <DC>
```

