**SUID**
```bash
find / -perm /4000 -type f 2>/dev/null
```
SGID
```bash
find / -perm -2000 -type f 2>/dev/null
```
writeable SUIDs
```bash
find / -perm -4000 -type f -writable 2>/dev/null
```
- If a SUID binary is writable by your user, you can replace it with code that spawns a root shell.
