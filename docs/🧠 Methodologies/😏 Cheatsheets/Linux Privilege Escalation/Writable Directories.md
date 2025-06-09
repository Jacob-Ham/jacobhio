**Find World-Writable Directories**
```bash
find / -type d -perm -002 -ls 2>/dev/null
```
**Find World-Writable Files**
```bash
find / -type f -perm -002 -ls 2>/dev/null
```
