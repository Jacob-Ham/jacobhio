**Check ACLs on Sensitive Files**
```bash
getfacl /etc/shadow    # see if you have read permissions
getfacl /etc/passwd    # see if you can modify or read
```
**Check ACLs on Directories**
```bash
getfacl /usr/local/bin # maybe you can write to a directory in /usr/local/bin
getfacl /etc            # check if you can write to /etc/
```
- If you have write ACL to `/etc`, you can drop a malicious script in `/etc/profile` or `/etc/bash.bashrc`.
