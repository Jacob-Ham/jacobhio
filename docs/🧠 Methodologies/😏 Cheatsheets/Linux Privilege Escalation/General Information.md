
Basic Info
```bash
whoami; id; hostname;
```
Networking
```bash
ip a
```
Can you run anything as sudo
```bash
sudo -l
```
What operating system do we have?
```bash
cat /etc/os-release
```
Check user path
```bash
echo $PATH
```
check environment variables
```bash
env
```
Check kernel version
```bash
uname -a
cat /proc/version
```
Check CPU info
```bash
lscpu
```
Check login shells
```bash
cat /etc/shells
```
Check attached printers:
```bash
lpstat
```
Check users and groups:
```bash
cat /etc/passwd
cat /etc/group
```
Check who is in a group:
```bash
getent group sudo
```
Check home directories of users on system and inspect their history files:
```bash
find /home -maxdepth 2 -type f -name ".*history" -exec ls -l {} \; 2>/dev/null
find /home -type f -name ".bash_history" -o -name ".zsh_history" 2>/dev/null
```
Check running processes as root
```bash
ps aux | grep root
```
Env vars
```bash
env
printenv
```
Check mounted filesystems
```bash
mount
df -h
```
Check open network sockets:
```bash
ss -tulpn
netstat -tulpn
```
check crons
```bash
crontab -l 2>/dev/null
ls -la /var/spool/cron/crontabs
ls -la /etc/cron.*
cat /etc/crontab
```
Check system information available in `/proc`:
```bash
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
```
Kernel version
```bash
uname -a
uname -r
```
