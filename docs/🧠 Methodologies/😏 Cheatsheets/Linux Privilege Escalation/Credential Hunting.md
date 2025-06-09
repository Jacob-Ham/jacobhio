Search for files containing “password” or “passwd”
```bash
grep -ir "password" /etc 2>/dev/null
grep -ir "passwd" /home 2>/dev/null
```
check for dbs and config files
```bash
find / -type f -name "*.conf" -exec grep -H "DB_USER" {} \; 2>/dev/null
find / -type f -name "*.yaml" -exec grep -H "password" {} \; 2>/dev/null
```
Private keys
```bash
find / -type f -name "*.pem" -o -name "*.key" 2>/dev/null
find /home -type f -name "id_rsa" 2>/dev/null
```
Search for credentials in environment files:
```bash
grep -R "export" /etc/profile /etc/bashrc 
```
git stuff
```bash
find /home -type f -name ".git-credentials" -o -name ".gitconfig" 2>/dev/null
```
aws creds
```bash
find /home -type f -path "*aws*" -exec grep -H "aws_access_key_id" {} \; 2>/dev/null
find / -type f -path "*aws*" -exec grep -H "AWS_ACCESS_KEY_ID" {} \; 2>/dev/null
```
Check `/var/log/auth.log` or `/var/log/secure` for previously captured credentials or failed attempts:
```bash
grep -i "fail" /var/log/auth.log
grep -i "Accepted" /var/log/auth.log
```
Look for passwords in scripts or in `/opt`, `/usr/local`:
```bash
grep -ir "password" /opt /usr/local 2>/dev/null
```
