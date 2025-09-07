___

#### Unauthenticated:

Scan entire ranges:
```bash
sudo nmap -p 445 --script=smb-security-mode.nse <target-ip/range>
```

```bash
nxc smb <subnet> --gen-relay-list nosigning.txt
```

```
auth smb <subnet> 
```

#### Authenticated:

```cmd
runas /netonly domain/user cmd.exe
powershell -ep bypass
. .\powerview.ps1
```

Dump computers and scan:
```powershell
Get-DomainComputer -Properties dnshostname | Select-Object -ExpandProperty dnshostname | Out-File -FilePath computers.txt
```

```bash
nxc smb computers.txt --gen-relay-list <output_file>
```

```bash
auth smb computers.txt 
```

**With bloodhound:**
```cypher
MATCH (n:Computer)
WHERE n.smbsigning = False
RETURN n
```


---
### Where to?

- [Authentication Coercion](../3.%20Credential%20Theft/Authentication%20Coercion.md)
- [Relay Attacks](../2.%20Initial%20Compromise/Relay%20Attacks.md)
