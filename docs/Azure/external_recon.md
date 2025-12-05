
### Discover public resources (blob, apps, etc...)
---
Using cloud_enum:
https://github.com/initstring/cloud_enum
```bash

```

Using azsubenum:
https://github.com/yuyudhn/AzSubEnum
```bash
python3 azsubenum.py -b companyname -t 10 -p permutations.txt
```
Or default options
```
python3 azsubenum.py -b companyname --thread 10
```

### Enumerate tenant information
---
Federation info
```bash
curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=domain.com' | jq
```

Get tenantID and OpenID configuration info

```bash
curl -s https://login.microsoftonline.com/domain.com/.well-known/openid-configuration | jq
```

With AADInternals
```
Install-Module AADInternals
Import-Module AADInternals
```
```powershell
Get-AADIntLoginInformation -Domain domain.com
```

Just tenantID
```
Get-AADIntTenantID -Domain domain.com
```

Public configuration enumeration
```powershell
Invoke-AADIntReconAsOutsider -DomainName megabigtech.com
```

### Determine Azure Region
---
```bash
curl --silent 'https://azservicetags.azurewebsites.net/api/iplookup?ipAddresses=20.75.112.13' | jq
```
