

**Login with az cli**
```bash
az login 
```

or with just user and pass
```
az login -u user.one@domain.com -p Password123!
```

**With service principal**
```bash
az login --service-principal -u clientid -p 'clientsecret' --tenant test.azuretnenat.com
```


Powershell:
```powershell
Install-Module Microsoft.Graph
Install-Module Az
Import-Module Microsoft.Graph.Users
Import-Module Az
```

login to  azure
```
Connect-AzAccount
```

or with device code
```powershell
Connect-AzAccount -AccountId "email@domain.com" -UseDeviceAuthentication
```

login to graph
```
Connect-MgGraph
```

Validate login:

azure :
```bash
az account show
```

graph
```
az ad signed-in-user show
```

Start graph session from azure resource manager session
```powershell
Connect-MgGraph
```

whoami but for graph
```
Get-MgContext
```


logout

```bash
az logout
```

```powershell
Disconnect-AzAccount
```