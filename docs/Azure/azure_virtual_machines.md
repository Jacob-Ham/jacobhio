
If you don't know jack shit about the resources you have access to why are you here?
- [[resource_enumeration]]
---

## Enumeration

```bash
az vm show --resource-group 'resource group' --name 'vm name'
```

> [!NOTE] NOTE
> VMs sometimes have userData defined containing sensitive strings.

#### UserData enumeration

Azure CLI
```bash
az vm show --resource-group "RGNAME" --name "VMNAME" -u --query "userData" --output tsv | base64 -d
```

Az Powershell
```powershell
(Get-AzVM -ResourceGroupName "RGNAME" -Name "VMNAME" -UserData).UserData | base64 -d
```

With API call
```powershell
$token = 'ey...'
Invoke-RestMethod -Method GET -Uri "https://management.azure.com/subscriptions/<SUBID>/resourceGroups/<RESOURCEGROUP>/providers/Microsoft.Compute/virtualMachines/<VM NAME>?api-version=2021-07-01&`$expand=userData" -Headers @{Authorization = "Bearer $token"}
```
or
```bash
TOKEN='ey...'

curl -s -X GET -H "Authorization: Bearer $TOKEN" 'https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-22/providers/Microsoft.Compute/virtualMachines/SECURITY-DIRECTOR?api-version=2021-07-01&$expand=userData' | jq '.properties.userData | @base64d'
```

