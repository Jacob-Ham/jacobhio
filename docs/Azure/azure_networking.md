
**Get networking info about a VM**
```bash
az network public-ip show --resource-group RESOURCEGROUP --name VMNAMEip304 --query "ipAddress" --output tsv
```