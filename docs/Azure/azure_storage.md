# Azure Storage

## Storage Endpoints

| Storage service               | Endpoint                                         |
| ----------------------------- | ------------------------------------------------ |
| Blob Storage                  | https://<storage-account>.blob.core.windows.net  |
| Static website (Blob Storage) | https://<storage-account>.web.core.windows.net   |
| Data Lake Storage Gen2        | https://<storage-account>.dfs.core.windows.net   |
| Azure Files                   | https://<storage-account>.file.core.windows.net  |
| Queue Storage                 | https://<storage-account>.queue.core.windows.net |
| Table Storage                 | https://<storage-account>.table.core.windows.net |

### Discovery
Sometimes you can identify in source code of website or automated: [[external_recon]]

## Storage Account Configurations

### Main Configuration Options
- Every storage account must have a unique name across all Azure
- Every storage account is deployed in a region or in an Azure extended zone
- Premium version available for better performance
- 4 types of redundancy to protect against rack, drive and datacenter failures

### Security Configuration Options
- **Require secure transfer**: Require TLS in any communication with the storage
- **Allow anonymous access**: If disabled, anonymous access cannot be enabled later
- **Enable storage account key access**: If disabled, access with Shared Keys is forbidden
- **Minimum TLS version**: Set minimum TLS version
- **Permitted scope for copy operations**: Allow from any storage account, same Entra tenant, or private endpoints in same VNet

### Blob Storage Options
- **Allow cross-tenant replication**
- **Access tier**: Hot (frequently accessed), Cool and Cold (rarely accessed)

### Networking Options
- **Allow from all networks**
- **Allow from selected virtual networks and IP addresses**
- **Disable public access and use private access**
- **Private endpoints**: Private connection to storage account from VNet

### Data Protection Options
- **Point-in-time restore for containers**: Restore containers to earlier state (requires versioning, change feed, and blob soft delete)
- **Enable soft delete for blobs**: Retention period for deleted blobs (even overwritten)
- **Enable soft delete for containers**: Retention period for deleted containers
- **Enable soft delete for file shares**: Retention period for deleted file shares
- **Enable versioning for blobs**: Maintain previous versions of blobs
- **Enable blob change feed**: Log create, modification, and delete changes to blobs
- **Enable version-level immutability support**: Time-based retention policy on account-level for all blob versions
- **Note**: Version-level immutability support and point-in-time restore cannot be enabled simultaneously

### Encryption Configuration Options
- **Encryption type**: Microsoft-managed keys (MMK) or Customer-managed keys (CMK)
- **Enable infrastructure encryption**: Double encrypt data for additional security

## Container Public Exposure

Containers organize blobs for easier management. Public exposure options:
- **Private**: No public access
- **Blob**: Read access for blobs only
- **Container**: Read access for container listing and blobs

## Authentication Methods

### RBAC Authentication
Azure Storage supports Microsoft Entra ID authorization using Azure RBAC:

```bash
az role assignment create --role "Storage Blob Data Contributor" --assignee <email> --scope "/subscriptions/<subscription>/resourceGroups/<resource-group>/providers/Microsoft.Storage/storageAccounts/<storage-account>/blobServices/default/containers/<container>"
```

### Access Key Authentication
Storage accounts have access keys providing full access to the storage account. **Access keys are not automatically rotated.**

### Shared Key & Lite Shared Keys
Generate signed URLs using access keys for authorization.

**Shared Key StringToSign:**
```
VERB + "\n" +
Content-Encoding + "\n" +
Content-Language + "\n" +
Content-Length + "\n" +
Content-MD5 + "\n" +
Content-Type + "\n" +
Date + "\n" +
If-Modified-Since + "\n" +
If-Match + "\n" +
If-None-Match + "\n" +
If-Unmodified-Since + "\n" +
Range + "\n" +
CanonicalizedHeaders +
CanonicalizedResource
```

**Lite Shared Key StringToSign:**
```
VERB + "\n" +  
Content-MD5 + "\n" +  
Content-Type + "\n" +  
Date + "\n" +  
CanonicalizedHeaders +   
CanonicalizedResource
```

**Authorization Header:**
```
Authorization="[SharedKey|SharedKeyLite] <AccountName>:<Signature>"

Authorization: SharedKey myaccount:ctzMq410TV3wS7upTBcunJTDLEJwMAZuFPfr0mrrA08=
```

**MitM to capture Azure CLI keys:**
```bash
export ADAL_PYTHON_SSL_NO_VERIFY=1
export AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=1
export HTTPS_PROXY="http://127.0.0.1:8080"
export HTTP_PROXY="http://127.0.0.1:8080"
export REQUESTS_CA_BUNDLE=/path/to/cacert.pem

az storage blob download \
  --account-name <account> \
  --container-name <container> \
  --name <blob> \
  --file /tmp/file
```

### Shared Access Signature (SAS)

SAS are secure, time-limited URLs granting specific permissions without exposing access keys.

#### Types of SAS
- **User delegation SAS**: Created from Entra ID principal, only for blob and data lake storage, max 7 days
- **Service SAS**: Signed using storage account access key, for specific resources in single service
- **Account SAS**: Signed using access key, grants access across all storage services

#### SAS URL Examples

**Access key signed:**
```
https://<container>.blob.core.windows.net/newcontainer?sp=r&st=2021-09-26T18:15:21Z&se=2021-10-27T02:14:21Z&spr=https&sv=2021-07-08&sr=c&sig=7S%2BZySOgy4aA3Dk0V1cJyTSIf1cW%2Fu3WFkhHV32%2B4PE%3D
```

**User delegation signed:**
```
https://<container>.blob.core.windows.net/testing-container?sp=r&st=2024-11-22T15:07:40Z&se=2024-11-22T23:07:40Z&skoid=<id>&sktid=<id>&skt=2024-11-22T15:07:40Z&ske=2024-11-22T23:07:40Z&sks=b&skv=2022-11-02&spr=https&sv=2022-11-02&sr=c&sig=<sig>
```

**Parameters:**
- `se`: Expiration date
- `sp`: Permissions
- `sig`: Signature validation
- `ss`: Allowed services (account SAS)
- `srt`: Resource types allowed (account SAS)

**Note**: SAS tokens are not tracked by Azure.

## SFTP for Azure Blob Storage

Azure Blob Storage supports SFTP for secure file transfer directly to Blob Storage.

**Key Features:**
- Works with hierarchical namespace (HNS) configured accounts
- Uses local user identities (no RBAC/ABAC integration)
- Authentication via Azure-generated passwords or SSH key pairs
- Granular permissions (Read, Write, Delete, List) for up to 100 containers
- Connections through port 22
- Supports network configurations (firewalls, private endpoints, VNets)

## Blob Storage

### Blob URL Breakdown
```
https://domainblobwebsite.blob.core.windows.net/$web/index.html
```
- **https**: Protocol (supports http and https)
- **domainblobwebsite**: Storage account name
- **blob.core.windows.net**: Azure Blob Storage Service
- **$web**: Container name hosting the website

### Unauthenticated Access

**Validate blob storage:**
```powershell
Invoke-WebRequest -Uri 'https://mbtwebsite.blob.core.windows.net/$web/index.html' -Method Head
```

**List objects in container:**
```
https://domainblobwebsite.blob.core.windows.net/$web?restype=container&comp=list
```

**List directories only:**
```
https://domainblobwebsite.blob.core.windows.net/$web?restype=container&comp=list&delimiter=%2F
```

**Check for blob versions (requires x-ms-version: 2019-12-12+):**
```bash
curl -H "x-ms-version: 2019-12-12" 'https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list&include=versions'
```

**Download specific version:**
```bash
curl -H "x-ms-version: 2019-12-12" 'https://blobdomainwebsite.blob.core.windows.net/$web/scripts-transfer.zip?versionId=2025-08-07T21:08:03.6678148Z' --output scripts-transfer.zip
```

### Authenticated Enumeration

**List storage accounts:**
```bash
az storage account list
```

**List containers:**
```bash
az storage container list --account-name <name>
```

**Check public access:**
```bash
az storage container show-permission --account-name <acc-name> -n <container-name>
```

**Make container public:**
```bash
az storage container set-permission \
  --public-access container \
  --account-name <acc-name> \
  -n <container-name>
```

**List blobs:**
```bash
az storage blob list \
  --container-name <container> \
  --account-name <account>
```

**Download blob:**
```bash
az storage blob download \
  --account-name <account> \
  --container-name <container> \
  --name <blob> \
  --file </path/to/file>
```

#### Restore blob version

**List version (note version timestamp)**
```bash
az storage blob list \
az storage blob list --account-name accountname --container-name containername --include v
```

**Download specific blob version**
```bash
az storage blob download \
    --account-name <storage-account-name> \
    --container-name <container-name> \
    --name <blob-name> \
    --file <local-destination-path-and-filename> \
    --version-id <version-id>
```



### Access Keys

Access keys allow persistent access to the entirety of the Azure storage account - not just an individual resource. **They are not automatically rotated at any point.**

#### Using a key to authenticate

**List all File Shares:** This confirms you have read access to the Azure Files service
```bash
az storage share list --account-name <name> --account-key <key>
```

**List all Blob Containers:** This confirms you have read access to the Azure Blob service and can see all containers.
```bash
az storage container list --account-name <name> --account-key <key>
```

**List Files within a Share/Directory:** This confirms you have read/list access to the file data.
```bash
az storage file list --share-name <share> --account-name <name> --account-key <key>
```

**List access keys:**
```bash
az storage account keys list --account-name <name>
```

**Check key policies:**
```bash
az storage account show -n <name> --query "{KeyPolicy:keyPolicy}"
```

**Use key for authentication:**
```bash
az storage blob list \
  --container-name <container> \
  --account-name <account> \
  --account-key "ZrF40pkVKvWPUr[...]v7LZw=="
```

> [!Note] File Recovery
> If you have access to a storage service, check if you can restore deleted files or restore previous blob versions.

### SAS Enumeration

**List access policies:**
```bash
az storage <container|queue|share|table> policy list \
  --account-name <acc> \
  --container-name <container>
```

**Generate SAS with access key:**
```bash
az storage <container|queue|share|table|blob> generate-sas \
  --permissions acdefilmrtwxy \
  --expiry 2024-12-31T23:59:00Z \
  --account-name <acc> \
  -n <container>
```

**Generate SAS with user delegation:**
```bash
az storage <container|queue|share|table|blob> generate-sas \
  --permissions acdefilmrtwxy \
  --expiry 2024-12-31T23:59:00Z \
  --account-name <acc> \
  --as-user --auth-mode login \
  -n <container>
```

**Generate account SAS:**
```bash
az storage account generate-sas \
  --expiry 2024-12-31T23:59:00Z \
  --account-name <acc> \
  --services qt \
  --resource-types sco \
  --permissions acdfilrtuwxy
```

**Use SAS token:**
```bash
az storage blob show \
  --account-name <account> \
  --container-name <container> \
  --sas-token 'se=2024-12-31T23%3A59%3A00Z&sp=racwdxyltfmei&sv=2022-11-02&sr=c&sig=<sig>' \
  --name 'file.txt'
```

**Enumerate local users:**
```bash
az storage account local-user list \
  --account-name <storage-account> \
  --resource-group <resource-group>
```

## Azure File Share

### What is Azure File Share?
Fully managed cloud file storage accessible via SMB and NFS protocols. Enables highly available network file shares accessible simultaneously by multiple VMs or on-premises systems.

### Access Tiers
- **Transaction Optimized**: Optimized for transaction-heavy operations
- **Hot**: Balanced between transactions and storage
- **Cool**: Cost-effective for storage
- **Premium**: High-performance, low-latency, IOPS-intensive workloads

### Backups & Snapshots
- **Daily backup**: Created daily at specified time, stored 1-200 days
- **Weekly backup**: Created weekly at specified time, stored 1-200 weeks
- **Monthly backup**: Created monthly at specified time, stored 1-120 months
- **Yearly backup**: Created yearly at specified time, stored 1-10 years
- **Manual backups**: Possible at any time
- **Note**: NFS file shares don't support backups

### Network Protections
Applied at Storage Account level:
- **Allow from all networks** (cannot be used with NFS)
- **Allow from selected virtual networks and IP addresses**
- **Disable public access and use private access**
- **Private endpoints**: Private connection from VNet

### SMB Authentication Methods
- **Access key as password**
- **On-premises AD DS Authentication**: Uses on-premises AD credentials synced with Entra ID
- **Microsoft Entra Domain Services Authentication**: Uses cloud-based AD for Entra credentials
- **Microsoft Entra Kerberos for Hybrid Identities**: Entra users authenticate over internet using Kerberos (hybrid/cloud-only Entra joined VMs, no cloud-only identities)
- **AD Kerberos Authentication for Linux Clients**: Linux clients use Kerberos via on-premises AD DS or Entra Domain Services

### NFS "Authentication"
**Root squash configurations:**
- **Root squash**: Root user mapped to anonymous user
- **No root squash**: Root user mapped to root user
- **All squash**: All users mapped to anonymous user

**Requirements:**
- Disable "Secure transfer required" (NFS doesn't support encryption)
- Private access required (no public access)
- Private endpoint exposed in VNet subnet with port 2049 open
- Can discover with nmap

### File Share Enumeration

**List file shares:**
```bash
az storage share list --account-name <name>
az storage share-rm list --storage-account <name> --include-deleted  # Include deleted
```

**List files in share:**
```bash
az storage file list --account-name <name> --share-name <share>
# Continue for subdirectories
az storage file list --account-name <name> --share-name <prev_dir/share>
```

**Download complete share:**
```bash
az storage file download-batch -d . --source <share> --account-name <name>
```

**Get snapshots/backups:**
```bash
az storage share list --account-name <name> --include-snapshots --query "[?snapshot != null]"
```

**List snapshot contents:**
```bash
az storage file list --account-name <name> --share-name <share> --snapshot <snapshot-version>
```

**Download snapshot:**
```bash
az storage file download-batch -d . --account-name <name> --source <share> --snapshot <snapshot-version>
```

### Local Enumeration

**Find NFS private endpoints:**
```bash
sudo nmap -n -T5 -Pn -p 2049,445 --open <private-ip>/16
```

**Find mounted shares:**
```bash
mount | grep nfs
mount | grep "username="
```

## Azure Table Storage

### What is Azure Table Storage?
NoSQL key-value store for large volumes of structured, non-relational data. High availability, low latency, and scalability. Data organized into tables with partition key and row key for fast lookups.

**Note**: No built-in backup mechanism for table storage.

### Keys Structure
- **PartitionKey**: Groups entities into logical partitions, improves query performance and scalability
  - Example: Department (HR, IT)
- **RowKey**: Unique identifier within partition, combined with PartitionKey for global uniqueness
  - Example: Employee ID within department
- **Custom Properties**: Additional user-defined properties stored as key-value pairs
  - Example: Name, Age, Title

### Network Protections
Applied at Storage Account level:
- **Allow from all networks**
- **Allow from selected virtual networks and IP addresses**
- **Disable public access and use private access**
- **Private endpoints**: Private connection from VNet

### Table Storage Enumeration

**List tables:**
```bash
az storage table list --account-name <name>
```

**Read table entities:**
```bash
az storage entity query \
  --account-name <name> \
  --table-name <table> \
  --num-results 10
```

## Privilege Escalation

**Microsoft.Storage/storageAccounts/listkeys/action**
- List and get access key values, enabling privilege escalation over storage accounts

**Microsoft.Storage/storageAccounts/regenerateKey/action**
- Renew and get new access key values, enabling privilege escalation. Returns both renewed and non-renewed key values

**Microsoft.Storage/storageAccounts/write**
- Create or update storage account, modify settings like network rules or policies

**Microsoft.Storage/storageAccounts/localusers/regeneratePassword/action**
- Regenerate local user password to access container and retrieve sensitive information

## Post Exploitation

### Blob Storage
**Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read**
- List blobs inside container and download files containing sensitive information

**Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write**
- Write and overwrite files in containers, potentially causing damage or privilege escalation

***/delete**
- Delete objects causing DoS and loss of valuable information

### File Share Storage
**Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read**
- List files inside file share and download files containing sensitive information

**Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write**
- Write and overwrite files in file shares, potentially causing damage or privilege escalation

### Table Storage
**Microsoft.Storage/storageAccounts/tableServices/tables/entities/read**
- List tables inside table storage and read information containing sensitive data

**Microsoft.Storage/storageAccounts/tableServices/tables/entities/write | Microsoft.Storage/storageAccounts/tableServices/tables/entities/add/action | Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action**
- Write, add, or update table entries, potentially causing damage or privilege escalation

## Persistence

- Keep access keys
- Generate SAS tokens
- User delegated SAS are maximum 7 days
- Create local user in container
- Enable soft delete in blobs and containers