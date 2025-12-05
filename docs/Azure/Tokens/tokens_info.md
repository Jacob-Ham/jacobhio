
### Info
---
### Token types

**Access tokens:** grant access to a specific resource. They act as authorization not authentication (JWT: `ey....`)

**Refresh token:**  Used to obtain new access tokens when your access token expires. (start with `0.A` or `1.A`)

**ARM Access Tokens:** used to authenticate and autorize requests to auzre managmenet layer. they're normally used through Azure portal, ARM API, Azure CLI or AZ Powershell.
	- audL: `managment.azure.com`
	
**Azure AD (AAD) Graph Tokens:** Used to auth requests to the Azure AD Graph API. AAD graph is deprecated and it prolly dead :( 
	- aud: `graph.windows.net`

**Microsoft Graph Tokens**: Used for microosft graph api, a unified endpoint for accessing data, intel, and insights from msft cloud. This includes Entra (Azure AD). O365, Enterprise Mobility + Security (EMS), and WIndows 10. 
	- aud: `graph.microsoft.com`

**Claims**:
- aud (audience) will tell you what the token was issued to grant access over.

### Family Client of IDs (FOCI)

Family Refresh Tokens (FRTs) can be exchanged for bearer tokens to access any application in teh FOCI. These apps share the same familyID and are registered by the same publisher in Entra.

