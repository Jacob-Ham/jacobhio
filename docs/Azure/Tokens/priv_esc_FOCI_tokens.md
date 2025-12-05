___
https://github.com/secureworks/family-of-client-ids-research/tree/main
"Refresh tokens are bound to a combination of user and client, but aren't tied to a resource or tenant. A client can use a refresh token to acquire access tokens across any combination of resource and tenant where it has permission to do so. Refresh tokens are encrypted and only the Microsoft identity platform can read them." 

It’s **possible with any refresh tokens from the Microsoft identity platform** (Microsoft Entra accounts, Microsoft personal accounts, and social accounts like Facebook and Google) **to request access tokens for other resources, scopes and even tenants.**


