---
tags:
  - Authenticated
  - Kerberos
  - OPSEC
  - Persistence
  - AD
---
Similar to a golden ticket in function but not in form. Instead of forging a new ticket, a diamond ticket is created by modifying fields of a previously granted ticket. This gives some opsec advantages because:

- TGS-REQ will have a AS-REQ preceding it.
- It will have all the correct details from the domain's Kerberos policy because it was issued by the DC

