---
tags:
  - Lateral-Movement
  - Privilege-Escalation
  - AD
---
**NTLM**
```bash
hashcat -m 1000 --force -a 0 hashes.txt <wordlist>
```
**NetNTLMv2**
```bash
hashcat -m 5600 --force -a 0 hashes.txt <wordlist>
```
**AS-REP** (Kerberos 5 AS-REP etype 23)
```bash
hashcat -m 18200 --force -a 0 hashes.txt <wordlist>
```
**Kerberoasted SPN** (Kerberos 5 TGS-REP)
```bash
hashcat -m 13100 --force -a 0 hashes.txt <wordlist>
```
- More ticket hash types can be found in the [Kerberoasting](Kerberoasting.md) sections.