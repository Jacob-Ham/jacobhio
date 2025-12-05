---
tags:
  - "#type/technique"
  - "#tactic/TA0006"
  - "#stage/credential-access"
  - "#stage/lateral-movement"
  - "#stage/privilege-escalation"
  - "#tool/hashcat"
  - "#tool/john"
  - "#os/windows"
  - "#protocol/ntlm"
  - "#protocol/kerberos"
aliases:
  - Password Cracking
  - Offline Credential Attack
  - Hash Breaking
  - Brute Force Attack
---

## Technique
___

Hash cracking is the process of attempting to recover plaintext passwords from their hashed values. This technique is used when an attacker has obtained password hashes through various means such as credential dumping, NTLM capture, or Kerberos attacks.

By successfully cracking hashes, an attacker can obtain the actual passwords for user accounts, allowing for direct authentication to systems and services rather than relying on pass-the-hash or similar techniques.

## Common Hash Types in Active Directory Environments
___

### NTLM Hashes

NTLM hashes are stored in the SAM database or NTDS.dit and represent local or domain user passwords. These are the most common targets in Windows environments.

**Cracking with Hashcat:**
```bash
hashcat -m 1000 --force -a 0 hashes.txt /path/to/wordlist
```

**Cracking with John the Ripper:**
```bash
john --format=NT hashes.txt --wordlist=/path/to/wordlist
```

### NetNTLMv2 Hashes

NetNTLMv2 hashes are captured from network authentication traffic, typically through tools like Responder, Inveigh, or NTLM relay attacks.

**Cracking with Hashcat:**
```bash
hashcat -m 5600 --force -a 0 hashes.txt /path/to/wordlist
```

**Cracking with John the Ripper:**
```bash
john --format=netntlmv2 hashes.txt --wordlist=/path/to/wordlist
```

### AS-REP Roasting Hashes (Kerberos 5 AS-REP etype 23)

These hashes are obtained when requesting authentication data for accounts with Kerberos pre-authentication disabled.

**Cracking with Hashcat:**
```bash
hashcat -m 18200 --force -a 0 hashes.txt /path/to/wordlist
```

**Cracking with John the Ripper:**
```bash
john --format=krb5asrep hashes.txt --wordlist=/path/to/wordlist
```

### Kerberoasting Hashes (Kerberos 5 TGS-REP)

These hashes are obtained through Kerberoasting, where service account ticket encryption can be subjected to offline cracking.

**Cracking with Hashcat:**
```bash
hashcat -m 13100 --force -a 0 hashes.txt /path/to/wordlist
```

**Cracking with John the Ripper:**
```bash
john --format=krb5tgs hashes.txt --wordlist=/path/to/wordlist
```

## Advanced Cracking Techniques
___

### Rule-Based Attacks

Rule-based attacks apply transformation rules to wordlist entries to generate variations:

```bash
hashcat -m 1000 -r rules/best64.rule hashes.txt /path/to/wordlist
```

### Mask Attacks (Pattern-Based)

Mask attacks define specific patterns to try:

```bash
# Crack an 8-character password with uppercase, lowercase, and digits
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?l?d
```

### Hybrid Attacks

Combines wordlists with masks:

```bash
# Append 4 digits to each word in the wordlist
hashcat -m 1000 -a 6 hashes.txt /path/to/wordlist ?d?d?d?d
```

### Dictionary Combination Attacks

Combines words from dictionaries:

```bash
hashcat -m 1000 -a 1 hashes.txt wordlist1.txt wordlist2.txt
```

## Optimizing Cracking Efficiency
___

1. **Use appropriate hardware:** GPUs significantly outperform CPUs for hash cracking.

2. **Choose targeted wordlists:** Use context-specific dictionaries (company names, industry terms, etc.).

3. **Start with fast attacks first:**
   - Basic wordlists
   - Common rule sets (best64.rule)
   - Short mask attacks
   - Then progress to more comprehensive approaches

4. **Customize rules for your target:** Create custom rules based on the organization's password policy.

5. **Utilize hash sorting:** Group similar hash types together for more efficient cracking.

## Detection & Mitigation
___

### Detection

- This is primarily an offline attack, making it difficult to detect
- Monitor for mass hash extraction events
- Look for suspicious access to authentication databases
- Watch for unusual traffic patterns that could indicate hash harvesting

### Mitigation

- Implement strong password policies (length, complexity, regular changes)
- Use password filters to prevent common or easily cracked passwords
- Enable multi-factor authentication where possible
- Consider implementing credential guard to protect authentication material
- Audit authentication logs regularly to detect potential compromise
- Use the Protected Users security group for privileged accounts
- Regularly run password audits to identify weak passwords before attackers do