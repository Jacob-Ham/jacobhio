---
tags:
  - "#type/checklist"
  - "#assessment/report"
  - "#os/windows"
  - "#service/active-directory"
aliases:
  - Active Directory Vulnerabilities Checklist
  - AD Security Assessment Checklist
  - Domain Security Issues
  - Reportable AD Findings

title: Internal Checklist
---

## Unauthenticated Checks

- [ ] **Network Scanning**
  - Perform comprehensive port scanning
  - Identify services running on the 
  - Map out domain infrastructure

- [ ] **LLMNR/NBT-NS/mDNS Poisoning**
  - Check if LLMNR/NBT-NS/mDNS are enabled and can be poisoned
  - Capture NTLMv2 hashes from broadcast name resolution
  - Link: [[llmnr_poisoning]]

- [ ] **SMB Signing Check**
  - Identify hosts with SMB signing disabled or not required
  - Potential for NTLM relay attacks
  - Link: [[smb_signing]]

- [ ] **IPv6 Attack Surface**
  - Check for IPv6 enabled networks with no IPv6 DNS server
  - Potential for IPv6 DNS takeover
  - Link: [[ipv6_attacks]]

- [ ] **Null Session Enumeration**
  - Check for null session access to systems
  - Enumerate shares, users, groups without authentication
  - Link: [[null_session]]

- [ ] **Anonymous LDAP Binds**
  - Test for anonymous LDAP binding
  - Enumerate domain information without credentials
  - Link: [[() ldap_techniques]]

- [ ] **Relay Attack Opportunities**
  - Identify services vulnerable to NTLM relay
  - Check WebDAV, HTTP endpoints, ADCS Web Enrollment
  - Link: [[relay_attacks]]

- [ ] **Pre-Windows 2000 Compatibility**
  - Check for "Everyone" permissions due to pre-Windows 2000 compatibility
  - Link: [[pre_windows_2000_computers]]

- [ ] **NFS Shares**
  - Identify open NFS exports
  - Check for no_root_squash misconfigurations
  - Look for sensitive data accessible via NFS
  - Link: [[nfs]]

- [ ] **Password Spraying Opportunities**
  - Test common/weak passwords against found usernames
  - Avoid account lockouts by tracking attempts
  - Link: [[() password_spraying]]

- [ ] **LDAP Passback Opportunities**
  - Printers & Networked phones
  - Link: [[cisco_phones]], [[ldap_passback]]

## Low-Privilege Checks

- [ ] **Password Policy**
  - Evaluate domain password policy strength
  - Check for fine-grained password policies
  - Link: [[- password_policy_enumeration]]

- [ ] **Kerberoasting**
  - Find service accounts with SPN records
  - Extract and crack service account TGS tickets
  - Link: [[kerberoasting]]

- [ ] **AS-REP Roasting**
  - Identify accounts with Kerberos pre-authentication disabled
  - Request and crack AS-REP encryption
  - Link: [[asreproast]]

- [ ] **Group Policy Preference Passwords**
  - Search for encrypted passwords in Group Policy Preferences
  - Decrypt cPassword attributes in GPP files
  - Link: [[gpp_password]]

- [ ] **BloodHound Analysis**
  - Collect domain information using SharpHound or similar
  - Analyze privilege escalation paths
  - Link: [[bloodhound]]

- [ ] **Accessible File Shares**
  - Enumerate readable shares across the domain
  - Look for sensitive files, configuration data, credentials
  - Check for overly permissive share permissions
  - Link: [[Internal/data_pillaging]]

- [ ] **Data Pillaging**
  - passwords, pii, phi, tokens, keys, etc...
  - Check user home directories and departmental shares
  - Link: [[Internal/data_pillaging]]

- [ ] **SYSVOL Enumeration**
  - Check readable files in the SYSVOL share
  - Look for scripts, configuration files with credentials
  - Link: [[() active_directory_enumeration]]

- [ ] **DNS Dump**
  - Extract DNS records from the domain
  - Map internal network structure
  - Identify potential targets
  - Link: [[dns_dump]]

- [ ] **Domain Wide Enumeration**
  - Comprehensive enumeration of domain objects
  - Map out users, groups, computers, and relationships
  - Identify misconfigurations and security issues
  - Link: [[domain_wide_enumeration]]

- [ ] **LDAP Enumeration for Sensitive Info**
  - Search for passwords/sensitive data in LDAP attributes
  - Check description fields, info fields, and comments
  - Link: [[() ldap_techniques]]

- [ ] **Local Admin Access Check**
  - Identify machines where current user has local admin
  - Potential lateral movement points
  - Link: [[() active_directory_enumeration]]

- [ ] **Machine Account Quota Abuse**
  - Check if current user can create computer accounts (default=10)
  - Potential for resource-based constrained delegation attacks
  - Link: [[machine_account_quota]]

- [ ] **Print Spooler Service**
  - Check for systems with Print Spooler enabled
  - Potential for PrintNightmare or other printer exploits
  - Link: [[() printnightmare]]

- [ ] **Authentication Coercion Points**
  - Identify services that can be coerced to authenticate
  - Check for PrinterBug, PetitPotam, ShadowCoerce opportunities
  - Force domain admin authentication via print spooler or EFS-RPC
  - Check for DVCSync exploitation
  - OPSEC Suggestions: Monitor for anomalous network traffic during coercion; use low-frequency attempts to avoid detection
  - Link: [[authentication_coercion]]

## Stage 3: Local Admin / Service Account Checks

- [ ] **Credential Harvesting**
  - Extract credentials from LSASS memory
  - Find stored credentials in registry/files
  - Link: [[credential_dumping]]

- [ ] **NTLM Hash Extraction**
  - Extract NTLM hashes from SAM database
  - Look for password reuse across systems
  - Link: [[ntlm_hash_theft]]

- [ ] **Credential Manager / DPAPI**
  - Extract saved credentials from Windows Credential Manager
  - Decrypt DPAPI blobs for stored credentials
  - Link: [[credential_dumping]]

- [ ] **Token Impersonation**
  - Check for impersonation privileges
  - Look for tokens of privileged users on compromised systems
  - Link: [[() token_impersonation]]

- [ ] **Local Privilege Escalation**
  - Check for misconfigurations enabling local privilege escalation
  - Vulnerable services, DLL hijacking, unquoted paths
  - Link: [[() windows_priv_esc]] [[unquoted_service_path]]

- [ ] **Scheduled Tasks & Services**
  - Analyze scheduled tasks and services for privilege escalation
  - Check for hardcoded credentials or weak permissions
  - Link: [[() windows_priv_esc]]

- [ ] **Sensitive Registry Keys**
  - Check registry for stored credentials
  - Look for autologon passwords, service credentials
  - Link: [[() windows_priv_esc]]

- [ ] **Browser Data**
  - Extract saved passwords from browsers
  - Look for domain credentials in browser storage
  - Link: [[credential_dumping]]

- [ ] **Lateral Movement Opportunities**
  - Identify potential lateral movement techniques
  - Use collected credentials on other systems
  - Link: [[pass_the_hash]] [[overpass_the_hash]] [[pass_the_ticket]]

- [ ] **LAPS Implementation Check**
  - Verify LAPS implementation and security
  - Check who can read LAPS passwords
  - Link: [[() laps_abuse]]

- [ ] **Group Managed Service Accounts**
  - Check for gMSA misconfigurations
  - Identify which principals can retrieve gMSA passwords
  - Link: [[() active_directory_enumeration]]

- [ ] **MSSQL Server Instances**
  - Identify SQL Servers accessible with current credentials
  - Check for linked servers, command execution capabilities
  - Link: [[mssql_abuse]]

## Stage 4: Domain Privilege Escalation Checks

- [ ] **Privileged Group Membership**
  - Analyze membership in privileged groups
  - Look for nested group memberships granting excessive privileges
  - Link: [[group_membership]]

- [ ] **Kerberos Delegation**
  - Check for unconstrained delegation
  - Check for constrained delegation misconfigurations
  - Check for resource-based constrained delegation issues
  - Link: [[kerberos_delegation]]

- [ ] **ACL Misconfigurations**
  - Identify dangerous permissions on AD objects
  - Look for WriteDACL, WriteOwner, GenericAll rights
  - Link:  [[- domain_acls]]

- [ ] **Shadow Credentials Attack**
  - Check for ability to modify msDS-KeyCredentialLink attribute
  - Potential for certificate-based authentication attacks
  - Link: [[- shadow_credentials]]

- [ ] **ADCS Vulnerabilities**
  - Check for misconfigured certificate templates
  - Look for ESC1-ESC8 vulnerabilities
  - Link: [[adcs_vulnerabilities]] 

- [ ] **Domain Trust Relationships**
  - Analyze domain and forest trusts
  - Check for transitive trust relationships that can be abused
  - Link: [[() forest_domain_trusts]]

- [ ] **Exchange Server Privileges**
  - Check for Exchange server privileges that can be abused
  - Look for excessive permissions granted to Exchange servers
  - Link: [[group_membership]]

- [ ] **SCCM Misconfigurations**
  - Assess SCCM deployment security
  - Check for privileges that can be leveraged for code execution
  - Link: [[sccm_site_takeover]] 

- [ ] **Windows Defender / AV Exclusions**
  - Check for excessive exclusions in antivirus settings
  - Look for excluded paths that could be used for persistence
  - Link: [[() active_directory_enumeration]]

## Stage 5: Domain Admin / Enterprise Admin Checks

- [ ] **DCSync Rights**
  - Identify accounts with DCSync capabilities
  - Check for GetChanges/GetChangesAll rights to domain objects
  - Link: [[dcsync]]

- [ ] **AdminSDHolder Issues**
  - Check for modifications to AdminSDHolder container
  - Look for backdoor permissions
  - Link: [[() active_directory_enumeration]]

- [ ] **krbtgt Account**
  - Check krbtgt password rotation practices
  - Potential for Golden Ticket attacks
  - Link: [[golden_ticket]]

- [ ] **Group Policy Object Security**
  - Analyze GPO permissions and settings
  - Look for overly permissive ACLs on GPOs
  - Link: [[group_policy_abuse]]

- [ ] **Domain Controller Security**
  - Review domain controller security settings
  - Check for unnecessary roles/features installed
  - Link: [[() active_directory_enumeration]]

- [ ] **AD Backup Security**
  - Check for insecure AD backups
  - Look for accessible NTDS.dit files
  - Link: [[() active_directory_enumeration]]

- [ ] **Tier Zero Asset Inventory**
  - Verify inventory of all Tier Zero assets
  - Look for undocumented domain controllers or admin workstations
  - Link: [[() active_directory_enumeration]]

- [ ] **AD Recycle Bin Access**
  - Check who has access to recover deleted objects
  - Potential for restoring backdoor accounts
  - Link: [[() active_directory_enumeration]]

- [ ] **AD Database Mounting**
  - Check for ability to mount copies of AD database
  - Potential offline credential extraction
  - Link: [[credential_dumping]]

- [ ] **Domain Controller LSASS Protection**
  - Check if credential guard or other LSASS protections are enabled
  - Verify if LSASS runs as a protected process
  - Link: [[credential_dumping]]

## Additional Checks

- [ ] **Pre-Boot Execution Environment (PXE)**
  - Check for insecure PXE boot configurations
  - Look for opportunities to intercept boot images
  - Link: [[pre_boot_execution_environment_pxe]]

- [ ] **ZeroLogon**
  - Test for CVE-2020-1472 vulnerability
  - Check if domain controllers are patched
  - Link: [[zerologon]]

- [ ] **NoPac (SamAccountName Spoofing)**
  - Test for CVE-2021-42278/CVE-2021-42287 vulnerabilities
  - Check for potential domain privilege escalation
  - Link: [[nopac_samaccountname_spoofing]]

- [ ] **Alternate Service Name Attacks**
  - Look for vulnerable service configurations
  - Check for potential authentication bypass
  - Link: [[- alternate_service_name]]

- [ ] **Default Credentials**
  - Check systems for default/unchanged credentials
  - Test known default username/password combinations
  - Link: [[() default_credentials]]

- [ ] **IPMI Hash Dump**
  - Identify IPMI interfaces
  - Attempt to extract password hashes
  - Link: [[ipmi_hash_dump]]

- [ ] **Cisco Smart Install**
  - Identify Cisco devices with Smart Install enabled
  - Check for potential configuration extraction or modification
  - Link: [[cisco_smart_install]]