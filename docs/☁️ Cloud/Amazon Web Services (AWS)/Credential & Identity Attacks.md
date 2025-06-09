___
Target IAM roles, policies, or SSO flows to obtain or elevate privileges.
Generate & Retrieve IAM Credential Report
```bash
aws iam generate-credential-report
aws iam get-credential-report
```
Retrieve All Roles You Can Assume
```bash
aws iam get-account-authorization-details
```
Review the `RoleDetailList` section for roles where you have `sts:AssumeRole` permissions.
**Confused Deputy / Role Chaining**
```bash
aws iam get-account-authorization-details
```
Look for trust policies that allow `sts:AssumeRole` from an external account or cross-service trust. If you can assume a higher-privilege role in another account (Confused Deputy), you can pivot to that role.
