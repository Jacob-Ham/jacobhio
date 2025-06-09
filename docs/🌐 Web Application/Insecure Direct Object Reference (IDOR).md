**ffuf**
- if you have UIDs (can be anything) `-mr` = regex match
```Python
ffuf -u <http://example.com/info.php?account=FUZZ> -w <UIDLIST> -mr 'admin'
```
# API
---
**Post data**
```Python
curl -X POST -k <ENDPOINT> -d '{key:"value"}'
```
**proxy through burp**
```Python
curl -X POST -k --proxy http://localhost:8080 <ENDPOINT> -d '{key:"value"}'
```
