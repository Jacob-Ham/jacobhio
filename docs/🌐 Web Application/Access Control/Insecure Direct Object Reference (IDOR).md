___
Similar to [Broken Object Level Access (BOLA)](Broken%20Object%20Level%20Access%20(BOLA).md) but less API focused, for example, iterating a pageID or page directory to view information of other users.

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
