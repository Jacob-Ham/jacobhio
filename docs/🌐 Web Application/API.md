**Post data**
```Python
curl -X POST -k <ENDPOINT> -d '{key:"value"}'
```
**proxy through burp**
```Python
curl -X POST -k --proxy http://localhost:8080 <ENDPOINT> -d '{key:"value"}'
```