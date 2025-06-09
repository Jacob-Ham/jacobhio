## Directory Fuzzing
---
**ffuf**
```Python
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u <URL>/FUZZ
```
```Python
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u <URL>/FUZZ -recursion
```
```Python
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u <URL>/FUZZ -fc 200
```
**dirb**
```Python
dirb <URL> /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
```Python
dirb <URL> -X .html
```
**feroxbuster**
```Python
feroxbuster -u http://example.com -x php,html,htm,asp,aspx
```
**dirsearch**
```Python
dirsearch -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -e php,txt,html -f -u http://example.com
```
