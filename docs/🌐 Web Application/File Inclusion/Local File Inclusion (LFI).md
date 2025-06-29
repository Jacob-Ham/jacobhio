!!! alert "note"
	Try to exploit 1st by replacing the expected value, then by appending your payload after the expected value. If you see a path `/var/www/images/5.jpg` we may need to insert our payload not at the root, but instead of 5.jpg - the application may be expecting the preceding path to exist in the request. 


**List of payloads**
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

**ffuf**
- Copy request to file via burp
```Python
ffuf -request r -request-proto http -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
```
**Filter by wordcount**
```Python
ffuf -request r -request-proto http -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fw 19,20
```

**List of most common LFI parameters**
```bash
?cat={payload}
?dir={payload]
?action={payload}
?board={payload}
?date={payload}
?detail={payload}
?file={payload}
?download={payload}
?path={payload}
?folder={payload}
?prefix={payload}
?include={payload}
?page={payload]
?inc={payload}
?locate={payload}
?show={payload}
?doc={payload}
?site={payload}
?type={payload}
?view={payload}
?content={payload}
?document={payload}
?layout={payload}
?mod={payload}
?conf={payload}
```
