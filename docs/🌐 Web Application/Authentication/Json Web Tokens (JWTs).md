___
Burpsuite "JWT Editor" Extension is helpful

!!! alert "note"
	When you remove the signature, you usually need to retain the trailing dot.

!!! alert "note"
	When testing JWTs, test similar to BFLA and BOLA and IDOR, make two users and see if you can modify user2s information by changing the user claim on the JWT from user1.

### Signing attacks
---
- Does the application check if the signature has been modified? Can we edit the claims and have them accepted?
- Can we change the algorithm and sign them ourselves?
- Does the application check if the token is signed? 
- Can we bruteforce the key?


### Header Injection
---
Headers to use in the attack:

- JWK (JSON web key)
- JKU (JSON web key set url)
- KID (Key ID)

We can potentially inject an arbitrary JSON web key, the application will then use this key to verify subsequent tokens.

1. Use JWT editor (burp) to create a new RSA key. 
2. Modify the web token to the administrator claim.
3. Click "attack" --> embed JWK --> select key --> match the signing algo from the original
4. Send to application and verify results.


### Tooling
---
[https://github.com/ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)
Includes a great workflow and a ton of automated exploitation options including cracking tokens.
**Good resource:** [https://github.com/ticarpi/jwt_tool/wiki](https://github.com/ticarpi/jwt_tool/wiki)

