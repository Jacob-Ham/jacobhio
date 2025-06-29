___
Using a low privileged users session token, can you perform actions of another user? of a higher privileged user? 

Use multiple accounts for testing, preferably two user accounts and two admin accounts. Proxy an admin request through burp and execute an admin function, repeat this request but replace the admin session token with the user sessions token. Is the admin function executed?

!!! alert "Tip:"
	Utilize the firefox containers addon to maintain sessions across multiple account for ease of use. 