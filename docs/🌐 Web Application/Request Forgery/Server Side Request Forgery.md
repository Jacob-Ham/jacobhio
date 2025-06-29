___
Force the server to make a request to an arbitrary endpoint.

Things to assess:
- Have a referrer header? Try blind SSRF
- API interactions where an entire URL is being passed via a controllable input
- HTTP parameters that are being passed URLs (or sometimes files)

Found an SSRF?
- Try requesting localhost
- Can you make a request to a sensitive endpoint coming from localhost?
- Fuzz LAN subnets
- Found alive IP on LAN? 
	- Fuzz for open ports


**Blind SSRF**
- We find an ssrf but we do not receive a response with data indicating we've hit an endpoint.
- Data exfil CAN be possible, but it is pretty difficult. 
- Use a tool like burp collaborator OR:
	- https://github.com/projectdiscovery/interactsh-web


**Misc**
- Payloads delivered via http request headers may take SSRF to further compromise.
	- Ex: https://infosecwriteups.com/shellshock-a-deep-dive-into-cve-2014-6271-3eb5b33e5de6 (Shell shock payload delivered via UA)