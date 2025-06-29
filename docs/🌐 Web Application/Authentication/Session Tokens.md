___
Determine if a token warrents further investigation
- send multiple requests with valid login to login endpoint
	- Do tokens change?
	- Is any part of the token static? 

#### Burp Sequencer
- Sequencer will allow you to request many tokens and automatically assess their entropy. 
- Sequencer identifies some patterns in a token, we should spend time investigating that token further.
