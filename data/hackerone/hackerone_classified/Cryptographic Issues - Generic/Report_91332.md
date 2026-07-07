# HackerOne Report: Open Url redirection on login with facebook
**Report ID:** 91332
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
steps to produce:
1, go to the site imgur.com and login with facebook and if you are new user then u must be asked for username on the link 
https://imgur.com/register/thirdparty/facebook?redirect=http://imgur.com/

nw just change the parameter redirect= value to https://google.com and hit enter and give username and  click next and you will redirected to google

Regards
Dipak

## Discussion & Remediation Timeline
