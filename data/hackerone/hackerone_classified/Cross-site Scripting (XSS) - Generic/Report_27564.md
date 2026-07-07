# HackerOne Report: Content spoofing
**Report ID:** 27564
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,

I'm Dheeraj and I have found a content spoofing vulnerability in your system.


**Description :** 

Using the following link : https://secure.phabricator.com/auth/login/facebook:facebook.com/?error=<Spoofed Content>
Attacker can perform phishing attack.

**Attack Example :** 

https://secure.phabricator.com/auth/login/facebook:facebook.com/?error=We%20are%20having%20trouble%20accessing%20your%20account,%20kindly%20send%20your%20account%20details%20here%20attacker@site.com.%20Sorry%20for%20the%20inconvenience%20caused.


Regards
Dheeraj
@dheerajhere


## Discussion & Remediation Timeline
