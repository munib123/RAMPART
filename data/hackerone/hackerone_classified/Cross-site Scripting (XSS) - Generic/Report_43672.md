# HackerOne Report: player.vimeo.com - Reflected XSS Vulnerability
**Report ID:** 43672
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi.

I want to report a reflected xss vulnerability that I found in `player.vimeo.com` website and which can affect the safety of your users. This vulnerability allows an attacker to inject in web pages javascript content for sending malicious scripts to an unsuspecting user. This flaw can access any cookies, session tokens, or other sensitive information retained by victim's browser and used with that site.

PoC Link: http://player.vimeo.com/hubnut/channel/830190?user="onmousemove="alert(1)"
Type: GET XSS
Vulnerable Parameter: `user`
Steps for reproducing this flaw: Open the PoC Link in a web browser and point the cursor over the page background and you will see that an` alert()` function will be called. The cause of this vulnerability is the value of `user` GET parameter which is inserted in the page without being encoded. As a result, I can inject a javascript function as a value for an event attribute like `onmousemove`, `onmouseover` etc .

Regards,
Coltuneac Alexandru

## Discussion & Remediation Timeline
