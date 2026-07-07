# HackerOne Report: Open redirection in fabric.io
**Report ID:** 39631
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
Hi dear, 
Once the person is logged into his account he can be redirected to any website .

https://www.fabric.io/login?redirect_url=@<payload>

for example : https://www.fabric.io/login?redirect_url=@google.com

Tested on updated firefox and chrome.

## Discussion & Remediation Timeline
