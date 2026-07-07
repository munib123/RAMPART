# HackerOne Report: Stored XSS in Contact Form
**Report ID:** 50564
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
In Contact form there is an option to display Message  when completed.
There I have put the payload
payload: "><img src=x onerror=alert(1)>

and the payload executed and saved permanently.

 

## Discussion & Remediation Timeline
