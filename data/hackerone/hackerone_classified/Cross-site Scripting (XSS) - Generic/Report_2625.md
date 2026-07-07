# HackerOne Report: Stored XSS in username.slack.com
**Report ID:** 2625
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi 

There is a stored XSS in username.slack.com.

Steps to reproduce:

1. Login to your Slack
2. Goto "Create Private Group" and with any name and purpose
3. Goto https://manish.slack.com/messages/group/files/
4. Upload a file hitting upload icon (^)  filename shall be "><img src=x onerror=alert(1);>.jpeg
5. After file is uploaded click on the image or file title, JS will execute as the filename is considered as payload

I've attached the image showing XSS.

Thanks!

## Discussion & Remediation Timeline
