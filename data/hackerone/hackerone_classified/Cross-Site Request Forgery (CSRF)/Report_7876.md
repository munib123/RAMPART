# HackerOne Report: XSS & HTML injection
**Report ID:** 7876
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Link:
http://www.localize.io/review/3C/languages/3

while approving and reviewing a phrase, you are able to send/set a message. You can XSS that by entering an  XSS string

String used:
<object data=data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoNCk+></object>?

Screenshot:
http://prntscr.com/3awo2p

## Discussion & Remediation Timeline
