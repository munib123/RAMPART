# HackerOne Report: Persistent Cross Site Scripting within the IRCCloud Pastebin 
**Report ID:** 7121
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
The HTML within a paste does not get correctly sanitized after an initial new line. So the following code gets executed: \r\n<script>alert(1);</script> 

https://www.irccloud.com/pastebin/FADYQPrO

## Discussion & Remediation Timeline
