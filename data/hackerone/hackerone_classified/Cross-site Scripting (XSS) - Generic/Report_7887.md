# HackerOne Report: XSS in invite approval
**Report ID:** 7887
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
If a translator's name is set as “><svg onload="prompt(/xss/);"> and requests to join a project, and the project admin clicks on the review to accept it, it results in an xss.

Screen:
attacker/translator:
http://prntscr.com/3ax1ca

contributor/admin:
http://prntscr.com/3ax1ix

## Discussion & Remediation Timeline
