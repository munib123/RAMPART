# HackerOne Report: XSS in main page (invitation)
**Report ID:** 7886
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
If a project name is saved with a XSS string such as: 
“><svg onload="prompt(/xss/);"><!--

and a translator visits and requests and invite,  it'll result in the xss executing in the main page, due to the fact that it shows your requests.

Screen:
http://prntscr.com/3awwuv

## Discussion & Remediation Timeline
