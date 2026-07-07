# HackerOne Report: Stored XSS on Blog's page Tile
**Report ID:** 50552
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
In blog page Custom Title Text ,
xss payload can be executed and  saved permanently  .
Poc: "><img src=x onerror=alert(1)>


## Discussion & Remediation Timeline
