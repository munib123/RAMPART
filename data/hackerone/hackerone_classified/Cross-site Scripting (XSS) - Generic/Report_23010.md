# HackerOne Report: XSS in 3rd party plugin (not affecting Uzbey's users)
**Report ID:** 23010
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Uzbey currently using a 3rd party solution from sharethis.com to share user's album.

It is possible to use this function as a medium to attack sharethis.com's users that using Uzbey service.

1- Create album using XSS payload
2- Share the album using Email function (letter icon)
3- XSS will execute.



## Discussion & Remediation Timeline
