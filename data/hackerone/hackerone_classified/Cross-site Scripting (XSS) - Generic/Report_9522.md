# HackerOne Report: https://polldaddy.com storage.swf XSS
**Report ID:** 9522
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,

I found a flash based XSS located here :
`https://polldaddy.com/swf/storage.swf?onload=alert(1)`

It happends in the `ExternalInterface.Call` Function, when a parameter is inserted unfiltered it will allow XSS, you can patch it by only allowing :
A-Z a-z 0-9

Best regards,

Olivier Beg

## Discussion & Remediation Timeline
