# HackerOne Report: Use after free during the StageVideoAvailabilityEvent can result in arbitrary code execution
**Report ID:** 47232
**Vulnerability Class:** Memory Corruption - Generic

## Vulnerability Information & PoC
An attacker can register the StageVideoAvailabilityEvent and have the SWF movie reloaded at the same time with LoadMovie. During this process, an object may be freed allowing the attacker to take control of the code flow.

Identified as CVE-2015-0315, and reported to Adobe via Chrome VRP:
https://helpx.adobe.com/security/products/flash-player/apsb15-04.html

Original report with an exploit for Chrome:
https://code.google.com/p/chromium/issues/detail?id=429276


## Discussion & Remediation Timeline
