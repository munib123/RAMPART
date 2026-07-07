# HackerOne Report: Use After Free in Flash MessageChannel.send can cause arbitrary code execution
**Report ID:** 47234
**Vulnerability Class:** Memory Corruption - Generic

## Vulnerability Information & PoC
Sending messages between workers while having the animation reloaded can cause an object to be freed while a reference remains in memory. An attacker can use this issue to control eip and potentially execute arbitrary code.

Identified as CVE-2015-0320, and reported to Adobe via Chrome VRP:
https://helpx.adobe.com/security/products/flash-player/apsb15-04.html

Original report with proof of concept showing how to control eip:
https://code.google.com/p/chromium/issues/detail?id=437441

## Discussion & Remediation Timeline
