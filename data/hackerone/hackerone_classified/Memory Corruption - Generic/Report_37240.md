# HackerOne Report: Race condition in Flash workers may cause an exploitabl​e double free
**Report ID:** 37240
**Vulnerability Class:** Memory Corruption - Generic

## Vulnerability Information & PoC
The issue occurs while sharing a bytearray between two workers. If both call bytearray.clear() at the same time, Flash does not correctly handle the race and may double free the array.

Indentified as CVE-2014-0574, and reported to Adobe via Chrome VRP:
http://helpx.adobe.com/security/products/flash-player/apsb14-24.html

Original report with proof of concept:
https://code.google.com/p/chromium/issues/detail?id=423703

## Discussion & Remediation Timeline
