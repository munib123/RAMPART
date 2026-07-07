# HackerOne Report: Homograph attack
**Report ID:** 59375
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hi,

I would like to report an incomplete fix of #58612 is. In short, backslash is not taken in consideration. 

PoC
>\[http://ebay.com](https:\\//ebаy.com)

[http://ebay.com](https:\\//ebаy.com)

## Discussion & Remediation Timeline
