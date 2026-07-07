# HackerOne Report: Accepting Invalid characters on email address
**Report ID:** 3991
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
I tried to change my email address on hackerone.com.And when I tried adding null Bytes,it was being accepted by hackerone.com.
I am registered wth ███ and I tried to change my email address to ████%00 
And guess what,this address was granted as an email address.

## Discussion & Remediation Timeline
