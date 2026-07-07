# HackerOne Report: Cross-domain AJAX request
**Report ID:** 97948
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
Hi,

Two weeks ago, I found a Cross-domain AJAX request, but due to the fact that you uses a very strict Content Security Policy, I hesitated to send this. Today, I noticed that bug has been fixed. But this fix can be bypassed.

This example not working now (screenshot 1):

https://hackerone.com/bugs?subject=/google.com/


But if will be (screenshot 2):

https://hackerone.com/bugs?subject=/hackerone.com@google.com/
or https://hackerone.com/bugs?subject=%2Fhackerone.com.google.com


It's will work. 

## Discussion & Remediation Timeline
