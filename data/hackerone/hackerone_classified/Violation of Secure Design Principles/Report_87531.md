# HackerOne Report: Mail spaming
**Report ID:** 87531
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hello,
We can bomb (spam) any email we want using your website. 
POC : 
1.register
2.go to https://gratipay.com/~hussein98d/emails/ and add your victim's email
3.start intercepting requests and click on "resend"
4.replay the same request many time , the victim's email will be spammed with Gratipay messages.

Thanks,
Hussein

## Discussion & Remediation Timeline
