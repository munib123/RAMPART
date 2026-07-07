# HackerOne Report: Content Spoofing - External Link Warning Page
**Report ID:** 60402
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Here is example link:
[Click Here](http://attackers.com/***************   is a fake website. Click Proceed to visit back HackerOne.)

Raw Data:
```
[Click Here](http://attackers.com/***************   is a fake website. Click Proceed to visit back HackerOne.)
```

Issue:
In External link warning page, this link shown as plain text and no forced URL encoded, leading an attacker to frame sentences and trick users. In given example, attacker can trick user to click 'Proceed' button saying it will redirect back to HackerOne but it wont. Though there will be written warning saying better to open in separate browser, bigger letter will be read by users first ;) . In redirected page, attacker can spoof HackerOne website or login page of same or any other phishing attacks.

Possible Fix:
URL Encode spaces to %20 which will convert spoofing content look like link. 

## Discussion & Remediation Timeline
