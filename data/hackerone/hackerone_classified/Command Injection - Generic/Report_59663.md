# HackerOne Report: Sendmail Remote Code Execution Vulnerability in Concrete5 version 5.7.3.1
**Report ID:** 59663
**Vulnerability Class:** Command Injection - Generic

## Vulnerability Information & PoC
Concrete5 is vulnerable to a Remote Code Execution because it fails to properly validate certain user input used as sender email address when sending out a registration notification email. This vulnerability is mitigated by the fact that it can be exploited only by authenticated administrator users (even though it could be exploited via a Cross Site Request Forgery attack as well) and only if the email is being sent with sendmail.

## Discussion & Remediation Timeline
