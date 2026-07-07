# HackerOne Report: Multiple Cross Site Request Forgery Vulnerabilities in Concrete5 version 5.7.3.1
**Report ID:** 59660
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Concrete5 implements a Synchronizer Token Pattern in order to provide anti-CSRF capabilities, which is done within the Concrete\Core\Validation\CSRF\Token class. However, the application fails to properly use this feature in every block or dashboard page which makes a system state change, such as settings modification. As a result, the application is vulnerable to some Cross Site Request Forgery (CSRF) attacks.

## Discussion & Remediation Timeline
