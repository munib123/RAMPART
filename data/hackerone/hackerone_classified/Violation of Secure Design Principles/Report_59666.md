# HackerOne Report: Unsafe usage of Host HTTP header in Concrete5 version 5.7.3.1
**Report ID:** 59666
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Concrete5 is affected by a design issue related to the Host HTTP header. Such header is being used to define the base URL for the application. Since the Host header can be arbitrarily manipulated by an attacker, this can have some security impacts.

## Discussion & Remediation Timeline
