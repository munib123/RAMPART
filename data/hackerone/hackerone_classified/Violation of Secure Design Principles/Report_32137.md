# HackerOne Report: Content Spoofing via reports
**Report ID:** 32137
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
The `report_id[]` param simply returns whatever entered , instead of showing report id's only. This can result in content injection in the reports field.
For example check this one : http://goo.gl/py2V8j 

## Discussion & Remediation Timeline
