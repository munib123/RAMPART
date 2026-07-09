# Nuclei Template: Angular Client-side-template-injection
**Template ID:** angular-client-side-template-injection
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**Source:** Nuclei Template (`angular-client-side-template-injection.yaml`)

## Vulnerability Information & PoC

## Description
Detects Angular client-side template injection vulnerability.

## Impact
May lead to remote code execution or sensitive data exposure.

## Remediation
Sanitize user inputs and avoid using user-controlled data in template rendering.

## References
- https://www.acunetix.com/vulnerabilities/web/angularjs-client-side-template-injection/
- https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs
