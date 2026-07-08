# Vulnerability: postMessage - Cross-Site Scripting
**Classification:** CWE-346
**Source:** Nuclei Template (`wildcard-postmessage.yaml`)

## Description
postMessage contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and therefore steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

