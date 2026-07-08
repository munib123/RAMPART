# Vulnerability: Accueil WAMPSERVER Configuration Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`accueil-wampserver.yaml`)

## Description
Accueil WAMPSERVER configuration page was detected.

## Secure Mitigation
Restrict access to the WAMP server configuration page and sub-tools.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

