# Vulnerability: Symantec PGP Global Directory Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`symantec-pgp-global-directory.yaml`)

## Description
Symantec PGP Global Directory panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/vkd/GetWelcomeScreen.event
```

