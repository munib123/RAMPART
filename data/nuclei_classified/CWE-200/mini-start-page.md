# Vulnerability: Miniweb Start Page Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mini-start-page.yaml`)

## Description
Miniweb Start Page login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/start.html
GET {{BaseURL}}/www/start.html
```

