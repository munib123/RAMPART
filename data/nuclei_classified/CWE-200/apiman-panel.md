# Vulnerability: Apiman Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`apiman-panel.yaml`)

## Description
An Apiman instance was detected via the login redirection.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/apimanui/api-manager
```

