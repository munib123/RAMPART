# Vulnerability: Avaya Aura Communication Manager Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`avaya-aura-communication-manager-panel.yaml`)

## Description
Avaya Aura Communication Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/common/login/webLogin
```

