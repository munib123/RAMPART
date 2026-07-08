# Vulnerability: Nutanix Web Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nutanix-web-console-login.yaml`)

## Description
Nutanix Web Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/console/
```

