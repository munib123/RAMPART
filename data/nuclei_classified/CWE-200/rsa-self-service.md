# Vulnerability: RSA Self-Service Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rsa-self-service.yaml`)

## Description
RSA Self-Service login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/console-selfservice/SelfService.do
```

