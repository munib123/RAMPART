# Vulnerability: Apache APISIX Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`apache-apisix-panel.yaml`)

## Description
An Apache APISIX login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/user/login?redirect=%2F
```

